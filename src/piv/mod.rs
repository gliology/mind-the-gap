//! The PIV backend: an X.509 chain from seeds, and uploads to YubiKeys.
//!
//! [`SeededSmartcard`] derives a root certificate authority, an optional issuing authority
//! and the three usable slot keys (9A, 9C, 9D) from the key seed, and the card's own
//! credentials, identifiers and 9E key from the card seed, on NIST P-256, on NIST P-384 with
//! [`Algorithm::P384`], as Ed25519 and X25519 keys with [`Algorithm::Curve25519`], or as
//! RSA keys. The chain is signed with RFC 6979 deterministic ECDSA, pure Ed25519 or PKCS#1
//! v1.5, all deterministic, so re-runs are byte-identical, and keys, certificates,
//! identifiers and per-slot policies are written to the card through the `yubikey` crate.
//! The chain layout and its constraints are documented in the certificates chapter,
//! <https://gliology.github.io/mind-the-gap/piv-certificates.html>.

use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use crate::backend::{Applet, Backend, Subtrees};
use crate::policy::Policy;
use crate::role::KeyRole;
use crate::seed::{Algorithm, KeyPath, Seeds};
use crate::target::CardTarget;

use anyhow::{Result, anyhow, bail};

use yubikey::piv::{RetiredSlotId, SlotId};

use x509_cert::ext::pkix::name::GeneralName;

use der::asn1::Ia5String;

use zeroize::Zeroizing;

mod algorithms;
mod card;
mod chain;
mod check;
mod export;
mod keys;
mod ownership;
mod slots;
mod update;

pub(crate) use algorithms::algorithm_of;
pub(crate) use card::read_serial;
pub use card::{change_pin, list, refuse_unfit_pin};
pub use chain::{
    CertChain, PublishedList, read_revocation_list, refuse_unfit_crl_url, refuse_unfit_names,
};
use chain::{IssuerKey, SubjectName};
use keys::SlotKey;
pub use slots::SlotRole;
pub use update::generation_on_card;
pub use update::{Change as UpdateChange, KeyReason, UpdatePlan};

/// Why a slot is refused that would take another key with the decryption key
const MISPLACED_SLOT: &str =
    "--slot places one key, the decryption key: pass --key decryption with it";

/// The slot the decryption key goes to by its number: 9d, or 82 to 95
fn decryption_slot(slot: u8) -> Result<SlotId> {
    Ok(match slot {
        0x9d => SlotId::KeyManagement,
        slots::FIRST_RETIRED_SLOT..=slots::LAST_RETIRED_SLOT => SlotId::Retired(
            RetiredSlotId::try_from(slot).map_err(|err| anyhow!("Slot {slot:02x}: {err}"))?,
        ),
        0x9a | 0x9c => bail!(
            "Slot {slot:02x} holds the {} key, which has no other slot; --slot moves the \
             decryption key only, to 9d or a retired slot from 82 to 95",
            if slot == 0x9a {
                "authentication"
            } else {
                "signature"
            }
        ),
        other => bail!(
            "Slot {other:02x} takes no key of the identity: the decryption key goes to 9d or a \
             retired slot from 82 to 95"
        ),
    })
}

/// Refuse a `--slot` the builder would refuse, without the seeds a builder needs: one no
/// decryption key goes to, or one given with `keys` (as `--key` names them, all three where
/// none) other than the decryption key alone
pub fn refuse_unfit_slot(slot: u8, keys: &[KeyRole]) -> Result<()> {
    decryption_slot(slot)?;
    if keys.is_empty() || keys.iter().any(|key| *key != KeyRole::Decryption) {
        bail!(MISPLACED_SLOT);
    }
    Ok(())
}

/// Which part of the certificate chain to publish
#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq)]
pub enum CertificateKind {
    /// The certificate authorities plus the slot certificates
    #[default]
    Chain,
    /// The self-signed root certificate authority, i.e. the trust anchor to distribute
    Root,
    /// The intermediate issuing certificate authority only
    Intermediate,
    /// The slot certificates only
    Leaves,
}

/// Algorithm of the derived management key `init` installs in slot 9B
#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ManagementKeyArg {
    /// AES-256 when the card reports firmware 5.4 or later, triple DES before
    #[default]
    Auto,
    /// AES-256: YubiKey 5.4 and later, Nitrokey 3, the trussed PIV app
    Aes256,
    /// Triple DES: the only management key a YubiKey 4, or a YubiKey 5 before 5.4, takes
    Tdes,
}

/// Config to create a PIV certificate chain
pub struct SeededSmartcard {
    /// The card seed's and the key seed's PIV subtrees
    ///
    /// The card seed's is apart from the key seed's on purpose: whoever administers the card
    /// holds it, which opens the card but derives no key the identity uses. Under the key
    /// seed's, the root authority is a *sibling* of the device and shared seeds, not their
    /// parent: were it the parent, anyone holding the authority key could re-derive every
    /// slot key.
    seeds: Subtrees,

    /// The keys derived so far, on the heap, where a builder moved on to its next option
    /// moves only the pointer
    derived: Box<Derived>,

    /// Where the usable keys sit under the key seed
    path: KeyPath,

    /// Algorithm every asymmetric key in the chain is derived with
    algorithm: Algorithm,

    /// Distinguished name attributes for every tier of the chain
    identity: SubjectName,

    /// Alternative names, e.g. emails addresses, to use in the leaf certificates
    alternatives: Vec<GeneralName>,

    /// Creation time of the root authority, which the identity keeps for good
    identity_time: Option<SystemTime>,

    /// Validity duration of the leaf certificates
    validity_duration: Option<Duration>,

    /// The URL `--crl-url` gives without its `.crl`: the stem every revocation list's URL is
    /// made from, which the certificates name where relying parties fetch their issuer's list
    list_stem: Option<String>,

    /// User pin to set on the card
    pin: Option<Zeroizing<String>>,

    /// Whether to insert an intermediate issuing certificate authority
    intermediate: bool,

    /// Pin and touch requirements of every slot but 9E, and of management access
    policy: Policy,

    /// Whether the policy was chosen rather than defaulted: `upload` changes a card's
    /// policies only when asked to, and otherwise keeps what the card has
    policy_given: bool,

    /// Whether to write the certificate authorities to the card's `msroots` object
    msroots: bool,

    /// Algorithm of the management key `init` installs
    management_algorithm: ManagementKeyArg,

    /// The keys `upload` writes, `check` compares and `publish` certifies
    keys: Vec<KeyRole>,

    /// Where the decryption key goes instead of 9D: a retired slot, for a key kept to read
    /// what was encrypted to it
    slot: Option<SlotId>,
}

/// The keys of the identity a builder has derived, each derived once however often a command
/// uses it: an RSA key takes seconds to find
///
/// Secret, and wiped with the builder as every key type here wipes itself on drop.
#[derive(Default)]
struct Derived {
    /// The root authority's key
    root: OnceLock<IssuerKey>,
    /// The issuing authority's key
    issuing: OnceLock<IssuerKey>,
    /// The usable keys, in [`KeyRole::ALL`] order
    roles: [OnceLock<SlotKey>; 3],
}

impl SeededSmartcard {
    /// Initialize a new seeded smartcard config from the seeds a command has
    pub fn new(seeds: Seeds<'_>, path: KeyPath, name: String) -> Self {
        SeededSmartcard {
            seeds: Subtrees::new(seeds, "piv", &path),
            derived: Box::default(),
            path,
            algorithm: Algorithm::P256,
            identity: SubjectName { name, ..Default::default() },
            alternatives: vec![],
            identity_time: None,
            validity_duration: None,
            list_stem: None,
            pin: None,
            intermediate: false,
            policy: Policy::default(),
            policy_given: false,
            msroots: true,
            management_algorithm: ManagementKeyArg::Auto,
            keys: KeyRole::ALL.to_vec(),
            slot: None,
        }
    }

    /// Set the user pin `init` installs in place of the PIV default and `check` verifies
    ///
    /// Fails on a pin no PIV card takes, see [`refuse_unfit_pin`].
    pub fn with_pin(mut self, pin: Zeroizing<String>) -> Result<Self> {
        refuse_unfit_pin(&pin)?;
        self.pin = Some(pin);
        Ok(self)
    }

    /// Derive the whole chain with `algorithm`, authorities included
    ///
    /// Every algorithm derives under its own labels, so switching a card between algorithms shares
    /// no key material between the two chains.
    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self.derived = Box::default();
        self
    }

    /// Add email to list of alternative names.
    ///
    /// Fails on anything the certificate could not carry -- rfc822Name is an IA5String, so
    /// a non-ASCII address is an input error, not a panic.
    pub fn add_email(mut self, address: &str) -> Result<Self> {
        let name = Ia5String::new(address)
            .map_err(|_| anyhow!("Email address '{address}' is not ASCII, cannot go in a SAN"))?;
        self.alternatives.push(GeneralName::Rfc822Name(name));
        Ok(self)
    }

    /// Set the organization (`O`) used in all certificate subjects
    pub fn with_org(mut self, org: String) -> Self {
        self.identity.org = Some(org);
        self
    }

    /// Set the organizational unit (`OU`) used in all certificate subjects
    pub fn with_org_unit(mut self, unit: String) -> Self {
        self.identity.org_unit = Some(unit);
        self
    }

    /// Set the country (`C`) used in all certificate subjects
    pub fn with_country(mut self, country: String) -> Self {
        self.identity.country = Some(country);
        self
    }

    /// Insert an intermediate issuing authority between the root and the slot certificates
    pub fn with_intermediate(mut self, intermediate: bool) -> Self {
        self.intermediate = intermediate;
        self
    }

    /// Choose the pin and touch requirements `upload` gives the slots and management access
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self.policy_given = true;
        self
    }

    /// Pick the algorithm of the management key `init` installs
    ///
    /// `check` ignores this and derives for whatever algorithm the card reports, so it needs
    /// no flag to verify either kind.
    pub fn with_management_key(mut self, algorithm: ManagementKeyArg) -> Self {
        self.management_algorithm = algorithm;
        self
    }

    /// Enable or disable writing the authorities to the card's `msroots` object
    pub fn with_msroots(mut self, msroots: bool) -> Self {
        self.msroots = msroots;
        self
    }

    /// Set the creation time of the identity's root authority
    pub fn with_identity_time(mut self, timestamp: SystemTime) -> Self {
        self.identity_time = Some(timestamp);
        self
    }

    /// Set certificate validity duration
    pub fn with_validity_duration(mut self, duration: Duration) -> Self {
        self.validity_duration = Some(duration);
        self
    }

    /// Name where the identity's revocation lists are published, by a URL whose last segment
    /// ends in `.crl`: each list is published beside it, under that name with its own
    /// suffix (see [`Self::revocation_list_suffix`]), and every certificate names the list of
    /// the authority that issued it
    ///
    /// Fails on a URL the lists cannot be named from, see [`refuse_unfit_crl_url`].
    pub fn with_crl_url(mut self, url: &str) -> Result<Self> {
        refuse_unfit_crl_url(url)?;
        let stem = url.strip_suffix(".crl").unwrap_or(url);
        self.list_stem = Some(stem.to_owned());
        Ok(self)
    }

    /// Write, compare and certify only these keys, in slot order
    pub fn with_keys(mut self, keys: &[KeyRole]) -> Result<Self> {
        if keys.is_empty() {
            bail!("No key chosen: name at least one of authentication, signature or decryption");
        }
        self.keys = KeyRole::ALL
            .into_iter()
            .filter(|role| keys.contains(role))
            .collect();
        self.refuse_misplaced_slot()?;
        Ok(self)
    }

    /// Put the decryption key into `slot` instead of 9D, by its number: 9d, or 82 to 95
    pub fn with_slot(mut self, slot: u8) -> Result<Self> {
        self.slot = Some(decryption_slot(slot)?);
        self.refuse_misplaced_slot()?;
        Ok(self)
    }

    /// Refuse a slot choice that does not name the decryption key alone
    fn refuse_misplaced_slot(&self) -> Result<()> {
        if self.slot.is_some() && self.keys != [KeyRole::Decryption] {
            bail!(MISPLACED_SLOT);
        }
        Ok(())
    }

    /// The slot a role's key is written to
    pub(super) fn slot_of(&self, role: KeyRole) -> SlotId {
        match (role, self.slot) {
            (KeyRole::Decryption, Some(slot)) => slot,
            (role, _) => SlotRole::from(role).slot(),
        }
    }

    /// The key path this card derives its keys along
    pub fn path(&self) -> &KeyPath {
        &self.path
    }

    /// Whether every usable key is chosen and in its own slot, which is what a card that
    /// carries this identity holds; only such an upload stores the authorities in msroots
    pub(super) fn whole_identity(&self) -> bool {
        self.keys == KeyRole::ALL && self.slot.is_none()
    }
}

impl Applet for SeededSmartcard {
    fn name(&self) -> &'static str {
        "PIV"
    }

    fn preflight(&self, target: Option<CardTarget>) -> Result<String> {
        SeededSmartcard::preflight(self, target)
    }

    fn init(&self, target: Option<CardTarget>) -> Result<()> {
        SeededSmartcard::init(self, target)
    }

    fn check(&self, target: Option<CardTarget>) -> Result<()> {
        SeededSmartcard::check(self, target)
    }

    fn plan_wipe(&self, target: Option<CardTarget>, force: bool) -> Result<String> {
        SeededSmartcard::plan_wipe(self, target, force)
    }

    fn wipe(&self, target: Option<CardTarget>, force: bool) -> Result<()> {
        SeededSmartcard::wipe(self, target, force)
    }

    fn reset_pin(&self, target: Option<CardTarget>, new: &str) -> Result<()> {
        SeededSmartcard::reset_pin(self, target, new)
    }
}

impl Backend for SeededSmartcard {
    type Change = UpdateChange;

    fn plan_upload(&self, target: Option<CardTarget>) -> Result<UpdatePlan> {
        SeededSmartcard::plan_upload(self, target)
    }

    fn upload(&self, target: Option<CardTarget>, confirmed: &UpdatePlan) -> Result<UpdatePlan> {
        SeededSmartcard::upload(self, target, confirmed)
    }

    fn plan_rotation_from(
        &self,
        previous: &Self,
        target: Option<CardTarget>,
    ) -> Result<UpdatePlan> {
        SeededSmartcard::plan_rotation_from(self, previous, target)
    }

    fn rotate_from(
        &self,
        previous: &Self,
        target: Option<CardTarget>,
        confirmed: &UpdatePlan,
    ) -> Result<UpdatePlan> {
        SeededSmartcard::rotate_from(self, previous, target, confirmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::{self, CardSerial};
    use yubikey::piv::RetiredSlotId;
    use yubikey::{MgmAlgorithmId, PinPolicy, TouchPolicy};

    fn card() -> SeededSmartcard {
        let path = KeyPath { subkey: Some("builder".into()), date: None };
        SeededSmartcard::new(Seeds::one(&[3u8; 32]), path, "Builder".into())
    }

    fn serial() -> CardSerial {
        CardSerial::piv(12345678)
    }

    /// Without overrides every slot keeps the policy SP 800-73 asks for, retired slots that of
    /// the key management slot whose keys they archive.
    #[test]
    fn policies_default_per_slot() {
        let card = card();
        let retired = SlotId::Retired(RetiredSlotId::try_from(0x82).unwrap());

        assert_eq!(
            card.policies_for(SlotId::Authentication),
            (PinPolicy::Once, TouchPolicy::Cached)
        );
        assert_eq!(card.policies_for(SlotId::Signature), (PinPolicy::Always, TouchPolicy::Always));
        assert_eq!(
            card.policies_for(SlotId::KeyManagement),
            (PinPolicy::Once, TouchPolicy::Cached)
        );
        assert_eq!(
            card.policies_for(SlotId::CardAuthentication),
            (PinPolicy::Never, TouchPolicy::Never)
        );
        assert_eq!(card.policies_for(retired), (PinPolicy::Once, TouchPolicy::Cached));
    }

    /// Every mode reaches 9A, 9C, 9D and the retired slots as `Policy` maps it, while 9E stays
    /// pin- and touch-free as the spec requires; management access follows the mode's touch
    #[test]
    fn policies_reach_every_slot_but_card_authentication() {
        use crate::policy::{Pin, Touch};
        use clap::ValueEnum;
        let retired = SlotId::Retired(RetiredSlotId::try_from(0x83).unwrap());
        let pin = |pin| match pin {
            Pin::Never => PinPolicy::Never,
            Pin::Once => PinPolicy::Once,
            Pin::Always => PinPolicy::Always,
        };
        let touch = |touch| match touch {
            Touch::Never => TouchPolicy::Never,
            Touch::Cached => TouchPolicy::Cached,
            Touch::Always => TouchPolicy::Always,
        };

        for &policy in Policy::value_variants() {
            let card = card().with_policy(policy);
            for slot in [
                SlotId::Authentication,
                SlotId::Signature,
                SlotId::KeyManagement,
                retired,
            ] {
                let (p, t) = policy.piv_slot(slot == SlotId::Signature);
                assert_eq!(card.policies_for(slot), (pin(p), touch(t)), "{policy:?} on {slot:?}");
            }
            assert_eq!(
                card.policies_for(SlotId::CardAuthentication),
                (PinPolicy::Never, TouchPolicy::Never),
                "{policy:?} reached 9E"
            );
        }

        // The build server profile, spelled out
        let card = card().with_policy(Policy::OncePin);
        assert_eq!(card.policies_for(SlotId::Signature), (PinPolicy::Once, TouchPolicy::Never));
        assert!(!Policy::OncePin.management_touch());
    }

    /// The 3DES management key: 24 bytes, reproducible, not weak, and sharing nothing with
    /// the AES-256 key of the same card. The values of both are pinned with the other card
    /// credentials, in `keys.rs`.
    #[test]
    fn tdes_management_key_is_independent_of_aes() {
        let tdes = card()
            .management_key(MgmAlgorithmId::ThreeDes, &serial())
            .unwrap();
        let again = card()
            .management_key(MgmAlgorithmId::ThreeDes, &serial())
            .unwrap();
        let aes = card()
            .management_key(MgmAlgorithmId::Aes256, &serial())
            .unwrap();

        assert_eq!(tdes.algorithm_id(), MgmAlgorithmId::ThreeDes);
        assert_eq!(aes.algorithm_id(), MgmAlgorithmId::Aes256);
        assert_eq!(tdes.as_ref().len(), 24);
        assert_eq!(aes.as_ref().len(), 32);
        assert_eq!(tdes.as_ref(), again.as_ref());
        assert!(!seed::is_weak_tdes_key(tdes.as_ref().try_into().unwrap()));

        // Not a truncation of the AES key, nor overlapping it anywhere
        assert_ne!(tdes.as_ref(), &aes.as_ref()[..24]);
        for window in tdes.as_ref().windows(8) {
            assert!(!aes.as_ref().windows(8).any(|other| other == window));
        }

        // Another card gets another key, and the key seed has no part in it
        let other = card()
            .management_key(MgmAlgorithmId::ThreeDes, &CardSerial::piv(87654321))
            .unwrap();
        assert_ne!(tdes.as_ref(), other.as_ref());
        let split = SeededSmartcard::new(
            Seeds { card: Some(&[3u8; 32]), key: Some(&[4u8; 32]) },
            KeyPath::default(),
            "Builder".into(),
        )
        .management_key(MgmAlgorithmId::ThreeDes, &serial())
        .unwrap();
        assert_eq!(tdes.as_ref(), split.as_ref());
    }

    /// A command without the card seed cannot reach a credential, and says which seed it lacks
    #[test]
    fn credentials_need_the_card_seed() {
        let keys_only = SeededSmartcard::new(
            Seeds { card: None, key: Some(&[3u8; 32]) },
            KeyPath::default(),
            "Builder".into(),
        );
        let err = match keys_only.management_key(MgmAlgorithmId::Aes256, &serial()) {
            Ok(_) => panic!("a management key without the card seed"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("card seed"), "{err}");
        assert!(keys_only.generate_chain().is_ok());
    }

    /// Algorithms this tool never installs are refused with a reason, not guessed at.
    #[test]
    fn foreign_management_key_algorithms_are_refused() {
        let err = match card().management_key(MgmAlgorithmId::Aes192, &serial()) {
            Ok(_) => panic!("an AES-192 management key was derived"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("never installs"), "{err}");
    }

    /// A SELECT response as trussed's piv-authenticator sends it once its list follows the
    /// build, with `algorithms` the identifiers listed
    fn listing(algorithms: &[u8]) -> yubikey::piv::ApplicationProperties {
        let mut entries: Vec<u8> = algorithms.iter().flat_map(|id| [0x80, 0x01, *id]).collect();
        entries.extend([0x06, 0x01, 0x00]);
        let mut template = vec![0x4f, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00];
        template.push(0xac);
        template.push(u8::try_from(entries.len()).unwrap());
        template.extend(entries);
        let mut response = vec![0x61, u8::try_from(template.len()).unwrap()];
        response.extend(template);
        yubikey::piv::ApplicationProperties::parse(&response).unwrap()
    }

    /// A card that lists its algorithms is judged by the list before anything is wiped:
    /// every slot's key algorithm and a management key algorithm `upload` can install
    #[test]
    fn listed_algorithms_decide_before_the_reset() {
        // AES-256, 3DES, P-256, P-384, Ed25519 and X25519: a build without RSA
        let no_rsa = listing(&[0x0c, 0x03, 0x11, 0x14, 0xe0, 0xe1]);

        let roles = SlotRole::ALL;
        assert_eq!(card().unlisted(&no_rsa, &roles, true), Some(vec![]));
        assert_eq!(
            card()
                .with_algorithm(Algorithm::Curve25519)
                .unlisted(&no_rsa, &roles, true),
            Some(vec![])
        );
        assert_eq!(
            card()
                .with_algorithm(Algorithm::Rsa3072)
                .unlisted(&no_rsa, &roles, true),
            Some(vec!["RSA-3072".to_string()])
        );

        // Curve25519 needs both of its card algorithms, named once each
        let no_x25519 = listing(&[0x0c, 0x11, 0xe0]);
        assert_eq!(
            card()
                .with_algorithm(Algorithm::Curve25519)
                .unlisted(&no_x25519, &roles, true),
            Some(vec!["X25519".to_string()])
        );

        // `auto` takes either management key algorithm; an explicit one needs exactly it
        let tdes_only = listing(&[0x03, 0x11]);
        assert_eq!(card().unlisted(&tdes_only, &roles, true), Some(vec![]));
        // An upload installs no management key, so it asks for none
        assert_eq!(
            card()
                .with_management_key(ManagementKeyArg::Aes256)
                .unlisted(&tdes_only, &roles[..3], false),
            Some(vec![])
        );
        assert_eq!(
            card()
                .with_management_key(ManagementKeyArg::Aes256)
                .unlisted(&tdes_only, &roles, true),
            Some(vec!["an AES-256 management key".to_string()])
        );
    }

    /// A card that lists nothing, such as a YubiKey, leaves the decision to the version
    #[test]
    fn unlisted_algorithms_decide_nothing() {
        let yubikey = yubikey::piv::ApplicationProperties::parse(&[
            0x61, 0x11, 0x4f, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x07, 0x4f, 0x05,
            0xa0, 0x00, 0x00, 0x03, 0x08,
        ])
        .unwrap();
        assert_eq!(
            card()
                .with_algorithm(Algorithm::Rsa4096)
                .unlisted(&yubikey, &SlotRole::ALL, true),
            None
        );
    }
}
