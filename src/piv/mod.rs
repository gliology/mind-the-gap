//! The PIV backend: an X.509 chain from seeds, and uploads to YubiKeys.
//!
//! [`SeededSmartcard`] derives a root certificate authority, an optional issuing authority
//! and the four slot keys (9A, 9C, 9D, 9E) on NIST P-256, on NIST P-384 with
//! [`Algorithm::P384`], as Ed25519 and X25519 keys with [`Algorithm::Curve25519`], or as
//! RSA keys. The chain is signed with RFC 6979 deterministic ECDSA, pure Ed25519 or PKCS#1
//! v1.5, all deterministic, so re-runs are byte-identical, and keys, certificates,
//! identifiers and per-slot policies are written to the card through the `yubikey` crate.
//! The chain layout and its constraints are documented in the certificates chapter,
//! <https://gliology.github.io/mind-the-gap/piv-certificates.html>.

use std::time::{Duration, SystemTime};

use crate::policy::Policy;
use crate::seed::{Algorithm, Seed256, Seed256Derive};

use anyhow::{Result, anyhow};

use yubikey::piv::SlotId;

use x509_cert::ext::pkix::name::GeneralName;

use der::asn1::Ia5String;

use zeroize::Zeroizing;

mod card;
mod chain;
mod check;
mod keys;
mod slots;

pub use card::status;
pub use chain::CertChain;
use chain::SubjectName;
pub use slots::SlotRole;

/// Which part of the certificate chain to export
#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq)]
pub enum CertificateKind {
    /// The certificate authorities plus all four slot certificates
    #[default]
    Chain,
    /// The self-signed root certificate authority, i.e. the trust anchor to distribute
    Root,
    /// The intermediate issuing certificate authority only
    Intermediate,
    /// The four slot certificates only
    Leaves,
}

/// Slots whose key can be derived without the subkey id, so it comes out the same on every card
///
/// Sharing the key management slot is the usual reason to reach for this. A sender encrypts to
/// one specific 9D certificate, so per-card key management keys mean a message can only be
/// opened on the card whose certificate the sender chose. Authentication and signature have no
/// such problem: the verifier checks whichever certificate was presented.
///
/// Slot 9E is deliberately absent. It identifies the *card*, carrying the card id in its
/// subject rather than the cardholder, so a shared one would defeat its only purpose.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SharedSlot {
    /// Authentication slot (9A)
    Authentication,
    /// Signature slot (9C)
    Signature,
    /// Key management slot (9D)
    KeyManagement,
}

impl From<SharedSlot> for SlotId {
    fn from(shared: SharedSlot) -> Self {
        match shared {
            SharedSlot::Authentication => SlotId::Authentication,
            SharedSlot::Signature => SlotId::Signature,
            SharedSlot::KeyManagement => SlotId::KeyManagement,
        }
    }
}

/// Algorithm of the derived management key `upload` installs in slot 9B
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
    /// Application seed the root authority and every generation's subseed descend from
    ///
    /// The root authority is a *sibling* of the subseeds, not their parent: were it the
    /// parent, anyone holding the authority key could re-derive every slot key. Kept so
    /// that a *previous* generation can be re-derived for archival, too.
    root: Zeroizing<Seed256>,

    /// Algorithm every asymmetric key in the chain is derived with
    algorithm: Algorithm,

    /// Seed used for the issuing authority, management key and all slot keys
    subseed: Zeroizing<Seed256>,
    /// Seed the subkey id is *not* mixed into, for slots listed in `shared`
    shared_seed: Zeroizing<Seed256>,
    /// Slots whose key is derived from `shared_seed` rather than `subseed`
    shared: Vec<SharedSlot>,

    /// Subkey id, used to keep issuing authority subjects distinguishable
    subkey: Option<String>,

    /// Superseded subkey ids whose key management key is archived, newest first
    retired: Vec<String>,

    /// Distinguished name attributes for every tier of the chain
    identity: SubjectName,

    /// Alternative names, e.g. emails addresses, to use in the leaf certificates
    alternatives: Vec<GeneralName>,

    /// Creation time of certificates
    creation_time: Option<SystemTime>,

    /// Validity duration of the leaf certificates
    validity_duration: Option<Duration>,

    /// User pin to set on the card
    pin: Option<Zeroizing<String>>,

    /// Whether to insert an intermediate issuing certificate authority
    intermediate: bool,

    /// Pin and touch requirements of every slot but 9E, and of management access
    policy: Policy,

    /// Whether to write the certificate authorities to the card's `msroots` object
    msroots: bool,

    /// Algorithm of the management key `upload` installs
    management_algorithm: ManagementKeyArg,
}

impl SeededSmartcard {
    /// Initialize a new seeded smartcard config
    pub fn new(seed: &Seed256, subkey: Option<String>, name: String) -> Self {
        // Derive application specific root seed
        let root = seed.app("piv");

        // Derive everything below the subkey id
        let subseed = root.sub(subkey.as_deref());

        // What the subseed would have been with no subkey id at all. Identical to `subseed`
        // when none was given, which is what makes `--shared` a no-op for a single card.
        let shared_seed = root.sub(None);

        SeededSmartcard {
            root,
            algorithm: Algorithm::P256,
            subseed,
            shared_seed,
            retired: vec![],
            shared: vec![],
            subkey,
            identity: SubjectName { name, ..Default::default() },
            alternatives: vec![],
            creation_time: None,
            validity_duration: None,
            pin: None,
            intermediate: false,
            policy: Policy::default(),
            msroots: true,
            management_algorithm: ManagementKeyArg::Auto,
        }
    }

    /// Set the pin to install on the card in place of the PIV default
    pub fn with_pin(mut self, pin: Zeroizing<String>) -> Self {
        self.pin = Some(pin);
        self
    }

    /// Derive the whole chain with `algorithm`, authorities included
    ///
    /// Every algorithm derives under its own labels, so switching a card between algorithms shares
    /// no key material between the two chains.
    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
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

    /// Archive the key management keys of superseded generations, newest first
    ///
    /// Each lands in a retired key management slot, 0x82 upward, so data encrypted to an older
    /// generation stays readable after the live key rotates. Only the key management key is
    /// archived: an old signing key would merely allow backdated signatures, and old
    /// authentication keys have no historical use.
    pub fn with_retired(mut self, retired: Vec<String>) -> Self {
        self.retired = retired;
        self
    }

    /// Derive the named slots without the subkey id, so every card gets the same key
    pub fn with_shared(mut self, shared: Vec<SharedSlot>) -> Self {
        self.shared = shared;
        self
    }

    /// Choose the pin and touch requirements `upload` gives the slots and management access
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// Pick the algorithm of the management key `upload` installs
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

    /// Set certificate creation time
    pub fn with_creation_time(mut self, timestamp: SystemTime) -> Self {
        self.creation_time = Some(timestamp);
        self
    }

    /// Set certificate validity duration
    pub fn with_validity_duration(mut self, duration: Duration) -> Self {
        self.validity_duration = Some(duration);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed;
    use yubikey::piv::RetiredSlotId;
    use yubikey::{MgmAlgorithmId, PinPolicy, TouchPolicy};

    fn card() -> SeededSmartcard {
        SeededSmartcard::new(&[3u8; 32], Some("builder".into()), "Builder".into())
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
    /// access secrets, in `keys.rs`.
    #[test]
    fn tdes_management_key_is_independent_of_aes() {
        let tdes = card().management_key(MgmAlgorithmId::ThreeDes).unwrap();
        let again = card().management_key(MgmAlgorithmId::ThreeDes).unwrap();
        let aes = card().management_key(MgmAlgorithmId::Aes256).unwrap();

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

        // A different card gets a different key
        let other = SeededSmartcard::new(&[3u8; 32], Some("other".into()), "Builder".into())
            .management_key(MgmAlgorithmId::ThreeDes)
            .unwrap();
        assert_ne!(tdes.as_ref(), other.as_ref());
    }

    /// Algorithms this tool never installs are refused with a reason, not guessed at.
    #[test]
    fn foreign_management_key_algorithms_are_refused() {
        let err = match card().management_key(MgmAlgorithmId::Aes192) {
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

        assert_eq!(card().unlisted(&no_rsa), Some(vec![]));
        assert_eq!(
            card()
                .with_algorithm(Algorithm::Curve25519)
                .unlisted(&no_rsa),
            Some(vec![])
        );
        assert_eq!(
            card().with_algorithm(Algorithm::Rsa3072).unlisted(&no_rsa),
            Some(vec!["RSA-3072".to_string()])
        );

        // Curve25519 needs both of its card algorithms, named once each
        let no_x25519 = listing(&[0x0c, 0x11, 0xe0]);
        assert_eq!(
            card()
                .with_algorithm(Algorithm::Curve25519)
                .unlisted(&no_x25519),
            Some(vec!["X25519".to_string()])
        );

        // `auto` takes either management key algorithm; an explicit one needs exactly it
        let tdes_only = listing(&[0x03, 0x11]);
        assert_eq!(card().unlisted(&tdes_only), Some(vec![]));
        assert_eq!(
            card()
                .with_management_key(ManagementKeyArg::Aes256)
                .unlisted(&tdes_only),
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
        assert_eq!(card().with_algorithm(Algorithm::Rsa4096).unlisted(&yubikey), None);
    }
}
