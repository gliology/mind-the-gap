//! The OpenPGP backend: certificates from seeds, and uploads to OpenPGP cards.
//!
//! [`SeededSmartcard`] re-derives a key set -- a primary plus signing, decryption and
//! authentication subkeys, Ed25519 and X25519 by default, NIST P-256 with
//! [`Algorithm::P256`], or RSA -- from its seeds, and either exports it as a certificate or imports
//! it into a card through `openpgp-card`. Determinism is the point:
//! creation times default to fixed values, the patched `sequoia-openpgp` drops its
//! per-signature salt, and P-256 signs with RFC 6979 nonces (`signer`), so the same seed
//! reproduces the same bytes -- see the derivation chapter,
//! <https://gliology.github.io/mind-the-gap/derivation.html>.

use crate::backend::{Applet, Backend, KeySide, Subtrees};
use crate::policy::Policy;
use crate::revocation::RevocationKind;
use crate::role::KeyRole;
use crate::seed::{Algorithm, KeyPath, SecretSeed, Seed256, Seed256Derive, Seeds};
use crate::target::CardTarget;

use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use anyhow::{Result, anyhow, bail};

use zeroize::Zeroizing;

use openpgp::cert::Cert;
use openpgp::crypto::Password;
use openpgp::packet::{self, UserID};
use openpgp::serialize::SerializeInto;
use openpgp::types::{KeyFlags, SignatureType};
use sequoia_openpgp as openpgp;

use openpgp_card::ocard::KeyType;

use rsa::RsaPrivateKey;

mod card;
mod import;
mod keys;
mod ownership;
mod signer;
mod update;

pub(crate) use card::read_ident;
pub use card::{change_pin, list, refuse_unfit_pin};
pub use update::generation_on_card;
pub use update::{Change as UpdateChange, UpdatePlan};

/// Why `--algorithm p384` stops at the OpenPGP backend
///
/// The curve exists for PIV chains whose consumers insist on P-384. Deriving OpenPGP keys
/// on it would add a third set of labels to the scheme for no card that asked for it.
pub(crate) const P384_REFUSED: &str = "P-384 is a PIV-only curve: the OpenPGP backend derives on curve25519, p256 or rsa2048 to rsa4096";

/// Which part of the certificate to publish
#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq)]
pub enum CertificateKind {
    /// The primary key, its user ids and the chosen subkeys, all self-signed
    #[default]
    Full,
    /// The primary key with its direct key signature only
    Primary,
    /// The primary key and its user ids
    Uids,
    /// The primary key and the chosen subkeys
    Subkeys,
}

/// Level of verification to specify in certification
#[derive(clap::ValueEnum, Clone, Debug, Default, PartialEq)]
pub enum VerificationKind {
    /// Unspecified amount of verification of identity claim
    #[default]
    Generic,
    /// No verification of identity claim
    Persona,
    /// Casual verification of identity claim
    Casual,
    /// Substantial verification of identity claim
    Positive,
}

/// Whether `init` makes the card take its pins through the KDF data object
///
/// With it (OpenPGP card 3.3), the host sends an iterated and salted SHA-256 hash of each
/// pin rather than the pin itself, so the pin never crosses the reader and the card holds
/// only the hash. Every client that enters a pin then has to know the scheme: gpg does,
/// OpenKeychain does not yet.
#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Kdf {
    /// On where the card depends on it, which is Gnuk: it wraps the keys it holds under the
    /// pin, and a stock Gnuk 2 imports no key without the KDF data object
    #[default]
    Auto,
    /// On, on every card that offers the KDF data object, refused where it does not
    On,
    /// Off: the pins go to the card as they are typed
    Off,
}

/// Which set of derivation labels to use
///
/// The labels of the current scheme are self-describing strings, behind a card seed and a
/// key seed. The scheme they replaced mixed three conventions -- sequence bytes, protocol
/// constants and strings -- derived everything from one seed, and let a user-supplied subkey
/// id collide with a fixed label. Cards provisioned under the old scheme keep working
/// through [`Scheme::Legacy`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Scheme {
    /// Self-describing labels, with the subkey id namespaced behind
    /// [`seed::PREFIX_SUB`](crate::seed::PREFIX_SUB)
    #[default]
    Current,
    /// The original labels, for cards provisioned before the scheme changed
    Legacy,
}

/// The OpenPGP side of a usable key: its card slot, its label and its flags
///
/// One place for what used to live in four parallel magic-byte tables: the legacy label
/// byte, the card slot, the binding flags and the flag matching all hang off the role, so
/// they cannot drift apart.
impl KeyRole {
    /// Every role, in the order subkeys are generated and uploaded, which is the card's
    pub const PGP: [KeyRole; 3] = [
        KeyRole::Signature,
        KeyRole::Decryption,
        KeyRole::Authentication,
    ];

    /// Legacy derivation label byte, frozen for cards provisioned under the old scheme.
    ///
    /// 0x0C is transport(0x04)|storage(0x08): the legacy scheme derived the label from how
    /// the OpenPGP key flags happen to be bundled.
    fn code(self) -> u8 {
        match self {
            KeyRole::Signature => 0x02,
            KeyRole::Decryption => 0x0C,
            KeyRole::Authentication => 0x20,
        }
    }

    /// Card slot this role is uploaded to
    pub fn key_type(self) -> KeyType {
        match self {
            KeyRole::Signature => KeyType::Signing,
            KeyRole::Decryption => KeyType::Decryption,
            KeyRole::Authentication => KeyType::Authentication,
        }
    }

    /// Whether the role takes a key agreement key rather than a signing one
    fn is_encryption(self) -> bool {
        matches!(self, KeyRole::Decryption)
    }

    /// Label segment of this role's key under `algorithm`, see
    /// [`seed::algorithm_label`](crate::seed::algorithm_label)
    fn algorithm_segment(self, algorithm: Algorithm) -> &'static str {
        if self.is_encryption() {
            algorithm.agreement_segment()
        } else {
            algorithm.signing_segment()
        }
    }

    /// The key flags the subkey is bound with
    fn flags(self) -> KeyFlags {
        match self {
            KeyRole::Signature => KeyFlags::empty().set_signing(),
            KeyRole::Decryption => KeyFlags::empty()
                .set_transport_encryption()
                .set_storage_encryption(),
            KeyRole::Authentication => KeyFlags::empty().set_authentication(),
        }
    }

    /// Whether a subkey's flags mark it as serving this role
    pub fn matches(self, flags: &KeyFlags) -> bool {
        match self {
            KeyRole::Signature => flags.for_signing(),
            KeyRole::Decryption => {
                flags.for_transport_encryption() || flags.for_storage_encryption()
            }
            KeyRole::Authentication => flags.for_authentication(),
        }
    }
}

/// Config to create an OpenPGP user cert
pub struct SeededSmartcard {
    /// The card seed's OpenPGP subtree, which the admin pin and the card identifier of every
    /// card derive from, and the key seed's, where the primary key sits; under the legacy
    /// scheme the one seed's subkey seed and its root, with the subkey seed in place of both
    /// key paths, since it shares no key between cards
    seeds: Subtrees,

    /// The keys derived so far, on the heap, where a builder moved on to its next option
    /// moves only the pointer
    derived: Box<Derived>,

    /// Where the subkeys sit under the key seed
    path: KeyPath,

    /// Algorithm every key is derived with; the legacy scheme knows only Curve25519
    algorithm: Algorithm,

    /// Which set of derivation labels this card was built with
    scheme: Scheme,

    /// Name of the owner of the cert
    name: String,

    /// User pin `init` installs and `check` verifies
    pin: Option<Zeroizing<String>>,

    /// Creation time of the primary key, which the identity keeps for good
    identity_time: Option<SystemTime>,

    /// Creation time of the subkeys under the legacy scheme, which knows no generations
    legacy_subkey_time: Option<SystemTime>,

    /// Validity duration of subkeys
    subkey_validity: Option<Duration>,

    /// List of user ids to include in cert
    userids: Vec<packet::UserID>,

    /// Pin and touch requirements `upload` gives the keys
    policy: Policy,

    /// Whether the policy was chosen rather than defaulted: `upload` changes a card's
    /// policies only when asked to, and otherwise keeps what the card has
    policy_given: bool,

    /// Whether `upload` makes the touch requirement unchangeable, where the card can
    fixed_touch: bool,

    /// Whether `init` sets up the KDF data object
    kdf: Kdf,

    /// The keys `upload` writes, `check` compares and `publish` certifies
    keys: Vec<KeyRole>,

    /// Card data `upload` writes when given: language preferences, the certificate's URL
    /// and the login data
    card_data: CardData,
}

/// The keys a builder has derived, each derived once however often a command uses it
///
/// Secret, and wiped with the builder: the raw secrets wipe themselves on drop, as the RSA
/// keys do.
#[derive(Default)]
struct Derived {
    /// The primary key's
    primary: OnceLock<KeySecret>,
    /// The subkeys', in [`KeyRole::PGP`] order
    roles: [OnceLock<KeySecret>; 3],
}

/// One key's derived secret: the raw bytes, and for RSA the key they stand for, whose primes
/// take seconds to find
struct KeySecret {
    raw: SecretSeed,
    rsa: Option<Box<RsaPrivateKey>>,
}

/// Cardholder data an upload writes, each only when given
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CardData {
    /// Cardholder language preferences, most preferred first
    pub lang: Vec<[u8; 2]>,
    /// URL where the public certificate can be fetched
    pub url: Option<String>,
    /// Login data (conventionally an account or user name)
    pub login: Option<String>,
}

impl SeededSmartcard {
    /// Initialize a new seeded smartcard config from the seeds a command has
    pub fn new(seeds: Seeds<'_>, path: KeyPath, name: String) -> Self {
        let seeds = Subtrees::new(seeds, "pgp", &path);
        Self::assemble(seeds, path, name, Scheme::Current)
    }

    /// Build a card under the legacy scheme, from its one seed
    ///
    /// The legacy scheme knows no card seed, no generation and no shared key: the admin pin
    /// and every subkey derive from the subkey seed, the primary from the root.
    pub fn legacy(seed: &Seed256, subkey: Option<String>, name: String) -> Self {
        // The label is the subcommand's old spelling, frozen with the rest of the scheme
        let root = seed.derive(Some(b"openpgp"));
        let subseed = root.derive(subkey.as_ref().map(|k| k.as_bytes()));
        let key = KeySide::fixed(root, subseed.clone(), subseed.clone());
        let path = KeyPath { subkey, date: None };
        Self::assemble(Subtrees::fixed(subseed, key), path, name, Scheme::Legacy)
    }

    fn assemble(seeds: Subtrees, path: KeyPath, name: String, scheme: Scheme) -> Self {
        SeededSmartcard {
            seeds,
            derived: Box::default(),
            path,
            algorithm: Algorithm::Curve25519,
            scheme,
            name,
            pin: None,
            identity_time: None,
            legacy_subkey_time: None,
            subkey_validity: None,
            userids: vec![],
            policy: Policy::default(),
            policy_given: false,
            fixed_touch: false,
            kdf: Kdf::default(),
            keys: KeyRole::PGP.to_vec(),
            card_data: CardData::default(),
        }
    }

    /// Derive every key with `algorithm`, the primary included
    ///
    /// Each algorithm derives under its own labels, so a certificate in one algorithm shares no key
    /// material with the same seed's certificate on the other. The legacy scheme predates
    /// the algorithm segment and only ever produced Curve25519 keys, so it refuses anything else.
    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Result<Self> {
        if algorithm == Algorithm::P384 {
            bail!(P384_REFUSED);
        }
        if self.scheme == Scheme::Legacy && algorithm != Algorithm::Curve25519 {
            bail!(
                "The legacy scheme derives Curve25519 keys only: drop --legacy to pick another algorithm"
            );
        }

        self.algorithm = algorithm;
        self.derived = Box::default();
        Ok(self)
    }

    /// Write, compare and certify only these subkeys, in the card's order
    pub fn with_keys(mut self, keys: &[KeyRole]) -> Result<Self> {
        if keys.is_empty() {
            bail!("No key chosen: name at least one of authentication, signature or decryption");
        }
        self.keys = KeyRole::PGP
            .into_iter()
            .filter(|role| keys.contains(role))
            .collect();
        Ok(self)
    }

    /// Write this cardholder data with the keys
    pub fn with_card_data(mut self, data: CardData) -> Self {
        self.card_data = data;
        self
    }

    /// The key path this card derives its subkeys along
    pub fn path(&self) -> &KeyPath {
        &self.path
    }

    /// Choose the pin and touch requirements `upload` gives the keys
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self.policy_given = true;
        self
    }

    /// Make the touch requirement unchangeable but by replacing the key, on cards that offer
    /// it (YubiKeys); elsewhere `upload` sets the plain variant and says so
    pub fn with_fixed_touch(mut self, fixed: bool) -> Self {
        self.fixed_touch = fixed;
        self
    }

    /// Choose whether `init` makes the card take hashed pins
    pub fn with_kdf(mut self, kdf: Kdf) -> Self {
        self.kdf = kdf;
        self
    }

    /// Set the user pin `init` installs and `check` verifies
    ///
    /// Fails on a pin no OpenPGP card takes, see [`refuse_unfit_pin`].
    pub fn with_pin(mut self, pin: Zeroizing<String>) -> Result<Self> {
        refuse_unfit_pin(&pin)?;
        self.pin = Some(pin);
        Ok(self)
    }

    /// Set the creation time of the primary key, which is part of its fingerprint: the
    /// identity keeps it for good
    pub fn with_identity_time(mut self, timestamp: SystemTime) -> Self {
        self.identity_time = Some(timestamp);
        self
    }

    /// Set the subkeys' creation time under the legacy scheme, which took it as an option of
    /// its own; the current scheme takes it from the generation's date
    pub fn with_legacy_subkey_time(mut self, timestamp: SystemTime) -> Self {
        self.legacy_subkey_time = Some(timestamp);
        self
    }

    /// Set subkey validity period
    pub fn with_subkey_validity(mut self, validity: Duration) -> Self {
        self.subkey_validity = Some(validity);
        self
    }

    /// Add userid to certificate.
    ///
    /// Fails on an address the OpenPGP user id convention cannot hold -- an embedded angle
    /// bracket or newline is an input error, not a panic.
    pub fn add_email(mut self, email: &str) -> Result<Self> {
        let userid = UserID::from_address(Some(&self.name[..]), None, email)
            .map_err(|err| anyhow!("Email address '{email}' does not fit a user id: {err}"))?;
        self.userids.push(userid);
        Ok(self)
    }

    /// Certify primary key, uids and/or subkeys
    pub fn certify(&self, kind: CertificateKind) -> Result<Cert> {
        use CertificateKind::*;

        let mut cert = self.primary_cert(kind == Primary || kind == Full, None)?;

        if kind == Uids || kind == Full {
            cert = self.append_uids(cert)?;
        }

        if kind == Subkeys || kind == Full {
            cert = self.append_subkeys(cert, None)?
        }

        Ok(cert.strip_secret_key_material())
    }

    /// Certify external keys
    pub fn trust(&self, other: Cert, kind: VerificationKind) -> Result<Cert> {
        use VerificationKind::*;

        let kind = match kind {
            Generic => SignatureType::GenericCertification,
            Persona => SignatureType::PersonaCertification,
            Casual => SignatureType::CasualCertification,
            Positive => SignatureType::PositiveCertification,
        };

        // Remove subkeys from supplied cert, as we do not sign those
        let cert = other.clone().retain_subkeys(|_| false);

        self.sign_uids(cert, other, kind)
    }

    /// Export all secret keys, encrypted under `passphrase` where there is one
    pub fn export(&self, passphrase: Option<&str>) -> Result<Cert> {
        let passphrase = passphrase.map(Password::from);
        let mut cert = self.primary_cert(false, passphrase.as_ref())?;

        cert = self.append_uids(cert)?;
        self.append_subkeys(cert, passphrase.as_ref())
    }

    /// Generate a revocation, ready to be armored
    ///
    /// A certificate revocation is a bare packet, which is the artifact gnupg expects and can
    /// be kept apart from the key it retires. A subkey revocation is delivered as the whole
    /// certificate instead: a lone subkey revocation signature has nothing to attach to, so
    /// what a recipient actually needs to import is the certificate carrying it.
    pub fn revoke(&self, kind: RevocationKind, code: u8, reason: &str) -> Result<Vec<u8>> {
        match kind {
            RevocationKind::Certificate => {
                let mut cert = self.primary_cert(false, None)?;
                let revocation = self.generate_revcert(&mut cert, code, reason)?;

                Ok(revocation.to_vec()?)
            }
            RevocationKind::Subkeys => {
                let cert = self.certify(CertificateKind::Full)?;
                let revocations = self.generate_subkey_revcerts(&cert, code, reason)?;

                if revocations.is_empty() {
                    bail!(
                        "Every chosen subkey is shared by every card of the identity; there is \
                         nothing to revoke for this device alone. Revoke the identity's \
                         decryption key with --key decryption"
                    );
                }

                Ok(cert.insert_packets(revocations)?.0.to_vec()?)
            }
        }
    }
}

impl Applet for SeededSmartcard {
    fn name(&self) -> &'static str {
        "OpenPGP"
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
