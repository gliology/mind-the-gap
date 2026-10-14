//! The OpenPGP backend: certificates from seeds, and uploads to OpenPGP cards.
//!
//! [`SeededSmartcard`] re-derives a key set -- a primary plus signing, decryption and
//! authentication subkeys, Ed25519 and X25519 by default, NIST P-256 with
//! [`Algorithm::P256`], or RSA -- from its seeds, and either exports it as a certificate or imports
//! it into a card through `openpgp-card`. Determinism is the point:
//! creation times default to fixed values and the patched `sequoia-openpgp` drops its
//! per-signature salt, so the same seed reproduces the same bytes -- see the derivation
//! chapter, <https://gliology.github.io/mind-the-gap/derivation.html>.

use crate::seed::{self, Algorithm, Seed256, Seed256Derive};

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

use openpgp_card::ocard::data::TouchPolicy;

use crate::pgp::keys::NAME_PRIMARY;

mod card;
mod import;
mod keys;

pub use card::status;

/// Why `--algorithm p384` stops at the OpenPGP backend
///
/// The curve exists for PIV chains whose consumers insist on P-384. Deriving OpenPGP keys
/// on it would add a third set of labels to a frozen scheme for no card that asked for it.
pub(crate) const P384_REFUSED: &str = "P-384 is a PIV-only curve: the OpenPGP backend derives on curve25519, p256 or rsa2048 to rsa4096";

/// What a revocation covers
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationKind {
    /// Retire the whole identity, primary key and all
    Certificate,
    /// Retire only this card's subkeys, leaving the identity and every other card alone
    ///
    /// The point of provisioning each card under its own subkey id: one lost card can be taken
    /// out of service without reissuing the identity everywhere.
    Subkeys,
}

/// Type of certificate to generate
#[derive(clap::ValueEnum, Clone, Debug, Default, PartialEq)]
pub enum CertificateKind {
    /// Generate certificate for user IDs and subkeys
    #[default]
    Generic,
    /// Generate certificate for primary key only
    Primary,
    /// Generate certificate for user IDs only
    Uids,
    /// Generate certificate for subkeys only
    Subkeys,
    /// Generate full certificate, incl. self-signed primary
    Full,
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

/// Which set of derivation labels to use
///
/// The labels below are self-describing strings. The scheme they replaced mixed three
/// conventions -- sequence bytes, protocol constants and strings -- and, more importantly, let
/// a user-supplied subkey id collide with a fixed label. Cards provisioned under the old
/// scheme keep working through [`Scheme::Legacy`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Scheme {
    /// Self-describing labels, with the subkey id namespaced behind [`seed::PREFIX_SUB`]
    #[default]
    Current,
    /// The original labels, for cards provisioned before the scheme changed
    Legacy,
}

/// The three subkey roles this backend derives, in generation and upload order.
///
/// One type for what used to live in four parallel magic-byte tables: the legacy label
/// byte, the current label name, the card slot, the binding flags and the flag matching
/// all hang off the role, so they cannot drift apart.
///
/// As a `--shared` value it names a subkey to derive *without* the subkey id, so it comes
/// out the same on every card. Sharing the decryption key is the usual reason: an OpenPGP
/// client encrypts to exactly *one* of a certificate's encryption subkeys, so per-card
/// decryption keys mean a message can only be opened on whichever card the sender happened
/// to pick. Signing and authentication have no such problem -- the verifier checks
/// whichever subkey was used.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubkeyRole {
    /// Signing subkey
    Signing,
    /// Decryption subkey
    Decryption,
    /// Authentication subkey
    Authentication,
}

/// The role named by `--shared`, which is simply a subkey role
pub type SharedKey = SubkeyRole;

/// Command line mirror of `openpgp-card`'s [`TouchPolicy`], which is a foreign type.
///
/// Spelled like PIV's touch policies, so both backends share one vocabulary. The `-fixed`
/// variants brick the setting on purpose: a card configured `always-fixed` or `cached-fixed`
/// refuses to change that key's policy again until its key is re-imported, which is what
/// makes the requirement tamper-evident.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum TouchPolicyArg {
    /// Never require a touch
    Never,
    /// Require a touch for every operation
    Always,
    /// Require a touch for every operation, and lock this setting until the key is replaced
    AlwaysFixed,
    /// Require a touch, valid for about 15 seconds of operations
    Cached,
    /// Like cached, and lock this setting until the key is replaced
    CachedFixed,
}

impl From<TouchPolicyArg> for TouchPolicy {
    fn from(arg: TouchPolicyArg) -> Self {
        match arg {
            TouchPolicyArg::Never => TouchPolicy::Off,
            TouchPolicyArg::Always => TouchPolicy::On,
            TouchPolicyArg::AlwaysFixed => TouchPolicy::Fixed,
            TouchPolicyArg::Cached => TouchPolicy::Cached,
            TouchPolicyArg::CachedFixed => TouchPolicy::CachedFixed,
        }
    }
}

/// How long one user pin entry stays valid for signing
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignPinValidity {
    /// Every signature asks for the pin again (the card default)
    Once,
    /// One pin entry signs until the card is disconnected
    Session,
}

/// What [`SeededSmartcard::configure`] may change on a provisioned card.
///
/// Everything is optional and only applied when given, so the command can adjust one
/// setting without touching the others.
#[derive(Default)]
pub struct CardSettings {
    /// Per-key touch policies to set
    pub touch: Vec<(SubkeyRole, TouchPolicyArg)>,
    /// Cardholder language preferences, most preferred first
    pub lang: Vec<[u8; 2]>,
    /// URL where the public certificate can be fetched
    pub url: Option<String>,
    /// Login data (conventionally an account or user name)
    pub login: Option<String>,
    /// Whether one pin entry signs once or for the whole session
    pub sign_pin: Option<SignPinValidity>,
}

impl SubkeyRole {
    /// Every role, in the order subkeys are generated and uploaded
    pub const ALL: [SubkeyRole; 3] = [
        SubkeyRole::Signing,
        SubkeyRole::Decryption,
        SubkeyRole::Authentication,
    ];

    /// Legacy derivation label byte, frozen for cards provisioned under the old scheme.
    ///
    /// 0x0C is transport(0x04)|storage(0x08): the legacy scheme derived the label from how
    /// the OpenPGP key flags happen to be bundled.
    fn code(self) -> u8 {
        match self {
            SubkeyRole::Signing => 0x02,
            SubkeyRole::Decryption => 0x0C,
            SubkeyRole::Authentication => 0x20,
        }
    }

    /// Current-scheme label name; `signature` rather than `signing` because it is the
    /// OpenPGP card spec's own name for the slot, and it matches the PIV label for the role
    fn name(self) -> &'static str {
        match self {
            SubkeyRole::Signing => "signature",
            SubkeyRole::Decryption => "decryption",
            SubkeyRole::Authentication => "authentication",
        }
    }

    /// Card slot this role is uploaded to
    pub fn key_type(self) -> KeyType {
        match self {
            SubkeyRole::Signing => KeyType::Signing,
            SubkeyRole::Decryption => KeyType::Decryption,
            SubkeyRole::Authentication => KeyType::Authentication,
        }
    }

    /// Whether the role takes a key agreement key rather than a signing one
    fn is_encryption(self) -> bool {
        matches!(self, SubkeyRole::Decryption)
    }

    /// Label segment of this role's key under `algorithm`, see [`seed::algorithm_label`]
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
            SubkeyRole::Signing => KeyFlags::empty().set_signing(),
            SubkeyRole::Decryption => KeyFlags::empty()
                .set_transport_encryption()
                .set_storage_encryption(),
            SubkeyRole::Authentication => KeyFlags::empty().set_authentication(),
        }
    }

    /// Whether a subkey's flags mark it as serving this role
    pub fn matches(self, flags: &KeyFlags) -> bool {
        match self {
            SubkeyRole::Signing => flags.for_signing(),
            SubkeyRole::Decryption => {
                flags.for_transport_encryption() || flags.for_storage_encryption()
            }
            SubkeyRole::Authentication => flags.for_authentication(),
        }
    }
}

/// Config to create an OpenPGP user cert
pub struct SeededSmartcard {
    /// Application seed the primary key and every subseed descend from
    ///
    /// Kept so that the primary can be re-derived when the algorithm changes after construction
    root: Zeroizing<Seed256>,

    /// Raw secret of the primary key, derived for `algorithm`
    seed: Zeroizing<Seed256>,

    /// Algorithm every key is derived with; the legacy scheme knows only Curve25519
    algorithm: Algorithm,

    /// Seed used for all subkeys
    subseed: Zeroizing<Seed256>,
    /// Seed the subkey id is *not* mixed into, for keys listed in `shared`
    shared_seed: Zeroizing<Seed256>,
    /// Subkeys derived from `shared_seed` rather than `subseed`
    shared: Vec<SharedKey>,
    /// Which set of derivation labels this card was built with
    scheme: Scheme,
    /// Subkey id this card was provisioned under, recorded in the subkey bindings
    ///
    /// Held as a plain `String`: it names a card rather than guarding it, and it is published
    /// in every certificate this card issues.
    subkey: Option<String>,

    /// Name of the owner of the cert
    name: String,

    /// Password to use to protect smartcard and secret keys
    pin: Option<Password>,

    /// Creation time of key certificate, defaults to one second after unix epoch
    creation_time: Option<SystemTime>,

    /// Creation time of subkeys, defaults to creation time of certificate
    subkey_creation_time: Option<SystemTime>,

    /// Validity duration of subkeys
    subkey_validity: Option<Duration>,

    /// List of user ids to include in cert
    userids: Vec<packet::UserID>,
}

impl SeededSmartcard {
    /// Initialize an new seeded smartcard config
    pub fn new(seed: &Seed256, subkey: Option<String>, name: String) -> Self {
        Self::with_scheme(seed, subkey, name, Scheme::default())
    }

    /// Build a card under an explicit derivation scheme
    pub fn with_scheme(
        seed: &Seed256,
        subkey: Option<String>,
        name: String,
        scheme: Scheme,
    ) -> Self {
        // Derive application specific root seed. The label matches the subcommand, which was
        // itself renamed from `open-pgp` to `pgp`; the legacy scheme keeps the old spelling
        // because changing it would move every key beneath it.
        let root = match scheme {
            Scheme::Legacy => seed.derive(Some(b"openpgp")),
            Scheme::Current => seed.app("pgp"),
        };

        // Derive seed for primary and subkeys. `shared_seed` is what the subseed would have
        // been with no subkey id at all, which is identical to `subseed` when none was given
        // -- that is what makes `--shared` a no-op for a single card.
        let algorithm = Algorithm::Curve25519;
        let (seed, subseed, shared_seed) = match scheme {
            Scheme::Legacy => (
                root.derive(Some(&[0x01])),
                root.derive(subkey.as_ref().map(|k| k.as_bytes())),
                root.derive(None),
            ),
            Scheme::Current => (
                root.algorithm_key(NAME_PRIMARY, algorithm.signing_segment()),
                root.sub(subkey.as_deref()),
                root.sub(None),
            ),
        };

        SeededSmartcard {
            root,
            seed,
            algorithm,
            subseed,
            shared_seed,
            shared: vec![],
            scheme,
            subkey,
            name,
            pin: None,
            creation_time: None,
            subkey_creation_time: None,
            subkey_validity: None,
            userids: vec![],
        }
    }

    /// Derive the named subkeys without the subkey id, so every card gets the same ones
    pub fn with_shared(mut self, shared: Vec<SharedKey>) -> Self {
        self.shared = shared;
        self
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
        if self.scheme == Scheme::Current {
            let label = seed::algorithm_label(NAME_PRIMARY, algorithm.signing_segment());
            self.seed = self.derive_secret(&self.root, Some(&label), false)?;
        }

        Ok(self)
    }

    /// Set password to protect secret keys
    pub fn with_pin(mut self, pin: Zeroizing<String>) -> Self {
        self.pin = Some(pin.as_str().into());
        self
    }

    /// Set certificate creation time
    pub fn with_creation_time(mut self, timestamp: SystemTime) -> Self {
        self.creation_time = Some(timestamp);
        self
    }

    /// Set subkey creation time
    pub fn with_subkey_creation_time(mut self, timestamp: SystemTime) -> Self {
        self.subkey_creation_time = Some(timestamp);
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

        let mut cert = self.primary_cert(kind == Primary || kind == Full)?;

        if kind == Generic || kind == Uids || kind == Full {
            cert = self.append_uids(cert)?;
        }

        if kind == Generic || kind == Subkeys || kind == Full {
            cert = self.append_subkeys(cert)?
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

    /// Export all secret keys
    pub fn export(&self) -> Result<Cert> {
        let mut cert = self.primary_cert(false)?;

        cert = self.append_uids(cert)?;
        self.append_subkeys(cert)
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
                let mut cert = self.primary_cert(false)?;
                let revocation = self.generate_revcert(&mut cert, code, reason)?;

                Ok(revocation.to_vec()?)
            }
            RevocationKind::Subkeys => {
                let cert = self.certify(CertificateKind::Full)?;
                let revocations = self.generate_subkey_revcerts(&cert, code, reason)?;

                if revocations.is_empty() {
                    bail!(
                        "Every subkey of this card is shared across the fleet; there is \
                         nothing to revoke for this card alone"
                    );
                }

                Ok(cert.insert_packets(revocations)?.0.to_vec()?)
            }
        }
    }
}
