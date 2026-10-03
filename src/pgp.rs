//! The OpenPGP backend: certificates from seeds, and uploads to OpenPGP cards.
//!
//! [`SeededSmartcard`] re-derives an ed25519/cv25519 key set -- a primary plus signing,
//! decryption and authentication subkeys -- from its seeds, and either exports it as a
//! certificate or imports it into a card through `openpgp-card`. Determinism is the point:
//! creation times default to fixed values and the patched `sequoia-openpgp` drops its
//! per-signature salt, so the same seed reproduces the same bytes -- see the derivation
//! chapter, <https://gliology.github.io/mind-the-gap/derivation.html>.

use crate::seed::{self, Seed256, Seed256Derive};

use std::convert::TryFrom;
use std::time::{Duration, SystemTime};

use anyhow::{Result, anyhow, bail};

use zeroize::Zeroizing;

use openpgp::cert::{Cert, CertRevocationBuilder, SubkeyRevocationBuilder};
use openpgp::crypto::{KeyPair, Password, mpi};
use openpgp::fmt::hex;
use openpgp::packet::key::Key4;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::packet::{self, Key, UserID, key};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::SerializeInto;
use openpgp::types::{
    Features, HashAlgorithm, KeyFlags, ReasonForRevocation, SignatureType, SymmetricAlgorithm,
};
use openpgp::{Packet, Result as PGPResult};
use sequoia_openpgp as openpgp;

use secrecy::SecretString;

use card_backend_pcsc::PcscBackend;

use openpgp_card::ocard::KeyType;
use openpgp_card::ocard::algorithm::Curve;
use openpgp_card::ocard::crypto::{CardUploadableKey, EccKey, EccType, PrivateKeyMaterial};
use openpgp_card::{Card, Error as CardError};

use openpgp_card::ocard::data::{Fingerprint as CardFingerprint, KeyGenerationTime, TouchPolicy};
use openpgp_card::state::Open;

// Some use type shorthands
type SecretPrimaryKey = Key<key::SecretParts, key::PrimaryRole>;
type SecretSubKey = Key<key::SecretParts, key::SubordinateRole>;

/// Map a numeric reason code onto the OpenPGP set
fn reason(code: u8) -> ReasonForRevocation {
    match code {
        0 => ReasonForRevocation::Unspecified,
        1 => ReasonForRevocation::KeySuperseded,
        2 => ReasonForRevocation::KeyCompromised,
        3 => ReasonForRevocation::KeyRetired,
        32 => ReasonForRevocation::UIDRetired,
        100..=110 => ReasonForRevocation::Private(code),
        _ => ReasonForRevocation::Unknown(code),
    }
}

/// What a revocation covers
#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RevocationKind {
    /// Retire the whole identity, primary key and all
    #[default]
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

/// Subkeys to export
pub const DEFAULT_KEY_TYPES: [KeyType; 3] = [
    KeyType::Signing,
    KeyType::Decryption,
    KeyType::Authentication,
];

/// Notation naming the card a subkey was provisioned for
///
/// On the *subkey binding* signature rather than the user id: a user id is bound to the
/// primary key, and the primary is identical on every card, so a comment there would label one
/// shared identity with one card's name -- and merging two cards' certificates would leave two
/// user ids for the same person. The binding signature is the only part that is genuinely per
/// card, and it survives a merge with each subkey keeping its own.
const NOTATION_SUBKEY: &str = "subkey@mind-the-gap.gli.al";

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

    /// Whether the role takes an encryption (cv25519) key rather than a signing (ed25519) one
    fn is_encryption(self) -> bool {
        matches!(self, SubkeyRole::Decryption)
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

/// Print list of currently available OpenPGP cards
pub fn status() -> Result<()> {
    println!("Available OpenPGP cards:");

    let backends: Vec<PcscBackend> = PcscBackend::cards(None)
        .map(|iter| iter.filter_map(Result::ok).collect())
        .unwrap_or_default();

    if backends.is_empty() {
        println!(" - None");
        println!();
    }

    for backend in backends {
        let mut card = Card::new(backend)?;
        let mut transaction = card.transaction()?;

        println!(" - Card {}", transaction.application_identifier()?.ident());

        let name = transaction.cardholder_name()?;
        if !name.is_empty() {
            println!("   Cardholder: {}", name);
        }

        for kt in DEFAULT_KEY_TYPES {
            if let Ok(Some(fp)) = transaction.fingerprint(kt) {
                println!("   {:?} key: {}", kt, fp.to_spaced_hex());
            }
        }

        println!();
    }

    Ok(())
}

// Determine smartcard to which to connect based on optional target string
fn open_card(target: Option<String>) -> Result<Card<Open>> {
    let card = match target {
        Some(ref serial) => {
            // Find card by ident by briefly connecting to each
            let backends: Vec<PcscBackend> =
                PcscBackend::cards(None)?.filter_map(Result::ok).collect();
            let mut found = None;
            for backend in backends {
                let mut c = Card::new(backend)?;
                let ident = {
                    let tx = c.transaction()?;
                    tx.application_identifier()?.ident()
                };
                if ident.eq_ignore_ascii_case(serial) {
                    found = Some(c);
                    break;
                }
            }
            found.ok_or_else(|| CardError::NotFound(format!("Card '{}' not found", serial)))?
        }
        None => {
            let backends: Vec<PcscBackend> =
                PcscBackend::cards(None)?.filter_map(Result::ok).collect();

            match backends.len() {
                0 => bail!("No card detected, please insert card"),
                1 => Card::new(backends.into_iter().next().unwrap())?,
                n => bail!("Multiple cards ({}) detected, please specify card by serial", n),
            }
        }
    };

    Ok(card)
}

/// Config to create an ed25519/cv25519 user cert
pub struct SeededSmartcard {
    /// Seed used for primary key
    seed: Zeroizing<Seed256>,

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
        let (seed, subseed, shared_seed) = match scheme {
            Scheme::Legacy => (
                root.derive(Some(&[0x01])),
                root.derive(subkey.as_ref().map(|k| k.as_bytes())),
                root.derive(None),
            ),
            Scheme::Current => (root.key("primary"), root.sub(subkey.as_deref()), root.sub(None)),
        };

        SeededSmartcard {
            seed,
            subseed,
            shared_seed,
            shared: vec![],
            scheme,
            subkey: subkey.as_ref().map(|id| id.to_string()),
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

    /// Label a subkey is derived under
    ///
    /// The legacy labels are the OpenPGP key flag values themselves, which ties the derivation
    /// to how those flags happen to be bundled -- 0x0C is transport(0x04)|storage(0x08), so
    /// splitting them later would silently move the key.
    fn label_for(&self, role: SubkeyRole) -> Vec<u8> {
        match self.scheme {
            Scheme::Legacy => role.code().to_le_bytes().to_vec(),
            Scheme::Current => seed::label(seed::PREFIX_KEY, role.name()),
        }
    }

    /// Admin pin for this card
    fn admin_pin(&self) -> Zeroizing<String> {
        match self.scheme {
            Scheme::Legacy => self.subseed.base64(Some(b"admin")),
            Scheme::Current => self.subseed.pin("admin"),
        }
    }

    /// Seed a subkey is derived from, which is the shared one only when asked for
    fn seed_for(&self, role: SubkeyRole) -> &Seed256 {
        if self.shared.contains(&role) {
            &self.shared_seed
        } else {
            &self.subseed
        }
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

    // PUBLIC OUTPUT API

    /// Check smartcard access and subkeys
    pub fn check(&self, target: Option<String>) -> Result<()> {
        // Fingerprints first: comparing them costs no pin retries, so a wrong seed, subkey id
        // or scheme fails here without consuming one of the card's three admin attempts --
        // three mistaken checks would otherwise lock the admin pin.
        //
        // The primary has to be *signed*: `check_subkeys` evaluates the certificate under the
        // standard policy, and a bare primary key packet carries no binding signature at all,
        // so an unsigned one fails with "No binding signature" before any card is consulted.
        // The direct key signature does not affect the subkey fingerprints being compared.
        let mut cert = self.generate_signed_primary()?;
        cert = self.append_subkeys(cert)?;
        self.check_subkeys(&cert, target.clone())?;

        // Only now check that the card is managed by the derived admin pin
        self.check_admin_pin(target.clone())?;

        // And that the supplied user pin, if any, actually opens the card
        if self.pin.is_some() {
            self.check_user_pin(target)?;
        }

        Ok(())
    }

    /// Certify primary key, uids and/or subkeys
    pub fn certify(&self, kind: CertificateKind) -> Result<Cert> {
        use CertificateKind::*;

        let mut cert = if kind == Primary || kind == Full {
            self.generate_signed_primary()?
        } else {
            self.generate_primary()?
        };

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

        // Match signature type to user input
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

    /// Upload secret subkeys
    pub fn upload(&self, target: Option<String>) -> Result<Cert> {
        let mut cert = self.generate_primary()?;

        cert = self.append_uids(cert)?;
        cert = self.append_subkeys(cert)?;

        self.upload_subkeys(&cert, target)?;

        Ok(cert)
    }

    /// Export all secret keys
    pub fn export(&self) -> Result<Cert> {
        let mut cert = self.generate_primary()?;

        cert = self.append_uids(cert)?;
        self.append_subkeys(cert)
    }

    /// Generate and sign revoaction certificate
    /// Generate a revocation, ready to be armored
    ///
    /// A certificate revocation is a bare packet, which is the artifact gnupg expects and can
    /// be kept apart from the key it retires. A subkey revocation is delivered as the whole
    /// certificate instead: a lone subkey revocation signature has nothing to attach to, so
    /// what a recipient actually needs to import is the certificate carrying it.
    pub fn revoke(&self, kind: RevocationKind, code: u8, text: &str) -> Result<Vec<u8>> {
        match kind {
            RevocationKind::Certificate => {
                let mut cert = self.generate_primary()?;
                let revocation = self.generate_revcert(&mut cert, code, text)?;

                Ok(revocation.to_vec()?)
            }
            RevocationKind::Subkeys => {
                let cert = self.certify(CertificateKind::Full)?;
                let revocations = self.generate_subkey_revcerts(&cert, code, text)?;

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

    // INTERNAL API

    /// Helper to determine creation time
    fn creation_time(&self) -> SystemTime {
        self.creation_time
            .unwrap_or(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
    }

    /// Helper to create primary key-based signature builder including metadata.
    fn new_primary_sbuilder(&self, stype: SignatureType) -> PGPResult<SignatureBuilder> {
        SignatureBuilder::new(stype)
            .set_features(Features::sequoia())?
            .set_hash_algo(HashAlgorithm::SHA512)
            .set_key_validity_period(None)?
            .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256])?
            .set_preferred_symmetric_algorithms(vec![
                SymmetricAlgorithm::AES256,
                SymmetricAlgorithm::AES128,
            ])?
            .set_signature_creation_time(self.creation_time())
    }

    /// Helper to create primary key-based signer
    fn new_primary_signer(&self) -> PGPResult<KeyPair> {
        // Generate primary key.
        let primary: SecretPrimaryKey =
            Key4::import_secret_ed25519(&*self.seed, self.creation_time())?.into();

        let signer = primary
            .clone()
            .into_keypair()
            .expect("key generated above has a secret");

        Ok(signer)
    }

    /// Generate a primary certificate
    fn generate_primary(&self) -> PGPResult<Cert> {
        // Generate and self-sign primary key.
        let primary: SecretPrimaryKey =
            Key4::import_secret_ed25519(&*self.seed, self.creation_time())?.into();

        // Optionally encrypt the primary key copy for the certificate
        let mut primary_enc = primary.clone();
        if let Some(pin) = self.pin.as_ref() {
            primary_enc
                .secret_mut()
                .encrypt_in_place(primary.parts_as_public(), pin)?;
        }

        let cert = Cert::try_from(vec![Packet::SecretKey(primary_enc)])?;

        Ok(cert)
    }

    /// Generate a self-signed primary certificate
    fn generate_signed_primary(&self) -> PGPResult<Cert> {
        // Generate and self-sign primary key.
        let primary: SecretPrimaryKey =
            Key4::import_secret_ed25519(&*self.seed, self.creation_time())?.into();

        let mut signer = primary
            .clone()
            .into_keypair()
            .expect("key generated above has a secret");

        let sig = self.new_primary_sbuilder(SignatureType::DirectKey)?;
        let sig = sig.sign_direct_key(&mut signer, primary.parts_as_public())?;

        // Optionally encrypt the primary key copy for the certificate
        let mut primary_enc = primary.clone();
        if let Some(pin) = self.pin.as_ref() {
            primary_enc
                .secret_mut()
                .encrypt_in_place(primary.parts_as_public(), pin)?;
        }

        let cert = Cert::try_from(vec![Packet::SecretKey(primary_enc), sig.into()])?;

        Ok(cert)
    }

    /// Append self-signed user ids to a primary certificate
    fn append_uids(&self, mut cert: Cert) -> PGPResult<Cert> {
        // Generate, self-sign and append all subkeys.
        let mut signer = self.new_primary_signer()?;

        for (i, uid) in self.userids.iter().enumerate() {
            let mut sig = self.new_primary_sbuilder(SignatureType::PositiveCertification)?;

            if i == 0 {
                sig = sig.set_primary_userid(true)?;
            }

            let signature = uid.bind(&mut signer, &cert, sig)?;
            cert = cert
                .insert_packets(vec![Packet::from(uid.clone()), signature.into()])
                .map(|(c, _)| c)?;
        }

        Ok(cert)
    }

    /// Append self-signed subkeys to a primary certificate
    fn append_subkeys(&self, mut cert: Cert) -> PGPResult<Cert> {
        // Generate primary key and signer
        let primary: SecretPrimaryKey =
            Key4::import_secret_ed25519(&*self.seed, self.creation_time())?.into();

        let mut signer = primary
            .clone()
            .into_keypair()
            .expect("key generated above has a secret");

        // Create and sign subkeys
        let subkey_creation_time = self.subkey_creation_time.unwrap_or(self.creation_time());

        for role in SubkeyRole::ALL {
            let flags = role.flags();

            // Derive subkey specific seed and turn into key
            let mut seed = self.seed_for(role).derive(Some(&self.label_for(role)));

            let mut subkey: SecretSubKey =
                if flags.for_transport_encryption() || flags.for_storage_encryption() {
                    // Curve25519 Paper, Sec. 3:
                    // A user can, for example, generate 32 uniform random bytes, clear bits 0, 1, 2 of the first
                    // byte, clear bit 7 of the last byte, and set bit 6 of the last byte.
                    seed[0] &= 0b1111_1000;
                    seed[31] &= !0b1000_0000;
                    seed[31] |= 0b0100_0000;

                    Key4::import_secret_cv25519(&*seed, None, None, subkey_creation_time)?.into()
                } else {
                    Key4::import_secret_ed25519(&*seed, subkey_creation_time)?.into()
                };

            // Sign subkey with primary
            let mut builder = SignatureBuilder::new(SignatureType::SubkeyBinding)
                .set_hash_algo(HashAlgorithm::SHA512)
                .set_signature_creation_time(subkey_creation_time)?
                .set_key_flags(flags.clone())?
                .set_key_validity_period(self.subkey_validity)?;

            // Record which card this subkey belongs to. Not applied under the legacy scheme,
            // which has to keep producing exactly the certificates it always did.
            if self.scheme == Scheme::Current
                && let Some(id) = &self.subkey
            {
                builder = builder.add_notation(
                    NOTATION_SUBKEY,
                    seed::stamp(id).as_bytes(),
                    NotationDataFlags::empty().set_human_readable(),
                    false,
                )?;
            }

            if flags.for_certification() || flags.for_signing() {
                // We need to create a primary key binding signature.
                let mut subkey_signer = subkey.clone().into_keypair()?;
                let backsig = SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
                    .set_signature_creation_time(subkey_creation_time)?
                    .set_hash_algo(HashAlgorithm::SHA512)
                    .sign_primary_key_binding(&mut subkey_signer, &primary, &subkey)?;

                builder = builder.set_embedded_signature(backsig)?;
            }

            let signature = subkey.bind(&mut signer, &cert, builder)?;

            // Apply password protection (use a clone for the key reference to avoid borrow conflict)
            if let Some(pin) = self.pin.as_ref() {
                let subkey_pub = subkey.clone();
                subkey
                    .secret_mut()
                    .encrypt_in_place(subkey_pub.parts_as_public(), pin)?;
            }

            // Add everything to certificate
            cert = cert
                .insert_packets(vec![Packet::SecretSubkey(subkey), signature.into()])
                .map(|(c, _)| c)?;
        }

        Ok(cert)
    }

    /// Sign uids in external certificate with our primary key
    fn sign_uids(&self, mut cert: Cert, other: Cert, kind: SignatureType) -> PGPResult<Cert> {
        // Generate and self-sign primary key.
        let mut signer = self.new_primary_signer()?;

        let policy = &StandardPolicy::new();
        let valid_other = other.with_policy(policy, None)?;

        for uid in valid_other.userids() {
            log::info!("Signing userid '{}'", uid.userid());

            // Use a minimal builder without subpackets
            let sig = SignatureBuilder::new(kind)
                .set_hash_algo(HashAlgorithm::SHA512)
                .set_signature_creation_time(self.creation_time())?;

            let signature = uid.userid().bind(&mut signer, &cert, sig)?;

            // Insert each signed UserID with its signature to associate them
            cert = cert
                .insert_packets(vec![Packet::from(uid.userid().clone()), signature.into()])
                .map(|(c, _)| c)?;
        }

        Ok(cert)
    }

    /// Check that smartcard can be accessed with derived admin pin
    pub fn check_admin_pin(&self, target: Option<String>) -> Result<()> {
        // Determine smartcard to which to connect
        let mut card = open_card(target)?;

        // Establish connection and receive metadata
        let mut transaction = card.transaction()?;
        log::info!("Connected to smartcard '{}'", transaction.application_identifier()?.ident());

        // Verify admin pin derived from subseed
        let admin_pin = self.admin_pin();
        transaction.verify_admin_pin(SecretString::new(admin_pin.as_str().to_owned()))?;

        Ok(())
    }

    /// Check that the supplied user pin opens the smartcard
    pub fn check_user_pin(&self, target: Option<String>) -> Result<()> {
        let pin = match self.pin.as_ref() {
            Some(pin) => pin,
            None => return Ok(()),
        };

        // Determine smartcard to which to connect
        let mut card = open_card(target)?;
        let mut transaction = card.transaction()?;

        // A valid UTF-8 pin borrows through `from_utf8_lossy`, and the `String` moves into
        // `SecretString`, which zeroizes it -- no unwiped copy is left behind
        let pin_str = pin.map(|p| String::from_utf8_lossy(p).to_string());
        transaction.verify_user_pin(SecretString::new(pin_str))?;

        log::info!("User pin verified");

        Ok(())
    }

    /// Check that subkey fingerprints of certificate matches those on smartcard
    pub fn check_subkeys(&self, cert: &Cert, target: Option<String>) -> Result<()> {
        // Determine smartcard to which to connect
        let mut card = open_card(target)?;

        // Establish connection and receive metadata
        let mut transaction = card.transaction()?;
        log::info!("Connected to smartcard '{}'", transaction.application_identifier()?.ident());

        // Get the certificate subkeys
        let policy = &StandardPolicy::new();
        let valid_cert = cert.with_policy(policy, None)?;

        // Collected rather than raised, so that one bad subkey does not hide the others. A
        // card provisioned from the wrong seed disagrees in all three.
        let mut mismatches: Vec<String> = Vec::new();

        // For each of the expected subkeys...
        for role in SubkeyRole::ALL {
            let kt = role.key_type();

            // ... get fingerprint of matching subkey in cert ...
            let subkey = valid_cert
                .keys()
                .subkeys()
                .find(|k| k.key_flags().is_some_and(|flags| role.matches(&flags)))
                .ok_or_else(|| anyhow::anyhow!("{:?} key not found in cert", kt))?;

            let cert_fp_bytes: [u8; 20] = subkey
                .key()
                .fingerprint()
                .as_bytes()
                .try_into()
                .map_err(|_| anyhow::anyhow!("Unexpected fingerprint length"))?;

            // ... and try to compare it to the fingerprint on the smartcard
            match transaction.fingerprint(kt) {
                Ok(Some(card_fp)) if card_fp.as_bytes() == cert_fp_bytes => {
                    log::info!("Fingerprint match for {:?} key: {}", kt, card_fp.to_spaced_hex())
                }
                Ok(Some(card_fp)) => mismatches.push(format!(
                    "Fingerprint mismatch for {:?} key: certificate={}, card={}",
                    kt,
                    hex::encode_pretty(cert_fp_bytes),
                    card_fp.to_spaced_hex()
                )),
                Ok(None) => mismatches.push(format!("No {kt:?} key found on card")),
                Err(err) => mismatches.push(format!("Could not read {kt:?} fingerprint: {err}")),
            }
        }

        crate::common::report_mismatches("certificate", mismatches)
    }

    /// Upload subkeys to a smartcard and reset and lock smartcard in the process
    fn upload_subkeys(&self, cert: &Cert, target: Option<String>) -> PGPResult<()> {
        // Determine smartcard to which to connect
        let mut card = open_card(target)?;

        // Establish connection and receive metadata
        let mut transaction = card.transaction()?;
        log::info!("Connected to smartcard '{}'", transaction.application_identifier()?.ident());

        // Factory reset smartcard
        transaction.factory_reset()?;

        // Change user pin if it was specified
        if let Some(pin) = self.pin.as_ref() {
            let new_pin: Zeroizing<String> =
                pin.map(|p| String::from_utf8_lossy(p).to_string()).into();
            transaction.change_user_pin(
                SecretString::new("123456".to_string()),
                SecretString::new(AsRef::<str>::as_ref(&*new_pin).to_owned()),
            )?;
        } else {
            // The factory reset above restored it, so say so out loud: a provisioned card
            // that still answers to 123456 is not something to discover later
            log::warn!("No user pin supplied, the card keeps the default pin 123456");
        }

        // Set new admin pin derived from subseed
        let admin_pin = self.admin_pin();
        transaction.change_admin_pin(
            SecretString::new("12345678".to_string()),
            SecretString::new(admin_pin.as_str().to_owned()),
        )?;

        // Authenticate as admin (combines verify + elevation in one step)
        let mut admin =
            transaction.to_admin_card(SecretString::new(admin_pin.as_str().to_owned()))?;

        admin.set_cardholder_name(&self.name)?;
        admin.set_lang(&[['e', 'n'].into()])?;

        let p = &StandardPolicy::new();
        let vc = cert.with_policy(p, None)?;

        for role in SubkeyRole::ALL {
            let kt = role.key_type();

            // Find the matching subkey in the cert to get fingerprint, timestamp, and public bytes
            let subkey = vc
                .keys()
                .subkeys()
                .find(|k| k.key_flags().is_some_and(|flags| role.matches(&flags)))
                .ok_or_else(|| anyhow::anyhow!("{:?} key not found in cert", kt))?;

            // Extract fingerprint as 20-byte array
            let fp_bytes: [u8; 20] = subkey
                .key()
                .fingerprint()
                .as_bytes()
                .try_into()
                .map_err(|_| anyhow::anyhow!("Unexpected fingerprint length"))?;

            // Extract creation timestamp
            let ts = subkey
                .key()
                .creation_time()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|e| anyhow::anyhow!("Key creation time error: {}", e))?
                .as_secs() as u32;

            // Extract public key bytes from cert MPI (0x40-prefixed for 25519 keys)
            let pub_bytes = match subkey.key().mpis() {
                mpi::PublicKey::EdDSA { q, .. } => q.value().to_vec(),
                mpi::PublicKey::ECDH { q, .. } => q.value().to_vec(),
                _ => bail!("{:?} key has unexpected algorithm in cert", kt),
            };

            // Re-derive the raw private seed bytes
            let mut seed = self.seed_for(role).derive(Some(&self.label_for(role)));

            // Apply Cv25519 clamping for decryption key
            if role.is_encryption() {
                seed[0] &= 0b1111_1000;
                seed[31] &= !0b1000_0000;
                seed[31] |= 0b0100_0000;
            }

            let (oid, ecc_type) = if role.is_encryption() {
                (Curve::Curve25519.oid(), EccType::ECDH)
            } else {
                (Curve::Ed25519.oid(), EccType::EdDSA)
            };

            let key = RawEccKey {
                oid,
                private_bytes: Zeroizing::new(seed.to_vec()),
                public_bytes: pub_bytes,
                ecc_type,
                fingerprint: CardFingerprint::from(fp_bytes),
                timestamp: KeyGenerationTime::from(ts),
            };

            log::info!("Uploading {:?} key", kt);
            admin.import_key(Box::new(key), kt)?;

            // Set touch policy (Cached: one touch valid for ~15s)
            admin.set_touch_policy(kt, TouchPolicy::Cached)?;
        }

        Ok(())
    }

    /// Generate revocation certificate
    fn generate_revcert(&self, cert: &mut Cert, code: u8, text: &str) -> PGPResult<Packet> {
        let creation_time = self.creation_time();

        // Derive signing key
        let primary: SecretPrimaryKey =
            Key4::import_secret_ed25519(&*self.seed, creation_time)?.into();

        let mut signer = primary
            .clone()
            .into_keypair()
            .expect("key generated above has a secret");

        // Sign revocation certificate
        let revocation: Packet = CertRevocationBuilder::new()
            .set_signature_creation_time(creation_time)?
            .set_reason_for_revocation(reason(code), text.as_bytes())?
            .build(&mut signer, cert, None)?
            .into();

        Ok(revocation)
    }

    /// Revoke every subkey of this card, leaving the primary and other cards untouched
    fn generate_subkey_revcerts(
        &self,
        cert: &Cert,
        code: u8,
        text: &str,
    ) -> PGPResult<Vec<Packet>> {
        let creation_time = self.creation_time();

        // A subkey is revoked by its *primary*, which is what makes this possible at all: the
        // primary is re-derivable from the seed, so a card can be retired without it present
        let primary: SecretPrimaryKey =
            Key4::import_secret_ed25519(&*self.seed, creation_time)?.into();
        let mut signer = primary
            .clone()
            .into_keypair()
            .expect("key generated above has a secret");

        let policy = StandardPolicy::new();
        let valid = cert.with_policy(&policy, None)?;

        valid
            .keys()
            .subkeys()
            .filter(|subkey| {
                // A subkey derived without the subkey id is byte-identical on every card,
                // so revoking it here would retire it fleet-wide -- exactly what
                // `--kind subkeys` promises not to do. Leave shared subkeys standing.
                let Some(flags) = subkey.key_flags() else {
                    return true;
                };
                let shared = self.shared.iter().any(|role| role.matches(&flags));
                if shared {
                    log::warn!(
                        "Leaving shared subkey {} in service: it is not this card's alone",
                        subkey.key().fingerprint()
                    );
                }
                !shared
            })
            .map(|subkey| {
                Ok(SubkeyRevocationBuilder::new()
                    .set_signature_creation_time(creation_time)?
                    .set_reason_for_revocation(reason(code), text.as_bytes())?
                    .build(&mut signer, cert, subkey.key(), None)?
                    .into())
            })
            .collect()
    }
}

/// Raw ECC key material for uploading to an OpenPGP card.
/// Implements both `CardUploadableKey` and `EccKey`.
struct RawEccKey {
    oid: &'static [u8],
    private_bytes: Zeroizing<Vec<u8>>,
    public_bytes: Vec<u8>,
    ecc_type: EccType,
    fingerprint: CardFingerprint,
    timestamp: KeyGenerationTime,
}

impl CardUploadableKey for RawEccKey {
    fn private_key(&self) -> std::result::Result<PrivateKeyMaterial, openpgp_card::Error> {
        // Box self as an EccKey implementor — clone fields into a new heap-allocated instance
        Ok(PrivateKeyMaterial::E(Box::new(RawEccKeyRef {
            oid: self.oid,
            private_bytes: self.private_bytes.clone(),
            public_bytes: self.public_bytes.clone(),
            ecc_type: self.ecc_type,
        })))
    }

    fn timestamp(&self) -> KeyGenerationTime {
        self.timestamp
    }

    fn fingerprint(&self) -> std::result::Result<CardFingerprint, openpgp_card::Error> {
        Ok(self.fingerprint.clone())
    }
}

/// Inner ECC key reference, separated from `RawEccKey` to satisfy `Box<dyn EccKey>`.
struct RawEccKeyRef {
    oid: &'static [u8],
    private_bytes: Zeroizing<Vec<u8>>,
    public_bytes: Vec<u8>,
    ecc_type: EccType,
}

impl EccKey for RawEccKeyRef {
    fn oid(&self) -> &[u8] {
        self.oid
    }

    fn private(&self) -> Vec<u8> {
        self.private_bytes.to_vec()
    }

    fn public(&self) -> Vec<u8> {
        self.public_bytes.clone()
    }

    fn ecc_type(&self) -> EccType {
        self.ecc_type
    }
}
