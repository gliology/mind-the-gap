//! The PIV backend: a P-256 X.509 chain from seeds, and uploads to YubiKeys.
//!
//! [`SeededSmartcard`] derives a root certificate authority, an optional issuing authority
//! and the four slot keys (9A, 9C, 9D, 9E), issues the chain with RFC 6979 deterministic
//! ECDSA so re-runs are byte-identical, and writes keys, certificates, identifiers and
//! per-slot policies to the card through the `yubikey` crate. The chain layout and its
//! constraints are documented in the certificates chapter,
//! <https://gliology.github.io/mind-the-gap/piv-certificates.html>.

use std::str::FromStr;
use std::time::{Duration, SystemTime};

use crate::seed::{self, Seed256, Seed256Derive};

use anyhow::{Result, anyhow, bail};

use yubikey::certificate::CertInfo;
use yubikey::piv::{self, AlgorithmId, RetiredSlotId, SlotId};
use yubikey::reader::Context;
use yubikey::{
    CardId, CccId, Certificate as CardCertificate, ChuId, Error as CardError, MgmAlgorithmId,
    MgmKey, MsRoots, PinPolicy, Serial, TouchPolicy, YubiKey,
};

use cms::content_info::ContentInfo;

use p256::ecdsa::{DerSignature, SigningKey};

use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::der::oid::db::rfc5280::{ID_KP_CLIENT_AUTH, ID_KP_EMAIL_PROTECTION};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
    SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::ext::{Extension, ToExtension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};
use x509_cert::{Certificate as X509Certificate, PkiPath, TbsCertificate};

use der::asn1::Ia5String;
use der::flagset::FlagSet;
use der::{Encode, EncodePem};

use sha2::{Digest, Sha256};
use spki::{ObjectIdentifier, SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use zeroize::Zeroizing;

/// Configuration of key slots to be generated and uploaded.
///
/// Slot numbering follows NIST SP 800-73-4; note that `0x9b` is the management key slot and
/// therefore deliberately absent. PIN and touch policies are the per-slot defaults required
/// (9E) or recommended (the rest) by the same document -- see [`SeededSmartcard::policies_for`].
const DEFAULT_KEY_SLOTS: [(SlotId, SlotRole, PinPolicy, TouchPolicy); 4] = [
    // One PIN verification unlocks a series of authentication operations (SSH, TLS, logon).
    (SlotId::Authentication, SlotRole::Authentication, PinPolicy::Once, TouchPolicy::Cached),
    // Non-repudiable signing: PIN and touch immediately before every single signature.
    (SlotId::Signature, SlotRole::Signature, PinPolicy::Always, TouchPolicy::Always),
    (SlotId::KeyManagement, SlotRole::KeyManagement, PinPolicy::Once, TouchPolicy::Cached),
    // The card authentication key MUST be usable without cardholder verification.
    (
        SlotId::CardAuthentication,
        SlotRole::CardAuthentication,
        PinPolicy::Never,
        TouchPolicy::Never,
    ),
];

/// Dummy pin used to lock card
const DUMMY_PIN: [u8; 8] = [0xff; 8];

/// Derivation name for the root certificate authority key
const NAME_ROOT_CA: &str = "root-ca";

/// Derivation name for the intermediate issuing certificate authority key
const NAME_ISSUING_CA: &str = "issuing-ca";

/// Derivation name for the card management key in slot 9B
const NAME_MANAGEMENT: &str = "management";

/// Derivation name for the key management key, live in slot 9D and archived in a retired slot
const NAME_KEY_MANAGEMENT: &str = "key-management";

/// First retired key management slot, per SP 800-73; twenty follow, up to 0x95
const FIRST_RETIRED_SLOT: u8 = 0x82;

/// Derivation name for the card identifier printed in the slot 9E subject
const NAME_CARD_ID: &str = "card";

/// Derivation name for the CHUID Card UUID
const NAME_CHUID_ID: &str = "chuid";

/// Derivation name for the CCC card identifier
const NAME_CCC_ID: &str = "ccc";

/// Derivation name for a slot's key, by the *role* it plays rather than where it sits
///
/// Positional names (`slot-9d`) would tie a key to one slot, but the retired slots hold
/// superseded key management keys: the same key has to derive identically whether it lives in
/// 9D or in 0x82, or an archived generation could never be re-derived.
fn slot_name(slot: SlotId) -> &'static str {
    match slot {
        SlotId::Authentication => "authentication",
        SlotId::Signature => "signature",
        SlotId::KeyManagement => NAME_KEY_MANAGEMENT,
        SlotId::CardAuthentication => "card-authentication",
        other => unreachable!("{other:?} is not one of DEFAULT_KEY_SLOTS"),
    }
}

/// FIPS 201 CHUID, with a zeroed Card UUID.
///
/// Replicated from `yubikey`'s private `CHUID_TMPL`, because `ChuId::set` overwrites the
/// template with all 59 bytes it is handed -- there is no way to supply only the GUID. Every
/// field but the UUID is fixed: a non-federal FASC-N, the hard-coded 2030-01-01 expiry, and
/// empty signature and error-detection blocks.
const CHUID_TEMPLATE: [u8; ChuId::BYTE_SIZE] = [
    0x30, 0x19, 0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73, 0x9d, 0x83, 0x68, 0x58,
    0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0xc8, 0x42, 0x10, 0xc3, 0xeb, 0x34, 0x10, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35, 0x08, 0x32,
    0x30, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x3e, 0x00, 0xfe, 0x00,
];

/// Offset of the 16-byte Card UUID within [`CHUID_TEMPLATE`]
const CHUID_GUID_OFFSET: usize = 29;

/// GSC-IS Cardholder Capability Container, with a zeroed card identifier.
///
/// Replicated from `yubikey`'s private `CCC_TMPL` for the same reason as [`CHUID_TEMPLATE`].
const CCC_TEMPLATE: [u8; CccId::BYTE_SIZE] = [
    0xf0, 0x15, 0xa0, 0x00, 0x00, 0x01, 0x16, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1, 0x01, 0x21, 0xf2, 0x01, 0x21, 0xf3, 0x00, 0xf4,
    0x01, 0x00, 0xf5, 0x01, 0x10, 0xf6, 0x00, 0xf7, 0x00, 0xfa, 0x00, 0xfb, 0x00, 0xfc, 0x00, 0xfd,
    0x00, 0xfe, 0x00,
];

/// Offset of the 14-byte card identifier within [`CCC_TEMPLATE`]
const CCC_ID_OFFSET: usize = 9;

/// Maximum number of re-derivations while searching for a valid P-256 scalar.
///
/// A rejection happens with probability of roughly 2^-32 per draw, so in practice the first
/// candidate is always accepted; the bound merely keeps the function total.
const MAX_SCALAR_TRIES: usize = 8;

/// `id-PIV-cardAuth` -- NIST SP 800-73-4 Part 1, Appendix B.
///
/// FIPS 201-3 section 4.2.3 requires this extended key usage on the slot 9E certificate.
const ID_PIV_CARD_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.6.8");

/// Microsoft Smartcard Logon, required by Windows/Active Directory smartcard logon
const ID_MS_SMARTCARD_LOGON: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.20.2.2");

/// Print list of currently available PIV cards
pub fn status() -> Result<()> {
    println!("Available PIV cards:");

    let mut context = Context::open()?;
    let cards: Vec<_> = context.iter()?.collect();

    if cards.is_empty() {
        println!(" - None");
        println!();
    }

    for reader in cards {
        println!(" - Reader '{}'", reader.name());

        // A reader that is busy or holds a non-PIV card must not abort the whole listing:
        // status is a read-only overview and is expected to report what it can.
        let mut token = match reader.open() {
            Ok(token) => token,
            Err(err) => {
                println!("   Unavailable: {err}");
                println!();
                continue;
            }
        };
        println!("   Serial: {}", token.serial());

        match token.piv_keys() {
            Ok(keys) => {
                for key in keys {
                    // Skip the pin/puk/management key references. They hold no certificate of
                    // their own, but `yubikey`'s slot table maps `ManagementSlotId::Pin` onto
                    // object 0x5fc10b -- which *is* the key management certificate -- so every
                    // card otherwise reports that same certificate a second time under a
                    // nonexistent "Pin" slot.
                    if matches!(key.slot(), SlotId::Management(_)) {
                        continue;
                    }

                    let cert = key.certificate();

                    // Fingerprint is SHA256 hash of certificate
                    match cert.cert.to_der() {
                        Ok(der) => println!(
                            "   {} key: {:x} ({})",
                            key.slot(),
                            Sha256::digest(der),
                            cert.subject()
                        ),
                        Err(err) => {
                            println!("   {} key: unreadable certificate: {err}", key.slot())
                        }
                    }
                }
            }
            Err(err) => println!("   No PIV keys: {err}"),
        }

        println!();
    }

    Ok(())
}

/// Connect to a PIV token, optionally selected by serial number.
///
/// Mirrors [`crate::pgp`]'s `open_card`: bare `YubiKey::open()` silently picks the first
/// reader, which is the wrong behaviour when several cards are attached.
fn open_token(target: Option<String>) -> Result<YubiKey> {
    if let Some(serial) = target {
        let token = YubiKey::open_by_serial(Serial::from_str(&serial)?)?;
        log::info!("Connected to reader '{}'", token.name());
        return Ok(token);
    }

    let mut context = Context::open()?;
    let readers: Vec<_> = context.iter()?.collect();

    match readers.len() {
        0 => bail!("No card detected, please insert card"),
        1 => {
            let token = readers[0].open()?;
            log::info!("Connected to reader '{}'", token.name());
            Ok(token)
        }
        n => bail!("Multiple cards ({n}) detected, please specify card by serial"),
    }
}

/// Which part of the certificate chain to export
#[derive(clap::ValueEnum, Clone, Debug, Default, PartialEq)]
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

/// Command line mirror of [`yubikey::PinPolicy`], which is a foreign type
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq)]
pub enum PinPolicyArg {
    /// Leave the card's own default in place
    Default,
    /// Never require the user pin
    Never,
    /// Require the user pin once per session
    Once,
    /// Require the user pin before every operation
    Always,
}

impl From<PinPolicyArg> for PinPolicy {
    fn from(arg: PinPolicyArg) -> Self {
        match arg {
            PinPolicyArg::Default => PinPolicy::Default,
            PinPolicyArg::Never => PinPolicy::Never,
            PinPolicyArg::Once => PinPolicy::Once,
            PinPolicyArg::Always => PinPolicy::Always,
        }
    }
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

/// Command line mirror of [`yubikey::TouchPolicy`], which is a foreign type
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq)]
pub enum TouchPolicyArg {
    /// Leave the card's own default in place
    Default,
    /// Never require a touch
    Never,
    /// Require a touch before every operation
    Always,
    /// Require a touch, then cache it for roughly fifteen seconds
    Cached,
}

impl From<TouchPolicyArg> for TouchPolicy {
    fn from(arg: TouchPolicyArg) -> Self {
        match arg {
            TouchPolicyArg::Default => TouchPolicy::Default,
            TouchPolicyArg::Never => TouchPolicy::Never,
            TouchPolicyArg::Always => TouchPolicy::Always,
            TouchPolicyArg::Cached => TouchPolicy::Cached,
        }
    }
}

/// Role a certificate plays, mapped one-to-one onto a NIST PIV key slot
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotRole {
    /// Slot 9A: client authentication, SSH and smartcard logon
    Authentication,
    /// Slot 9C: non-repudiable document and email signing
    Signature,
    /// Slot 9D: ECDH key agreement for email encryption
    KeyManagement,
    /// Slot 9E: PIN-less card-to-reader authentication
    CardAuthentication,
}

impl SlotRole {
    /// Key usage bits appropriate for this role
    fn key_usage(&self) -> FlagSet<KeyUsages> {
        match self {
            SlotRole::Authentication => KeyUsages::DigitalSignature.into(),
            SlotRole::Signature => KeyUsages::DigitalSignature | KeyUsages::NonRepudiation,
            // These are ECDH keys. `keyEncipherment` describes RSA key transport and is
            // invalid for EC keys (RFC 5480 section 3, RFC 8813); NSS rejects such a
            // certificate for S/MIME decryption. `encipherOnly`/`decipherOnly` are left
            // unset as either would break `openssl verify -purpose smimeencrypt`.
            SlotRole::KeyManagement => KeyUsages::KeyAgreement.into(),
            SlotRole::CardAuthentication => KeyUsages::DigitalSignature.into(),
        }
    }

    /// Extended key usages appropriate for this role
    fn extended_key_usage(&self) -> Vec<ObjectIdentifier> {
        match self {
            SlotRole::Authentication => vec![ID_KP_CLIENT_AUTH, ID_MS_SMARTCARD_LOGON],
            SlotRole::Signature => vec![ID_KP_EMAIL_PROTECTION],
            SlotRole::KeyManagement => vec![ID_KP_EMAIL_PROTECTION, ID_KP_CLIENT_AUTH],
            SlotRole::CardAuthentication => vec![ID_PIV_CARD_AUTH],
        }
    }

    /// Whether certificates in this role carry the user's alternative names.
    ///
    /// Slot 9E authenticates the *card*, not the person, so it stays unbound (FIPS 201-3
    /// section 4.2.3).
    fn is_user_bound(&self) -> bool {
        *self != SlotRole::CardAuthentication
    }
}

/// Distinguished name attributes shared by every tier of the chain
#[derive(Clone, Debug, Default)]
pub struct Identity {
    /// Common name base, e.g. the cardholder's name
    pub name: String,
    /// Organization (`O`)
    pub org: Option<String>,
    /// Organizational unit (`OU`)
    pub org_unit: Option<String>,
    /// Two letter ISO country code (`C`)
    pub country: Option<String>,
}

/// Escape a distinguished name attribute value per RFC 4514 section 2.4.
///
/// Without this a cardholder name containing e.g. a comma silently parses into the wrong
/// relative distinguished name sequence.
fn escape_rdn(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());

    for (index, character) in value.char_indices() {
        let last = index + character.len_utf8() == value.len();
        match character {
            '"' | '+' | ',' | ';' | '<' | '>' | '\\' | '=' => {
                escaped.push('\\');
                escaped.push(character);
            }
            // A leading '#' or space, and a trailing space, are also special
            '#' if index == 0 => escaped.push_str("\\#"),
            ' ' if index == 0 || last => escaped.push_str("\\ "),
            '\0' => escaped.push_str("\\00"),
            _ => escaped.push(character),
        }
    }

    escaped
}

impl Identity {
    /// Build `CN=<cn>[,OU=..][,O=..][,C=..]`.
    ///
    /// `RdnSequence::from_str` reverses the sequence, so writing the attributes in RFC 4514
    /// order yields DER order C, O, OU, CN.
    fn dn(&self, common_name: &str) -> Result<Name> {
        self.qualified_dn(common_name, None)
    }

    /// Build the same DN with a `dnQualifier` distinguishing this card from its siblings.
    ///
    /// `dnQualifier` is the X.500 attribute for telling apart entries that share a name, which
    /// is exactly the situation one seed provisioning several cards creates: every card's
    /// person-bound certificates carry the same `CN`. Kept off the root authority, which is
    /// shared by every card and so has nothing to distinguish.
    fn qualified_dn(&self, common_name: &str, qualifier: Option<&str>) -> Result<Name> {
        let mut parts = vec![format!("CN={}", escape_rdn(common_name))];

        if let Some(qualifier) = qualifier {
            parts.push(format!("dnQualifier={}", escape_rdn(&seed::stamp(qualifier))));
        }

        if let Some(unit) = &self.org_unit {
            parts.push(format!("OU={}", escape_rdn(unit)));
        }
        if let Some(org) = &self.org {
            parts.push(format!("O={}", escape_rdn(org)));
        }
        if let Some(country) = &self.country {
            parts.push(format!("C={}", escape_rdn(country)));
        }

        Ok(Name::from_str(&parts.join(","))?)
    }

    /// Subject of the self-signed root certificate authority
    fn root_dn(&self) -> Result<Name> {
        self.dn(&format!("{} PIV Root CA", self.name))
    }

    /// Subject of the intermediate issuing certificate authority.
    ///
    /// The subkey id is appended so that separate generations stay distinguishable.
    fn issuing_dn(&self, subkey: Option<&str>) -> Result<Name> {
        Ok(match subkey {
            Some(id) => self.dn(&format!("{} PIV Issuing CA {}", self.name, id))?,
            None => self.dn(&format!("{} PIV Issuing CA", self.name))?,
        })
    }

    /// Subject of the person-bound slot certificates (9A, 9C, 9D)
    fn user_dn(&self, subkey: Option<&str>) -> Result<Name> {
        self.qualified_dn(&self.name, subkey)
    }

    /// Subject of the card-bound slot certificate (9E)
    fn card_dn(&self, card_id: &str) -> Result<Name> {
        self.dn(&format!("PIV Card {card_id}"))
    }
}

/// A complete, deterministically derived PIV certificate chain
#[derive(Clone, Debug)]
pub struct CertChain {
    /// Self-signed trust anchor
    pub root: X509Certificate,
    /// Subkey-scoped issuing authority, present only with `--intermediate`
    pub intermediate: Option<X509Certificate>,
    /// End-entity certificates, one per configured key slot
    pub leaves: Vec<(SlotId, X509Certificate)>,
}

impl CertChain {
    /// The certificate authorities, root last, as consumed by the `msroots` object
    pub fn cas(&self) -> PkiPath {
        let mut path = Vec::with_capacity(2);
        if let Some(intermediate) = &self.intermediate {
            path.push(intermediate.clone());
        }
        path.push(self.root.clone());
        path
    }

    /// The certificate that directly issues the slot certificates
    pub fn issuer(&self) -> &X509Certificate {
        self.intermediate.as_ref().unwrap_or(&self.root)
    }

    /// Every certificate in the chain, leaves first and trust anchor last
    pub fn iter(&self) -> impl Iterator<Item = &X509Certificate> {
        self.leaves
            .iter()
            .map(|(_, cert)| cert)
            .chain(self.intermediate.iter())
            .chain(std::iter::once(&self.root))
    }

    /// Select the requested subset of the chain
    pub fn select(&self, kind: CertificateKind) -> Result<Vec<&X509Certificate>> {
        Ok(match kind {
            CertificateKind::Chain => self.iter().collect(),
            CertificateKind::Root => vec![&self.root],
            CertificateKind::Intermediate => vec![self.intermediate.as_ref().ok_or(anyhow!(
                "No intermediate certificate authority, pass --intermediate to generate one"
            ))?],
            CertificateKind::Leaves => self.leaves.iter().map(|(_, cert)| cert).collect(),
        })
    }

    /// Concatenated PEM encoding of the requested subset
    pub fn to_pem(&self, kind: CertificateKind) -> Result<String> {
        let mut out = String::new();
        for cert in self.select(kind)? {
            out.push_str(&cert.to_pem(der::pem::LineEnding::default())?);
        }
        Ok(out)
    }
}

/// Derive a *valid* P-256 secret scalar, re-deriving deterministically on rejection.
///
/// A uniform 256-bit string is only a valid NIST P-256 private key when it lies in
/// `[1, n-1]`; `SecretKey::from_bytes` performs exactly that range and zero check.
fn derive_p256_scalar(parent: &Seed256, path: Option<&[u8]>) -> Result<Zeroizing<Seed256>> {
    let mut candidate = parent.derive(path);

    for _ in 0..MAX_SCALAR_TRIES {
        // `into()` hands p256 a transient `FieldBytes` copy that is beyond our wiping
        if p256::SecretKey::from_bytes(&(*candidate).into()).is_ok() {
            return Ok(candidate);
        }

        log::warn!("Derived scalar outside the P-256 group order, re-deriving");
        candidate = candidate.key("p256-retry");
    }

    bail!("Failed to derive a valid P-256 scalar")
}

/// Derive a P-256 signing key from a seed
fn derive_p256_key(parent: &Seed256, path: Option<&[u8]>) -> Result<SigningKey> {
    let bytes = derive_p256_scalar(parent, path)?;
    SigningKey::from_bytes(&(*bytes).into()).map_err(|err| anyhow!("Invalid P-256 scalar: {err}"))
}

/// Serial number from the last 20 bytes of the subject public key fingerprint.
///
/// Known deviation from RFC 5280 4.1.2.2: the serial is a function of the *key* alone, so
/// re-running `certify` with a different `--date`, `--validity` or DN produces a different
/// certificate carrying the same (issuer, serial) pair, which relying-party caches and
/// revocation lists key on. Folding the rest of the TBS content into the hash would fix
/// that -- but it would change every issued certificate, and `check` compares byte for
/// byte, so within the frozen `mtg1` scheme this stays as it is; revisit for `mtg2`. In
/// practice one seed re-issues the same certificate deterministically, so colliding
/// serials only arise when the flags change between runs.
fn serial_for(pubkey: &SubjectPublicKeyInfoOwned) -> Result<SerialNumber> {
    let mut keyid = pubkey.fingerprint_bytes()?;
    keyid[12] &= 0x7f; // MSB has to be zero
    Ok(SerialNumber::new(&keyid[12..32])?)
}

/// Issue a certificate for `subject_pki`, signed by `issuer`
fn issue<P: BuilderProfile>(
    profile: P,
    validity: Validity,
    subject_pki: SubjectPublicKeyInfoOwned,
    issuer: &SigningKey,
) -> Result<X509Certificate> {
    let serial = serial_for(&subject_pki)?;
    let builder = CertificateBuilder::new(profile, serial, validity, subject_pki)?;

    // The explicit signature type is required: SigningKey implements Signer for more than
    // one signature representation. Deliberately `build`, not `build_with_rng`: ECDSA here
    // uses RFC 6979 deterministic nonces, which is what makes the output reproducible.
    Ok(builder.build::<_, DerSignature>(issuer)?)
}

/// Config to create a P-256 PIV certificate chain
pub struct SeededSmartcard {
    /// Seed used for the root certificate authority key
    primary: Zeroizing<Seed256>,

    /// Application seed every generation's subseed descends from
    ///
    /// Kept so that a *previous* generation can be re-derived for archival, which is the one
    /// place this card needs a subseed other than its own.
    root: Zeroizing<Seed256>,

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
    identity: Identity,

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

    /// Override for the derived card identifier used in the slot 9E subject
    card_id: Option<String>,

    /// Override for the per-slot pin policy, ignored for slot 9E
    pin_policy: Option<PinPolicy>,

    /// Override for the per-slot touch policy, ignored for slot 9E
    touch_policy: Option<TouchPolicy>,

    /// Whether to write the certificate authorities to the card's `msroots` object
    msroots: bool,
}

impl SeededSmartcard {
    /// Initialize a new seeded smartcard config
    pub fn new(seed: &Seed256, subkey: Option<String>, name: String) -> Self {
        // Derive application specific root seed
        let root = seed.app("piv");

        // Derive seed for the root authority and everything below the subkey id. The root
        // authority is a *sibling* of the subseed, not its parent: were it the parent (as it
        // used to be), anyone holding the authority key could re-derive every slot key.
        let primary = root.key(NAME_ROOT_CA);
        let subseed = root.sub(subkey.as_deref());

        // What the subseed would have been with no subkey id at all. Identical to `subseed`
        // when none was given, which is what makes `--shared` a no-op for a single card.
        let shared_seed = root.sub(None);

        SeededSmartcard {
            primary,
            root,
            subseed,
            shared_seed,
            retired: vec![],
            shared: vec![],
            subkey,
            identity: Identity { name, ..Default::default() },
            alternatives: vec![],
            creation_time: None,
            validity_duration: None,
            pin: None,
            intermediate: false,
            card_id: None,
            pin_policy: None,
            touch_policy: None,
            msroots: true,
        }
    }

    /// Set the pin to install on the card in place of the PIV default
    pub fn with_pin(mut self, pin: Zeroizing<String>) -> Self {
        self.pin = Some(pin.clone());
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

    /// Where a slot's key comes from: the seed it derives under and the label it uses
    ///
    /// A retired slot holds a *previous* generation's key management key, so it derives from
    /// that generation's subseed under the very same label the live 9D key uses. Deriving it
    /// by role rather than by slot is what lets an archived key be re-derived at all.
    fn key_source(&self, slot: SlotId) -> Result<(Zeroizing<Seed256>, Vec<u8>)> {
        if let SlotId::Retired(retired) = slot {
            let index = usize::from(u8::from(retired).saturating_sub(FIRST_RETIRED_SLOT));
            let generation = self
                .retired
                .get(index)
                .ok_or_else(|| anyhow!("No retired generation for {slot:?}"))?;

            return Ok((
                self.root.sub(Some(generation)),
                seed::label(seed::PREFIX_KEY, NAME_KEY_MANAGEMENT),
            ));
        }

        // A deliberate copy of the slot's parent seed, wiped when the caller is done with it
        Ok((Zeroizing::new(*self.seed_for(slot)), seed::label(seed::PREFIX_KEY, slot_name(slot))))
    }

    /// Slot each archived generation is written to, newest first from 0x82
    fn retired_slots(&self) -> Result<Vec<(SlotId, &str)>> {
        // An archived generation re-derives as that generation's *per-card* key management
        // key. Under --shared key-management there is no such key: the fleet-wide key is
        // derived without any subkey id and never rotates with it, so the archive would hold
        // a key no card ever carried -- and check could not catch it, because it compares
        // against the same wrong derivation.
        if !self.retired.is_empty() && self.shared.contains(&SharedSlot::KeyManagement) {
            bail!(
                "--retire archives per-card key management generations, which --shared \
                 key-management does not produce: the shared key never rotates with the \
                 subkey id, so there is no generation to archive. Drop one of the two flags."
            );
        }

        self.retired
            .iter()
            .enumerate()
            .map(|(index, generation)| {
                let offset = u8::try_from(index)
                    .ok()
                    .and_then(|i| FIRST_RETIRED_SLOT.checked_add(i));
                let slot = offset
                    .and_then(|byte| RetiredSlotId::try_from(byte).ok())
                    .ok_or_else(|| anyhow!("Only 20 generations fit in the retired slots"))?;

                Ok((SlotId::Retired(slot), generation.as_str()))
            })
            .collect()
    }

    /// Derive the named slots without the subkey id, so every card gets the same key
    pub fn with_shared(mut self, shared: Vec<SharedSlot>) -> Self {
        self.shared = shared;
        self
    }

    /// Seed a slot key is derived from, which is the shared one only when asked for
    fn seed_for(&self, slot: SlotId) -> &Seed256 {
        if self.shared.iter().any(|entry| SlotId::from(*entry) == slot) {
            &self.shared_seed
        } else {
            &self.subseed
        }
    }

    /// Override the derived card id recorded in the card authentication subject
    pub fn with_card_id(mut self, card_id: String) -> Self {
        self.card_id = Some(card_id);
        self
    }

    /// Override the per-slot pin policy
    pub fn with_pin_policy(mut self, policy: PinPolicy) -> Self {
        self.pin_policy = Some(policy);
        self
    }

    /// Override the per-slot touch policy
    pub fn with_touch_policy(mut self, policy: TouchPolicy) -> Self {
        self.touch_policy = Some(policy);
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

    // PUBLIC OUTPUT API

    /// Generate the full certificate chain, without touching a card
    pub fn certify(&self, kind: CertificateKind) -> Result<CertChain> {
        // `kind` only selects what is exported later, but validate it eagerly so that
        // `--kind intermediate` without `--intermediate` fails before doing the work.
        let chain = self.generate_chain()?;
        chain.select(kind)?;
        Ok(chain)
    }

    /// Check that an available PIV card matches the derived chain
    ///
    /// Every slot is inspected before anything is reported. A card provisioned from the wrong
    /// seed, or with the wrong `--date` / `--card-id` / DN flags, disagrees in *all* of them,
    /// and failing on the first would hide how far the divergence actually goes.
    pub fn check(&self, target: Option<String>) -> Result<()> {
        let chain = self.generate_chain()?;
        let mut token = open_token(target)?;

        // Card has to be under our management key. The prompt goes to stderr: stdout may be
        // carrying PEM or a report, and a buried prompt is a missed touch and a failed run.
        log::info!("Verifying smart card management key");
        eprintln!("[Please touch device to authenticate management access!]");
        token.authenticate(&self.management_key()?)?;
        eprintln!();

        // The supplied user pin, if any, has to open the card. A wrong pin consumes one of
        // the card's retries, but that is inherent to verifying it at all.
        if let Some(pin) = &self.pin {
            log::info!("Verifying smart card user pin");
            token.verify_pin(pin.as_bytes())?;
        }

        // Collected rather than raised, so one bad slot does not mask the others. Note that
        // `?` is still used for failures of *our* side -- a chain that will not encode is a
        // bug here, not a disagreement with the card.
        let mut mismatches: Vec<String> = Vec::new();

        for (slot, expected) in &chain.leaves {
            match piv::metadata(&mut token, *slot) {
                Err(err) => mismatches.push(format!("{slot:?} slot: metadata unreadable: {err}")),
                Ok(metadata) => {
                    // Key material has to match what we would derive
                    let want = expected
                        .tbs_certificate()
                        .subject_public_key_info()
                        .to_der()?;

                    match metadata.public.as_ref().map(|key| key.to_der()) {
                        None => mismatches.push(format!("{slot:?} slot: no key on card")),
                        Some(Err(err)) => mismatches
                            .push(format!("{slot:?} slot: on-card public key is malformed: {err}")),
                        Some(Ok(got)) if got != want => mismatches
                            .push(format!("{slot:?} slot: public key is not the derived one")),
                        Some(Ok(_)) => {}
                    }

                    // Policies are advisory: warn rather than fail, they can be tightened by
                    // hand, and `upload` itself lets them be overridden
                    if let Some(policy) = metadata.policy {
                        let expected_policy = self.policies_for(*slot);
                        if policy != expected_policy {
                            log::warn!(
                                "Policy mismatch in {:?} slot: card={:?}, expected={:?}",
                                slot,
                                policy,
                                expected_policy
                            );
                        }
                    }
                }
            }

            // Certificate has to be byte identical
            let want = Sha256::digest(expected.to_der()?);
            match CardCertificate::read(&mut token, *slot) {
                Err(err) => {
                    mismatches.push(format!("{slot:?} slot: certificate unreadable: {err}"))
                }
                Ok(card) => match card.cert.to_der() {
                    Err(err) => mismatches
                        .push(format!("{slot:?} slot: on-card certificate is malformed: {err}")),
                    Ok(der) => {
                        let got = Sha256::digest(der);
                        if got != want {
                            mismatches.push(format!(
                                "{slot:?} slot: certificate mismatch: card={got:x}, derived={want:x}"
                            ));
                        } else {
                            log::info!("{:?} slot matches: {:x}", slot, got);
                        }
                    }
                },
            }
        }

        // Advisory for the same reason `upload` only warns when it cannot write it: msroots is
        // Windows-specific, and a card that never received it is not thereby wrong
        if self.msroots {
            let expected = ContentInfo::try_from(chain.cas())?.to_der()?;
            match MsRoots::read(&mut token) {
                Ok(Some(roots)) if AsRef::<[u8]>::as_ref(&roots) == expected.as_slice() => {
                    log::info!("Certificate authorities in msroots match")
                }
                Ok(Some(_)) => log::warn!("Certificate authorities in msroots do not match"),
                Ok(None) => log::warn!("No certificate authorities stored in msroots"),
                Err(err) => log::warn!("Could not read msroots: {err}"),
            }
        }

        // Tidy up, but never at the cost of the report: a failure to drop the management key
        // session must not swallow the mismatches we came here to show
        if let Err(err) = token.deauthenticate() {
            log::warn!("Could not deauthenticate management key: {err}");
        }

        crate::common::report_mismatches("chain", mismatches)
    }

    /// Generate keys and certificates and upload them to a card
    pub fn upload(&self, target: Option<String>) -> Result<CertChain> {
        // Build the whole chain before touching the card, so that a derivation or encoding
        // failure never leaves a freshly reset card half provisioned.
        let chain = self.generate_chain()?;

        let mut token = open_token(target)?;

        self.reset_and_lock(&mut token)?;
        self.upload_card_identifiers(&mut token)?;
        self.upload_subcerts(&chain, &mut token)?;

        if self.msroots {
            // Windows-only, so a failure here must not abort an otherwise good provisioning
            if let Err(err) = self.upload_msroots(&chain, &mut token) {
                log::warn!("Failed to store certificate authorities in msroots: {err}");
            }
        }

        // Everything is on the card, so future management access can now demand a touch. Done
        // last on purpose: setting the flag needs no touch itself (we are still authenticated),
        // and leaving it until the end means a card is never wiped for a button that was not
        // pressed in time.
        log::info!("Requiring touch for future management access");
        self.management_key()?.set_manual(&mut token, true)?;

        token.deauthenticate()?;

        Ok(chain)
    }

    // HELPER FOR COMMON PROPERTIES

    /// Certificate creation time.
    ///
    /// Defaults to one second after the unix epoch so that `certify` stays byte
    /// reproducible without `--date`, mirroring the OpenPGP backend.
    fn creation_time(&self) -> SystemTime {
        self.creation_time
            .unwrap_or(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
    }

    /// Validity period of the leaf certificates
    fn validity(&self) -> Result<Validity> {
        let not_before = self.creation_time();
        let not_after = match self.validity_duration {
            Some(duration) => Time::try_from(not_before + duration)?,
            None => Time::INFINITY,
        };

        Ok(Validity::new(Time::try_from(not_before)?, not_after))
    }

    /// Validity period of the certificate authorities.
    ///
    /// Authorities never expire: they are re-derivable from the mnemonic, and an infinite
    /// notAfter guarantees a leaf can never outlive its issuer.
    fn ca_validity(&self) -> Result<Validity> {
        Ok(Validity::new(Time::try_from(self.creation_time())?, Time::INFINITY))
    }

    /// Effective pin and touch policy for a slot
    fn policies_for(&self, slot: SlotId) -> (PinPolicy, TouchPolicy) {
        // A retired slot holds a superseded key management key, so it keeps that slot's policy
        let slot = match slot {
            SlotId::Retired(_) => SlotId::KeyManagement,
            other => other,
        };

        let (_, _, pin, touch) = DEFAULT_KEY_SLOTS
            .iter()
            .find(|(candidate, ..)| *candidate == slot)
            .expect("slot is one of DEFAULT_KEY_SLOTS");

        // Slot 9E must stay pin-less and touch-less to remain spec compliant, so overrides
        // deliberately do not apply to it.
        if slot == SlotId::CardAuthentication {
            if self.pin_policy.is_some() || self.touch_policy.is_some() {
                log::warn!("Ignoring policy override for the card authentication slot");
            }
            return (*pin, *touch);
        }

        (self.pin_policy.unwrap_or(*pin), self.touch_policy.unwrap_or(*touch))
    }

    /// Management key derived from the subkey generation seed
    fn management_key(&self) -> Result<MgmKey> {
        // Moved in by value so our copy is wiped when `from_bytes` drops it; the `MgmKey`
        // itself keeps an unwiped internal cipher-key copy, so callers keep it short-lived
        let mgmt_seed = self.subseed.key(NAME_MANAGEMENT);
        Ok(MgmKey::from_bytes(mgmt_seed, Some(MgmAlgorithmId::Aes256))?)
    }

    /// Write the CHUID and CCC data objects
    ///
    /// Windows smartcard logon and a good deal of middleware refuse a card carrying neither.
    /// Both identifiers are *derived* rather than generated -- `CardId::generate` would pick a
    /// random one -- so that re-provisioning from the same seed reproduces the same card.
    ///
    /// Each identifier has its own label rather than taking a slice of a shared derivation.
    /// All three are published, so sharing material buys no secrecy, and independent labels
    /// mean a format changing width cannot disturb the others.
    fn upload_card_identifiers(&self, token: &mut YubiKey) -> Result<()> {
        log::info!("Storing card identifiers in CHUID and CCC");

        let mut chuid = CHUID_TEMPLATE;
        chuid[CHUID_GUID_OFFSET..CHUID_GUID_OFFSET + 16]
            .copy_from_slice(&self.subseed.id(NAME_CHUID_ID, 16));
        ChuId(chuid).set(token)?;

        let mut ccc = CCC_TEMPLATE;
        ccc[CCC_ID_OFFSET..CCC_ID_OFFSET + CardId::BYTE_SIZE]
            .copy_from_slice(&self.subseed.id(NAME_CCC_ID, CardId::BYTE_SIZE));
        CccId(ccc).set(token)?;

        Ok(())
    }

    /// Card identifier used in the slot 9E subject.
    ///
    /// Derived from the subkey generation seed rather than read off the card, so that
    /// `certify` (which runs without hardware) and `upload` agree and `check` can compare.
    fn card_id(&self) -> String {
        if let Some(id) = &self.card_id {
            return id.clone();
        }

        let derived: String = self
            .subseed
            .id(NAME_CARD_ID, 4)
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect();

        seed::stamp(&derived)
    }

    /// Derive the whole chain from the seed, without touching a card
    fn generate_chain(&self) -> Result<CertChain> {
        // Root authority: self-signed trust anchor
        let root_key = derive_p256_key(&self.primary, None)?;
        let root_dn = self.identity.root_dn()?;
        let root = issue(
            PivRootCa {
                subject: root_dn.clone(),
                path_len: if self.intermediate { 1 } else { 0 },
            },
            self.ca_validity()?,
            SubjectPublicKeyInfoOwned::from_key(root_key.verifying_key())?,
            &root_key,
        )?;

        // Optional issuing authority, scoped to this subkey generation
        let issuing = if self.intermediate {
            let key = derive_p256_key(
                &self.subseed,
                Some(&seed::label(seed::PREFIX_KEY, NAME_ISSUING_CA)),
            )?;
            let subject = self.identity.issuing_dn(self.subkey.as_deref())?;
            let cert = issue(
                PivIssuingCa { subject, issuer: root_dn.clone() },
                self.ca_validity()?,
                SubjectPublicKeyInfoOwned::from_key(key.verifying_key())?,
                &root_key,
            )?;
            Some((key, cert))
        } else {
            None
        };

        let (issuer_key, issuer_dn) = match &issuing {
            Some((key, cert)) => (key, cert.tbs_certificate().subject().clone()),
            None => (&root_key, root_dn),
        };

        // End-entity certificates, one per slot
        let subkey = self.subkey.as_deref();
        let user_dn = self.identity.user_dn(subkey)?;
        let card_dn = self.identity.card_dn(&self.card_id())?;
        let validity = self.validity()?;

        // Live slots, then the archived generations behind them
        let live = DEFAULT_KEY_SLOTS
            .iter()
            .map(|(slot, role, ..)| (*slot, *role, None));
        let archived = self
            .retired_slots()?
            .into_iter()
            .map(|(slot, generation)| (slot, SlotRole::KeyManagement, Some(generation)));

        let plan: Vec<_> = live.chain(archived).collect();

        let mut leaves = Vec::with_capacity(plan.len());
        for (slot, role, generation) in plan {
            let (seed, label) = self.key_source(slot)?;
            let key = derive_p256_key(&seed, Some(&label))?;

            let profile = PivLeaf {
                // An archived key is qualified by the generation it came from rather than the
                // one running the card, so an old certificate says which rotation it belongs to
                subject: match generation {
                    Some(generation) => self.identity.user_dn(Some(generation))?,
                    None if role.is_user_bound() => user_dn.clone(),
                    None => card_dn.clone(),
                },
                issuer: issuer_dn.clone(),
                role,
                alternatives: if role.is_user_bound() {
                    self.alternatives.clone()
                } else {
                    vec![]
                },
            };

            let cert = issue(
                profile,
                validity,
                SubjectPublicKeyInfoOwned::from_key(key.verifying_key())?,
                issuer_key,
            )?;

            leaves.push((slot, cert));
        }

        Ok(CertChain { root, intermediate: issuing.map(|(_, cert)| cert), leaves })
    }

    /// Wipe the card and install the derived management key and user pin
    fn reset_and_lock(&self, token: &mut YubiKey) -> Result<()> {
        // Lock pin (by repeated tries) ...
        //
        // Both loops are bounded: the retry counters are a u8 on the wire, so no card can
        // ever grant more tries than that, and a conversation that fails to converge within
        // the bound is firmware misbehaving -- better to stop with a report than to hammer
        // the card forever.
        log::info!("Locking smart card pin");
        let mut retries = token.get_pin_retries()?;
        for _ in 0..=u8::MAX as u32 {
            if retries == 0 {
                break;
            }
            match token.verify_pin(&DUMMY_PIN) {
                // The dummy verified: the card's pin *is* the dummy value, and the
                // successful try has just reset the retry counter, so locking by
                // exhaustion can never converge from here
                Ok(()) => bail!("Card pin equals the lock-out pin; change it and retry"),
                Err(CardError::WrongPin { tries }) => retries = tries,
                // Depending on the firmware, a blocked pin may come back as PinLocked
                // instead of a zero try count
                Err(CardError::PinLocked) => retries = 0,
                Err(other) => return Err(other.into()),
            }
        }
        if retries > 0 {
            bail!("Card pin did not lock after exhausting its retries");
        }

        // ... lock puk (by repeated tries) ...
        log::info!("Locking smart card puk");
        retries = 1;
        for _ in 0..=u8::MAX as u32 {
            if retries == 0 {
                break;
            }
            match token.unblock_pin(b"", b"") {
                // An empty puk just unblocked the pin: the puk *is* empty, the retry
                // counter has reset, and exhaustion can never converge from here
                Ok(()) => bail!("Card puk is empty; set one and retry"),
                Err(CardError::WrongPin { tries }) => retries = tries,
                Err(CardError::PinLocked) => retries = 0,
                Err(other) => return Err(other.into()),
            }
        }
        if retries > 0 {
            bail!("Card puk did not lock after exhausting its retries");
        }

        // ... to reset the device
        log::info!("Resetting smart card");
        token.reset_device()?;

        // Authenticate with default key
        token.authenticate(&MgmKey::get_default(token)?)?;

        // Install our management key, but *without* the touch requirement for now.
        //
        // Requiring a touch at this point means a missed button press aborts after
        // `reset_device` has already wiped the card and blocked its puk, leaving it bare with
        // nothing provisioned in exchange -- and the prompt only lasts as long as the token's
        // touch timeout. `require_touch` is switched on at the end of `upload` instead, where
        // the same failure costs nothing and can simply be repeated.
        let mgmt_key = self.management_key()?;
        mgmt_key.set_manual(token, false)?;
        token.authenticate(&mgmt_key)?;

        // Update pin
        if let Some(pin) = &self.pin {
            token.change_pin(b"123456", pin.as_bytes())?;
            token.verify_pin(pin.as_bytes())?;
        } else {
            token.verify_pin(b"123456")?;
            log::warn!("Default pin is being used");
        }

        // Disable puk
        token.block_puk()?;

        Ok(())
    }

    /// Import the slot keys and store their certificates
    fn upload_subcerts(&self, chain: &CertChain, token: &mut YubiKey) -> Result<()> {
        for (slot, cert) in &chain.leaves {
            log::info!("Generating and uploading {:?} subkey", slot);

            // The very same rejection sampled bytes have to reach the card, otherwise the
            // on-card key and the key we just certified would diverge.
            let (seed, label) = self.key_source(*slot)?;
            let bytes = derive_p256_scalar(&seed, Some(&label))?;
            let (pin_policy, touch_policy) = self.policies_for(*slot);

            piv::import_ecc_key(
                token,
                *slot,
                AlgorithmId::EccP256,
                &*bytes,
                touch_policy,
                pin_policy,
            )?;

            // Invariant: the card has to hold the key we certified
            let on_card = piv::metadata(token, *slot)?
                .public
                .ok_or(anyhow!("Failed to retrieve public key"))?;
            if on_card.to_der()? != cert.tbs_certificate().subject_public_key_info().to_der()? {
                bail!("Imported key for {:?} does not match the certified key", slot);
            }

            log::info!("Uploading {:?} certificate", slot);
            CardCertificate::from_bytes(cert.to_der()?)?.write(
                token,
                *slot,
                CertInfo::Uncompressed,
            )?;

            log::info!(
                "Uploaded certificate with fingerprint '{:x}'",
                Sha256::digest(cert.to_der()?)
            );
        }

        Ok(())
    }

    /// Store the certificate authorities in the card's `msroots` object
    fn upload_msroots(&self, chain: &CertChain, token: &mut YubiKey) -> Result<()> {
        log::info!("Storing certificate authorities in msroots");

        // `msroots` holds a degenerate PKCS#7 certs-only SignedData blob
        let content = ContentInfo::try_from(chain.cas())?;
        MsRoots::new(content.to_der()?)?.write(token)?;

        Ok(())
    }
}

/// A [`BuilderProfile`] for the self-signed root certificate authority
struct PivRootCa {
    subject: Name,
    path_len: u8,
}

impl BuilderProfile for PivRootCa {
    fn get_issuer(&self, subject: &Name) -> Name {
        // RFC 5280 Section 3.2: a self-signed certificate is a self-issued certificate
        // whose signature may be verified by the public key bound into it.
        subject.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    // `to_extension` takes the extensions accumulated so far, because `Criticality` may
    // depend on them, so these pushes are sequentially dependent and cannot become a
    // `vec![]` literal.
    #[allow(clippy::vec_init_then_push)]
    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let mut extensions: Vec<Extension> = Vec::new();
        let ski = SubjectKeyIdentifier::try_from(spk)?;

        extensions.push(
            BasicConstraints { ca: true, path_len_constraint: Some(self.path_len) }
                .to_extension(tbs.subject(), &extensions)?,
        );

        extensions.push(
            KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
                .to_extension(tbs.subject(), &extensions)?,
        );

        extensions.push(ski.to_extension(tbs.subject(), &extensions)?);

        // RFC 5280 Section 4.2.1.1: for a self-signed certificate the authority key
        // identifier points back at the subject key identifier.
        extensions.push(
            AuthorityKeyIdentifier { key_identifier: Some(ski.0.clone()), ..Default::default() }
                .to_extension(tbs.subject(), &extensions)?,
        );

        // Deliberately no extended key usage: an absent EKU is unconstrained, which is what
        // a personal root spanning clientAuth, emailProtection and id-PIV-cardAuth needs.
        Ok(extensions)
    }
}

/// A [`BuilderProfile`] for the intermediate issuing certificate authority
struct PivIssuingCa {
    subject: Name,
    issuer: Name,
}

impl BuilderProfile for PivIssuingCa {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    // `to_extension` takes the extensions accumulated so far, because `Criticality` may
    // depend on them, so these pushes are sequentially dependent and cannot become a
    // `vec![]` literal.
    #[allow(clippy::vec_init_then_push)]
    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let mut extensions: Vec<Extension> = Vec::new();

        extensions.push(
            BasicConstraints { ca: true, path_len_constraint: Some(0) }
                .to_extension(tbs.subject(), &extensions)?,
        );

        extensions.push(
            KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
                .to_extension(tbs.subject(), &extensions)?,
        );

        extensions
            .push(SubjectKeyIdentifier::try_from(spk)?.to_extension(tbs.subject(), &extensions)?);

        extensions.push(
            AuthorityKeyIdentifier::try_from(issuer_spk)?
                .to_extension(tbs.subject(), &extensions)?,
        );

        Ok(extensions)
    }
}

/// A [`BuilderProfile`] for the end-entity certificate of a single key slot
struct PivLeaf {
    subject: Name,
    issuer: Name,
    role: SlotRole,
    alternatives: Vec<GeneralName>,
}

impl BuilderProfile for PivLeaf {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    // `to_extension` takes the extensions accumulated so far, because `Criticality` may
    // depend on them, so these pushes are sequentially dependent and cannot become a
    // `vec![]` literal.
    #[allow(clippy::vec_init_then_push)]
    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let mut extensions: Vec<Extension> = Vec::new();

        extensions.push(KeyUsage(self.role.key_usage()).to_extension(tbs.subject(), &extensions)?);

        extensions.push(
            ExtendedKeyUsage(self.role.extended_key_usage())
                .to_extension(tbs.subject(), &extensions)?,
        );

        extensions
            .push(SubjectKeyIdentifier::try_from(spk)?.to_extension(tbs.subject(), &extensions)?);

        extensions.push(
            AuthorityKeyIdentifier::try_from(issuer_spk)?
                .to_extension(tbs.subject(), &extensions)?,
        );

        // GeneralNames is a SEQUENCE SIZE (1..MAX), so an empty alternative name list has to
        // omit the extension rather than encode an empty SEQUENCE.
        if !self.alternatives.is_empty() {
            extensions.push(
                SubjectAltName(self.alternatives.clone())
                    .to_extension(tbs.subject(), &extensions)?,
            );
        }

        // Deliberately no basic constraints: x509-cert always marks them critical and the
        // NIST PIV end-entity profile omits the extension entirely.
        Ok(extensions)
    }
}
