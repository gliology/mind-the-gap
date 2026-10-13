//! The PIV backend: an X.509 chain from seeds, and uploads to YubiKeys.
//!
//! [`SeededSmartcard`] derives a root certificate authority, an optional issuing authority
//! and the four slot keys (9A, 9C, 9D, 9E) on NIST P-256, on NIST P-384 with
//! [`Algorithm::P384`] or, with [`Algorithm::Curve25519`], as Ed25519 and X25519 keys. The
//! chain is signed with RFC 6979 deterministic ECDSA or pure Ed25519 so re-runs are
//! byte-identical, and keys, certificates, identifiers and per-slot policies are written to
//! the card through the `yubikey` crate. The chain layout and its constraints are documented
//! in the certificates chapter,
//! <https://gliology.github.io/mind-the-gap/piv-certificates.html>.

use std::str::FromStr;
use std::time::{Duration, SystemTime};

use crate::common;
use crate::seed::{self, Algorithm, Seed256, Seed256Derive};

use anyhow::{Result, anyhow, bail};

use yubikey::certificate::CertInfo;
use yubikey::piv::{self, AlgorithmId, ManagementSlotId, RetiredSlotId, SlotId};
use yubikey::reader::Context;
use yubikey::{
    CardId, CccId, Certificate as CardCertificate, ChuId, Error as CardError, MgmAlgorithmId,
    MgmKey, MsRoots, PinPolicy, Serial, TouchPolicy, Version, YubiKey,
};

use cms::content_info::ContentInfo;

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{DerSignature, SigningKey};

use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

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

use der::asn1::{BitString, Ia5String};
use der::flagset::FlagSet;
use der::{Encode, EncodePem};

use sha2::{Digest, Sha256};
use spki::{
    AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef,
};
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

/// The factory management key of every PIV card in the Yubico ecosystem, whatever its
/// algorithm
const DEFAULT_MANAGEMENT_KEY: [u8; 24] = [
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
];

/// Derivation name for the root certificate authority key
const NAME_ROOT_CA: &str = "root-ca";

/// Derivation name for the intermediate issuing certificate authority key
const NAME_ISSUING_CA: &str = "issuing-ca";

/// Derivation name for the card management key in slot 9B
const NAME_MANAGEMENT: &str = "management";

/// Algorithm segment of the triple DES management key, `key:management:tdes`
///
/// The AES-256 key predates the segment and keeps its bare `key:management` label, frozen
/// with the rest of `mtg1`; the 3DES key is a later, additive label.
const SEGMENT_TDES: &str = "tdes";

/// First firmware with AES management keys; YubiKey 4 and YubiKey 5 before 5.4 take 3DES only
const FIRST_AES_MANAGEMENT: Version = Version { major: 5, minor: 4, patch: 0 };

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

/// Role a slot plays, by which its key is derived and its algorithm chosen
///
/// A retired slot holds a superseded key management key, so it plays that role.
fn slot_role(slot: SlotId) -> SlotRole {
    match slot {
        SlotId::Retired(_) => SlotRole::KeyManagement,
        other => {
            DEFAULT_KEY_SLOTS
                .iter()
                .find(|(candidate, ..)| *candidate == other)
                .expect("slot is one of DEFAULT_KEY_SLOTS")
                .1
        }
    }
}

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

        // Read each real certificate slot directly instead of `piv_keys()`: the crate's
        // slot table behind that call maps pseudo-slots onto unrelated objects -- "Pin"
        // onto the key management certificate and "Puk" onto the key history object,
        // whose content is no certificate at all, so one written key history object (as
        // any card with retired certificates has) makes the whole listing fail.
        let slots = [
            SlotId::Authentication,
            SlotId::Signature,
            SlotId::KeyManagement,
            SlotId::CardAuthentication,
            SlotId::Attestation,
        ]
        .into_iter()
        .chain(
            (0x82..=0x95)
                .filter_map(|byte| RetiredSlotId::try_from(byte).ok().map(SlotId::Retired)),
        );

        for slot in slots {
            let cert = match CardCertificate::read(&mut token, slot) {
                Ok(cert) => cert,
                // An empty slot is the normal case, not something to report
                Err(_) => continue,
            };

            // Fingerprint is SHA256 hash of certificate
            match cert.cert.to_der() {
                Ok(der) => {
                    println!(
                        "   {} key: {:x} ({})",
                        slot,
                        Sha256::digest(der),
                        common::printable(&cert.subject().to_string())
                    )
                }
                Err(err) => println!(
                    "   {} key: unreadable certificate: {}",
                    slot,
                    common::printable(&err.to_string())
                ),
            }
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

/// Whether management access to a provisioned card demands a touch
#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ManagementTouchArg {
    /// Require a touch for every management authentication
    #[default]
    Always,
    /// Never require a touch, e.g. on a server card provisioned air-gapped
    Never,
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

    /// Label segment of this role's key under `algorithm`: key management agrees, the rest sign
    fn algorithm_segment(&self, algorithm: Algorithm) -> &'static str {
        match self {
            SlotRole::KeyManagement => algorithm.agreement_segment(),
            _ => algorithm.signing_segment(),
        }
    }

    /// The card algorithm this role's key takes when the chain is derived with `algorithm`
    fn card_algorithm(&self, algorithm: Algorithm) -> AlgorithmId {
        match (algorithm, self) {
            (Algorithm::P256, _) => AlgorithmId::EccP256,
            (Algorithm::P384, _) => AlgorithmId::EccP384,
            (Algorithm::Curve25519, SlotRole::KeyManagement) => AlgorithmId::X25519,
            (Algorithm::Curve25519, _) => AlgorithmId::Ed25519,
        }
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
            CertificateKind::Intermediate => vec![self.intermediate.as_ref().ok_or_else(|| {
                anyhow!(
                    "No intermediate certificate authority, pass --intermediate to generate one"
                )
            })?],
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

/// A certificate authority's signing key, in whichever algorithm the chain is built
enum IssuerKey {
    P256(SigningKey),
    P384(p384::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
}

impl IssuerKey {
    /// Derive the authority key for `name` under `parent`
    fn derive(parent: &Seed256, name: &str, algorithm: Algorithm) -> Result<Self> {
        let label = seed::algorithm_label(name, algorithm.signing_segment());
        match algorithm {
            Algorithm::P256 => {
                let bytes = seed::derive_p256_scalar(parent, Some(&label))?;
                SigningKey::from_bytes(&(*bytes).into())
                    .map(IssuerKey::P256)
                    .map_err(|err| anyhow!("Invalid P-256 scalar: {err}"))
            }
            Algorithm::P384 => {
                let bytes = seed::derive_p384_scalar(parent, Some(&label))?;
                p384::ecdsa::SigningKey::from_slice(&bytes)
                    .map(IssuerKey::P384)
                    .map_err(|err| anyhow!("Invalid P-384 scalar: {err}"))
            }
            // Any 32 bytes are an Ed25519 seed, so no rejection sampling here
            Algorithm::Curve25519 => Ok(IssuerKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(
                &parent.derive(Some(&label)),
            ))),
        }
    }

    /// The public half, as it goes into the authority's own certificate
    fn spki(&self) -> Result<SubjectPublicKeyInfoOwned> {
        Ok(match self {
            IssuerKey::P256(key) => SubjectPublicKeyInfoOwned::from_key(key.verifying_key())?,
            IssuerKey::P384(key) => SubjectPublicKeyInfoOwned::from_key(key.verifying_key())?,
            IssuerKey::Ed25519(key) => SubjectPublicKeyInfoOwned::from_key(&key.verifying_key())?,
        })
    }
}

/// A slot's private key: the raw bytes the card imports, and the algorithm they are for
///
/// The bytes are a vector because their width follows the algorithm: 48 for a P-384
/// scalar, 32 for everything else.
struct SlotKey {
    algorithm: AlgorithmId,
    bytes: Zeroizing<Vec<u8>>,
}

impl SlotKey {
    /// Derive the key for `role` under `parent` and `label`
    fn derive(
        parent: &Seed256,
        label: &[u8],
        role: SlotRole,
        algorithm: Algorithm,
    ) -> Result<Self> {
        let algorithm = role.card_algorithm(algorithm);
        let bytes = match algorithm {
            AlgorithmId::EccP256 => {
                Zeroizing::new(seed::derive_p256_scalar(parent, Some(label))?.to_vec())
            }
            AlgorithmId::EccP384 => seed::derive_p384_scalar(parent, Some(label))?,
            // Ed25519 takes any 32 bytes as its seed, X25519 clamps on use; the card does
            // the same with the very same bytes, so neither needs rejection sampling
            _ => Zeroizing::new(parent.derive(Some(label)).to_vec()),
        };

        Ok(SlotKey { algorithm, bytes })
    }

    /// The public half, encoded exactly as the card reports it through `GET METADATA`
    ///
    /// That equality is what `upload` and `check` compare on, byte for byte. The X25519
    /// encoding is spelled out because `x25519-dalek` has no SPKI support: RFC 8410 gives
    /// the algorithm no parameters and the raw 32-byte point as the subject key.
    fn spki(&self) -> Result<SubjectPublicKeyInfoOwned> {
        Ok(match self.algorithm {
            AlgorithmId::EccP256 => {
                let key = SigningKey::from_slice(&self.bytes)
                    .map_err(|err| anyhow!("Invalid P-256 scalar: {err}"))?;
                SubjectPublicKeyInfoOwned::from_key(key.verifying_key())?
            }
            AlgorithmId::EccP384 => {
                let key = p384::ecdsa::SigningKey::from_slice(&self.bytes)
                    .map_err(|err| anyhow!("Invalid P-384 scalar: {err}"))?;
                SubjectPublicKeyInfoOwned::from_key(key.verifying_key())?
            }
            AlgorithmId::Ed25519 => SubjectPublicKeyInfoOwned::from_key(
                &ed25519_dalek::SigningKey::from_bytes(&*self.seed()?).verifying_key(),
            )?,
            AlgorithmId::X25519 => SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifierOwned { oid: piv::OID_X25519, parameters: None },
                subject_public_key: BitString::from_bytes(
                    X25519PublicKey::from(&StaticSecret::from(*self.seed()?)).as_bytes(),
                )?,
            },
            other => bail!("{other:?} is not a slot key algorithm this backend derives"),
        })
    }

    /// The bytes as the 32-byte seed the Curve25519 keys take
    fn seed(&self) -> Result<Zeroizing<Seed256>> {
        let mut seed = Zeroizing::new([0u8; 32]);
        if self.bytes.len() != seed.len() {
            bail!("{:?} key is {} bytes, not 32", self.algorithm, self.bytes.len());
        }
        seed.copy_from_slice(&self.bytes);
        Ok(seed)
    }

    /// Import this key into `slot`, with the card's own import for its algorithm family
    fn import(
        &self,
        token: &mut YubiKey,
        slot: SlotId,
        touch_policy: TouchPolicy,
        pin_policy: PinPolicy,
    ) -> Result<()> {
        match self.algorithm {
            AlgorithmId::EccP256 | AlgorithmId::EccP384 => piv::import_ecc_key(
                token,
                slot,
                self.algorithm,
                &self.bytes,
                touch_policy,
                pin_policy,
            )?,
            _ => piv::import_cv_key(
                token,
                slot,
                self.algorithm,
                &self.bytes,
                touch_policy,
                pin_policy,
            )?,
        }

        Ok(())
    }
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
    issuer: &IssuerKey,
) -> Result<X509Certificate> {
    let serial = serial_for(&subject_pki)?;
    let builder = CertificateBuilder::new(profile, serial, validity, subject_pki)?;

    // The explicit signature type is required: SigningKey implements Signer for more than
    // one signature representation. Deliberately `build`, not `build_with_rng`: ECDSA here
    // uses RFC 6979 deterministic nonces and Ed25519 is deterministic by construction,
    // which is what makes the output reproducible.
    Ok(match issuer {
        IssuerKey::P256(key) => builder.build::<_, DerSignature>(key)?,
        IssuerKey::P384(key) => builder.build::<_, p384::ecdsa::DerSignature>(key)?,
        IssuerKey::Ed25519(key) => builder.build::<_, ed25519_dalek::Signature>(key)?,
    })
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

    /// Override for the per-slot pin policy, ignored for slot 9E
    pin_policy: Option<PinPolicy>,

    /// Override for the per-slot touch policy, ignored for slot 9E
    touch_policy: Option<TouchPolicy>,

    /// Whether to write the certificate authorities to the card's `msroots` object
    msroots: bool,

    /// Algorithm of the management key `upload` installs
    management_algorithm: ManagementKeyArg,

    /// Whether `upload` leaves management access demanding a touch
    management_touch: bool,
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
            identity: Identity { name, ..Default::default() },
            alternatives: vec![],
            creation_time: None,
            validity_duration: None,
            pin: None,
            intermediate: false,
            pin_policy: None,
            touch_policy: None,
            msroots: true,
            management_algorithm: ManagementKeyArg::Auto,
            management_touch: true,
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

    /// Where a slot's key comes from: the seed it derives under and the label it uses
    ///
    /// A retired slot holds a *previous* generation's key management key, so it derives from
    /// that generation's subseed under the very same label the live 9D key uses. Deriving it
    /// by role rather than by slot is what lets an archived key be re-derived at all.
    fn key_source(&self, slot: SlotId) -> Result<(Zeroizing<Seed256>, Vec<u8>)> {
        let segment = slot_role(slot).algorithm_segment(self.algorithm);

        if let SlotId::Retired(retired) = slot {
            let index = usize::from(u8::from(retired).saturating_sub(FIRST_RETIRED_SLOT));
            let generation = self
                .retired
                .get(index)
                .ok_or_else(|| anyhow!("No retired generation for {slot:?}"))?;

            return Ok((
                self.root.sub(Some(generation)),
                seed::algorithm_label(NAME_KEY_MANAGEMENT, segment),
            ));
        }

        // A deliberate copy of the slot's parent seed, wiped when the caller is done with it
        Ok((Zeroizing::new(*self.seed_for(slot)), seed::algorithm_label(slot_name(slot), segment)))
    }

    /// The private key a slot holds, derived the same way whether it is certified or imported
    fn slot_key(&self, slot: SlotId) -> Result<SlotKey> {
        let (seed, label) = self.key_source(slot)?;
        SlotKey::derive(&seed, &label, slot_role(slot), self.algorithm)
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

    /// Pick the algorithm of the management key `upload` installs
    ///
    /// `check` ignores this and derives for whatever algorithm the card reports, so it needs
    /// no flag to verify either kind.
    pub fn with_management_key(mut self, algorithm: ManagementKeyArg) -> Self {
        self.management_algorithm = algorithm;
        self
    }

    /// Choose whether management access keeps demanding a touch after `upload`
    pub fn with_management_touch(mut self, touch: ManagementTouchArg) -> Self {
        self.management_touch = touch == ManagementTouchArg::Always;
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
    /// seed, or with the wrong `--date`, `--subkey` or DN flags, disagrees in *all* of them,
    /// and failing on the first would hide how far the divergence actually goes.
    ///
    /// Slot keys are compared through `GET METADATA`. A card without it (YubiKey before
    /// 5.3) proves each key by signing a random challenge instead, which needs `--pin` for
    /// every slot whose pin policy is not `never`; its slot policies cannot be read at all.
    pub fn check(&self, target: Option<String>) -> Result<()> {
        let chain = self.generate_chain()?;
        let mut token = open_token(target)?;

        // Card has to be under our management key, in whatever algorithm it holds one: the
        // derivation for each is fixed, so the card's answer decides which to compare with
        let algorithm = MgmAlgorithmId::current(&mut token)?;
        let requested = self.management_algorithm(&token);
        if self.management_algorithm != ManagementKeyArg::Auto && algorithm != requested {
            log::warn!(
                "The card holds a {algorithm:?} management key, not the requested {requested:?}"
            );
        }

        // The management key's touch policy, where the card can report it. Advisory like the
        // slot policies below.
        let expected_touch = if self.management_touch {
            TouchPolicy::Always
        } else {
            TouchPolicy::Never
        };
        if let Ok(metadata) =
            piv::metadata(&mut token, SlotId::Management(ManagementSlotId::Management))
            && let Some((_, touch)) = metadata.policy
            && touch != expected_touch
        {
            log::warn!(
                "Policy mismatch in management key: card touch={touch:?}, expected={expected_touch:?}"
            );
        }

        // The prompt goes to stderr: stdout may be carrying PEM or a report, and a buried
        // prompt is a missed touch and a failed run
        log::info!("Verifying smart card {algorithm:?} management key");
        if self.management_touch {
            eprintln!("[Please touch device to authenticate management access!]");
        }
        token.authenticate(&self.management_key(algorithm)?)?;
        if self.management_touch {
            eprintln!();
        }

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

        // A card without GET METADATA warns about what it cannot show once, not per slot
        let mut policies_warned = false;
        let mut pin_warned = false;

        for (slot, expected) in &chain.leaves {
            match piv::metadata(&mut token, *slot) {
                Err(CardError::NotSupported) => {
                    if !policies_warned {
                        log::warn!(
                            "Card has no GET METADATA: slot pin and touch policies are not \
                             verifiable on this card, slot keys are proven by signing"
                        );
                        policies_warned = true;
                    }

                    let spki = expected.tbs_certificate().subject_public_key_info();
                    if let Some(problem) =
                        self.challenge_slot(&mut token, *slot, spki, &mut pin_warned)?
                    {
                        mismatches.push(problem);
                    }
                }
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

    /// Prove that `slot` holds the key behind `spki` on a card that cannot report it
    ///
    /// The card signs a fresh random digest, as wide as the curve's field, and the signature
    /// has to verify under the derived public key. Only the holder of the derived private
    /// key can produce one, so this proves the key as firmly as reading it back would. It
    /// returns the mismatch to report, or `None` when the key verified or could not be
    /// challenged, which is warned about rather than failed: that is a limit of the card,
    /// not a disagreement with the seed.
    fn challenge_slot(
        &self,
        token: &mut YubiKey,
        slot: SlotId,
        spki: &SubjectPublicKeyInfoOwned,
        pin_warned: &mut bool,
    ) -> Result<Option<String>> {
        let algorithm = slot_role(slot).card_algorithm(self.algorithm);
        let width = match algorithm {
            AlgorithmId::EccP256 => 32,
            AlgorithmId::EccP384 => 48,
            // Cards without GET METADATA predate Ed25519 and X25519 by several firmware
            // generations, so this is a card answering inconsistently
            other => {
                log::warn!(
                    "{slot:?} slot: cannot verify a {other:?} key on a card without GET \
                     METADATA, skipping it"
                );
                return Ok(None);
            }
        };

        // Signing is subject to the slot's pin policy. Verified again right before the
        // signature, which is what a pin-always slot demands; a pin-once slot does not mind.
        let (pin_policy, touch_policy) = self.policies_for(slot);
        if pin_policy != PinPolicy::Never {
            match &self.pin {
                Some(pin) => token.verify_pin(pin.as_bytes())?,
                None => {
                    if !*pin_warned {
                        log::warn!(
                            "Slot keys cannot be verified on this card without --pin: it has \
                             no GET METADATA, and signing the challenge needs the pin"
                        );
                        *pin_warned = true;
                    }
                    return Ok(None);
                }
            }
        }

        let mut digest = vec![0u8; width];
        getrandom::fill(&mut digest)
            .map_err(|err| anyhow!("No OS entropy for the signature challenge: {err}"))?;

        if touch_policy != TouchPolicy::Never {
            eprintln!("[Please touch device to prove the {slot:?} key!]");
        }
        let signature = match piv::sign_data(token, &digest, algorithm, slot) {
            Ok(signature) => signature,
            Err(err) => {
                return Ok(Some(format!("{slot:?} slot: signature challenge failed: {err}")));
            }
        };

        let point = spki.subject_public_key.raw_bytes();
        let verified = match algorithm {
            AlgorithmId::EccP256 => {
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
                    .map_err(|err| anyhow!("Derived P-256 key is malformed: {err}"))?;
                DerSignature::from_bytes(&signature)
                    .is_ok_and(|signature| key.verify_prehash(&digest, &signature).is_ok())
            }
            _ => {
                let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
                    .map_err(|err| anyhow!("Derived P-384 key is malformed: {err}"))?;
                p384::ecdsa::DerSignature::from_bytes(&signature)
                    .is_ok_and(|signature| key.verify_prehash(&digest, &signature).is_ok())
            }
        };

        if !verified {
            return Ok(Some(format!(
                "{slot:?} slot: public key is not the derived one (signature challenge)"
            )));
        }

        log::info!("{slot:?} slot key proven by a signature challenge");
        Ok(None)
    }

    /// Generate keys and certificates and upload them to a card
    pub fn upload(&self, target: Option<String>) -> Result<CertChain> {
        // Build the whole chain before touching the card, so that a derivation or encoding
        // failure never leaves a freshly reset card half provisioned.
        let chain = self.generate_chain()?;

        let mut token = open_token(target)?;

        let algorithm = self.reset_and_lock(&mut token)?;
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
        // pressed in time. A card that opts out keeps the key installed without the flag by
        // `reset_and_lock`: a build server's card is provisioned on an air-gapped machine, and
        // the derived management key never reaches the server it then lives in, so the touch
        // would guard nothing there while costing every unattended re-check a button press.
        if self.management_touch {
            log::info!("Requiring touch for future management access");
            self.management_key(algorithm)?
                .set_manual(&mut token, true)?;
        } else {
            log::info!("Management access stays touch-free (--management-key-touch never)");
        }

        // Dropping the session works by selecting the Yubico management applet, which only
        // exists on YubiKeys -- on other PIV implementations the authentication simply ends
        // with the connection, so a failure here must not fail the finished provisioning
        if let Err(err) = token.deauthenticate() {
            log::warn!("Could not deauthenticate management key: {err}");
        }

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

    /// Management key derived from the subkey generation seed, in `algorithm`
    ///
    /// Each algorithm derives under its own label, so the two keys share no bytes: the
    /// 3DES key is not a truncation of the AES-256 one.
    fn management_key(&self, algorithm: MgmAlgorithmId) -> Result<MgmKey> {
        // Moved in by value so our copy is wiped when `from_bytes` drops it; the `MgmKey`
        // itself keeps an unwiped internal cipher-key copy, so callers keep it short-lived
        Ok(match algorithm {
            MgmAlgorithmId::Aes256 => {
                MgmKey::from_bytes(self.subseed.key(NAME_MANAGEMENT), Some(algorithm))?
            }
            MgmAlgorithmId::ThreeDes => {
                let label = seed::algorithm_label(NAME_MANAGEMENT, SEGMENT_TDES);
                MgmKey::from_bytes(
                    seed::derive_tdes_key(&self.subseed, Some(&label))?,
                    Some(algorithm),
                )?
            }
            other => bail!(
                "The card's management key is {other:?}, which this tool never installs: \
                 it was not provisioned by mind-the-gap"
            ),
        })
    }

    /// Algorithm of the management key `upload` installs on `token`
    fn management_algorithm(&self, token: &YubiKey) -> MgmAlgorithmId {
        match self.management_algorithm {
            ManagementKeyArg::Aes256 => MgmAlgorithmId::Aes256,
            ManagementKeyArg::Tdes => MgmAlgorithmId::ThreeDes,
            // The reported version is what decides: a Nitrokey 3 or the trussed PIV app
            // reports 6.6.6 and takes AES, a YubiKey 4 reports 4.x and takes 3DES only
            ManagementKeyArg::Auto if token.version() >= FIRST_AES_MANAGEMENT => {
                MgmAlgorithmId::Aes256
            }
            ManagementKeyArg::Auto => MgmAlgorithmId::ThreeDes,
        }
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
        let root_key = IssuerKey::derive(&self.root, NAME_ROOT_CA, self.algorithm)?;
        let root_dn = self.identity.root_dn()?;
        let root = issue(
            PivRootCa {
                subject: root_dn.clone(),
                path_len: if self.intermediate { 1 } else { 0 },
            },
            self.ca_validity()?,
            root_key.spki()?,
            &root_key,
        )?;

        // Optional issuing authority, scoped to this subkey generation
        let issuing = if self.intermediate {
            let key = IssuerKey::derive(&self.subseed, NAME_ISSUING_CA, self.algorithm)?;
            let subject = self.identity.issuing_dn(self.subkey.as_deref())?;
            let cert = issue(
                PivIssuingCa { subject, issuer: root_dn.clone() },
                self.ca_validity()?,
                key.spki()?,
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
            let key = self.slot_key(slot)?;

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

            let cert = issue(profile, validity, key.spki()?, issuer_key)?;

            leaves.push((slot, cert));
        }

        Ok(CertChain { root, intermediate: issuing.map(|(_, cert)| cert), leaves })
    }

    /// Wipe the card and install the derived management key and user pin
    ///
    /// Returns the algorithm of the installed management key, for `upload` to finish with.
    fn reset_and_lock(&self, token: &mut YubiKey) -> Result<MgmAlgorithmId> {
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

        // Authenticate with the default key in whatever algorithm the reset installed: the
        // firmware version table behind `MgmKey::get_default` only knows YubiKeys
        let algorithm = MgmAlgorithmId::current(token)?;
        let default = MgmKey::from_bytes(DEFAULT_MANAGEMENT_KEY, Some(algorithm))?;
        token.authenticate(&default)?;

        // Install our management key, but *without* the touch requirement for now.
        //
        // Requiring a touch at this point means a missed button press aborts after
        // `reset_device` has already wiped the card and blocked its puk, leaving it bare with
        // nothing provisioned in exchange -- and the prompt only lasts as long as the token's
        // touch timeout. `require_touch` is switched on at the end of `upload` instead, where
        // the same failure costs nothing and can simply be repeated.
        let algorithm = self.management_algorithm(token);
        log::info!("Installing the derived {algorithm:?} management key");
        let mgmt_key = self.management_key(algorithm)?;
        mgmt_key.set_manual(token, false)?;
        token.authenticate(&mgmt_key)?;

        // Update pin
        if let Some(pin) = &self.pin {
            token.change_pin(b"123456", pin.as_bytes())?;
            token.verify_pin(pin.as_bytes())?;
        } else {
            // Warned about once at the command layer; here it only needs verifying
            token.verify_pin(b"123456")?;
        }

        // Disable puk
        token.block_puk()?;

        Ok(algorithm)
    }

    /// Import the slot keys and store their certificates
    fn upload_subcerts(&self, chain: &CertChain, token: &mut YubiKey) -> Result<()> {
        for (slot, cert) in &chain.leaves {
            log::info!("Generating and uploading {:?} subkey", slot);

            // The very same derived bytes have to reach the card, otherwise the on-card key
            // and the key we just certified would diverge.
            let key = self.slot_key(*slot)?;
            let (pin_policy, touch_policy) = self.policies_for(*slot);

            key.import(token, *slot, touch_policy, pin_policy)?;

            // Invariant: the card has to hold the key we certified. A card without GET
            // METADATA (YubiKey before 5.3) cannot say which key it holds; `check` proves it
            // by a signature challenge instead, which needs the pin and possibly a touch per
            // slot, too much to impose on every upload.
            match piv::metadata(token, *slot) {
                Ok(metadata) => {
                    let on_card = metadata
                        .public
                        .ok_or_else(|| anyhow!("Failed to retrieve public key"))?;
                    let want = cert.tbs_certificate().subject_public_key_info().to_der()?;
                    if on_card.to_der()? != want {
                        bail!("Imported key for {:?} does not match the certified key", slot);
                    }
                }
                Err(CardError::NotSupported) => {
                    log::info!("Card has no GET METADATA; the imported key is verified by `check`")
                }
                Err(err) => return Err(err.into()),
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

#[cfg(test)]
mod tests {
    use super::*;

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

    /// The build server profile: the overrides reach 9A, 9C, 9D and the retired slots, while
    /// 9E stays pin- and touch-free as the spec requires.
    #[test]
    fn policy_overrides_skip_card_authentication() {
        let card = card()
            .with_pin_policy(PinPolicy::Once)
            .with_touch_policy(TouchPolicy::Never);
        let retired = SlotId::Retired(RetiredSlotId::try_from(0x83).unwrap());

        for slot in [
            SlotId::Authentication,
            SlotId::Signature,
            SlotId::KeyManagement,
            retired,
        ] {
            assert_eq!(
                card.policies_for(slot),
                (PinPolicy::Once, TouchPolicy::Never),
                "{slot:?} slot ignored the override"
            );
        }
        assert_eq!(
            card.policies_for(SlotId::CardAuthentication),
            (PinPolicy::Never, TouchPolicy::Never)
        );
    }

    /// The 3DES management key: 24 bytes, reproducible, not weak, and sharing nothing with
    /// the AES-256 key of the same card.
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

        // The documented label, and the AES key's unchanged one
        let label = seed::algorithm_label(NAME_MANAGEMENT, SEGMENT_TDES);
        assert_eq!(label, b"key:management:tdes");
        let subseed = card().subseed;
        assert_eq!(aes.as_ref(), &subseed.key(NAME_MANAGEMENT)[..]);
        assert_eq!(tdes.as_ref(), &subseed.derive(Some(&label))[..24]);

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
}
