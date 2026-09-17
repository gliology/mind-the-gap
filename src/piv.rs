use std::str::FromStr;
use std::time::{Duration, SystemTime};

use crate::seed::{Seed256, Seed256Derive};

use anyhow::{anyhow, bail, Result};

use yubikey::certificate::CertInfo;
use yubikey::piv::{self, AlgorithmId, ManagementSlotId, SlotId};
use yubikey::reader::Context;
use yubikey::{
    Certificate as CardCertificate, Error as CardError, MgmAlgorithmId, MgmKey, MsRoots, PinPolicy,
    Serial, TouchPolicy, YubiKey,
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
    (
        SlotId::Authentication,
        SlotRole::Authentication,
        PinPolicy::Once,
        TouchPolicy::Cached,
    ),
    // Non-repudiable signing: PIN and touch immediately before every single signature.
    (
        SlotId::Signature,
        SlotRole::Signature,
        PinPolicy::Always,
        TouchPolicy::Always,
    ),
    (
        SlotId::KeyManagement,
        SlotRole::KeyManagement,
        PinPolicy::Once,
        TouchPolicy::Cached,
    ),
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

/// Derivation label for the root certificate authority key
const PATH_ROOT_CA: [u8; 1] = [0x01];

/// Derivation label for the intermediate issuing certificate authority key
const PATH_ISSUING_CA: [u8; 1] = [0x02];

/// Derivation label for the card identifier used in the slot 9E subject
const PATH_CARD_ID: &[u8] = b"card";

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
                    let cert = key.certificate();

                    // Fingerprint is SHA256 hash of certificate
                    match cert.cert.to_der() {
                        Ok(der) => println!(
                            "   {} key: {:x} ({})",
                            key.slot(),
                            Sha256::digest(der),
                            cert.subject()
                        ),
                        Err(err) => println!("   {} key: unreadable certificate: {err}", key.slot()),
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
        let mut parts = vec![format!("CN={}", escape_rdn(common_name))];

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
    fn user_dn(&self) -> Result<Name> {
        self.dn(&self.name)
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
    let mut candidate = Zeroizing::new(parent.derive(path));

    for _ in 0..MAX_SCALAR_TRIES {
        if p256::SecretKey::from_bytes(&(*candidate).into()).is_ok() {
            return Ok(candidate);
        }

        log::warn!("Derived scalar outside the P-256 group order, re-deriving");
        candidate = Zeroizing::new(candidate.derive(Some(b"p256-retry")));
    }

    bail!("Failed to derive a valid P-256 scalar")
}

/// Derive a P-256 signing key from a seed
fn derive_p256_key(parent: &Seed256, path: Option<&[u8]>) -> Result<SigningKey> {
    let bytes = derive_p256_scalar(parent, path)?;
    SigningKey::from_bytes(&(*bytes).into()).map_err(|err| anyhow!("Invalid P-256 scalar: {err}"))
}

/// Serial number from the last 20 bytes of the subject public key fingerprint
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
    primary: Seed256,

    /// Seed used for the issuing authority, management key and all slot keys
    subseed: Seed256,

    /// Subkey id, used to keep issuing authority subjects distinguishable
    subkey: Option<Zeroizing<String>>,

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
    pub fn new(seed: Seed256, subkey: Option<Zeroizing<String>>, name: String) -> Self {
        // Derive application specific root seed
        let root = seed.derive(Some(b"piv"));

        // Derive seed for the root authority and everything below the subkey id. The root
        // authority is a *sibling* of the subseed, not its parent: were it the parent (as it
        // used to be), anyone holding the authority key could re-derive every slot key.
        let primary = root.derive(Some(&PATH_ROOT_CA));
        let subseed = root.derive(subkey.as_ref().map(|k| k.as_bytes()));

        SeededSmartcard {
            primary,
            subseed,
            subkey,
            identity: Identity {
                name,
                ..Default::default()
            },
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

    pub fn with_pin(mut self, pin: Zeroizing<String>) -> Self {
        self.pin = Some(pin.clone());
        self
    }

    /// Add email to list of alternative names
    pub fn add_email(mut self, address: &str) -> Self {
        self.alternatives.push(GeneralName::Rfc822Name(
            Ia5String::new(address).expect("email address is valid ASCII"),
        ));
        self
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

    /// Override the card identifier used in the slot 9E subject
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
    pub fn check(&self, target: Option<String>) -> Result<()> {
        let chain = self.generate_chain()?;
        let mut token = open_token(target)?;

        // Card has to be under our management key
        log::info!("Verifying smart card management key");
        println!("[Please touch device to authenticate management access!]");
        token.authenticate(&self.management_key(&token)?)?;
        println!();

        for (slot, expected) in &chain.leaves {
            let metadata = piv::metadata(&mut token, *slot)?;

            // Key material has to match what we would derive
            let on_card = metadata
                .public
                .ok_or(anyhow!("No key found in {:?} slot", slot))?;
            if on_card.to_der()?
                != expected
                    .tbs_certificate()
                    .subject_public_key_info()
                    .to_der()?
            {
                bail!("Public key mismatch in {:?} slot", slot);
            }

            // Policies are advisory: warn rather than fail, they can be tightened by hand
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

            // Certificate has to be byte identical
            let card_cert = CardCertificate::read(&mut token, *slot)?;
            let want = Sha256::digest(expected.to_der()?);
            let got = Sha256::digest(card_cert.cert.to_der()?);
            if want != got {
                bail!(
                    "Certificate mismatch in {:?} slot: card={:x}, derived={:x}",
                    slot,
                    got,
                    want
                );
            }

            log::info!("{:?} slot matches: {:x}", slot, got);
        }

        if self.msroots {
            let expected = ContentInfo::try_from(chain.cas())?.to_der()?;
            match MsRoots::read(&mut token)? {
                Some(roots) if AsRef::<[u8]>::as_ref(&roots) == expected.as_slice() => {
                    log::info!("Certificate authorities in msroots match")
                }
                Some(_) => log::warn!("Certificate authorities in msroots do not match"),
                None => log::warn!("No certificate authorities stored in msroots"),
            }
        }

        token.deauthenticate()?;

        Ok(())
    }

    /// Generate keys and certificates and upload them to a card
    pub fn upload(&self, target: Option<String>) -> Result<CertChain> {
        // Build the whole chain before touching the card, so that a derivation or encoding
        // failure never leaves a freshly reset card half provisioned.
        let chain = self.generate_chain()?;

        let mut token = open_token(target)?;

        self.reset_and_lock(&mut token)?;
        self.upload_subcerts(&chain, &mut token)?;

        if self.msroots {
            // Windows-only, so a failure here must not abort an otherwise good provisioning
            if let Err(err) = self.upload_msroots(&chain, &mut token) {
                log::warn!("Failed to store certificate authorities in msroots: {err}");
            }
        }

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
        Ok(Validity::new(
            Time::try_from(self.creation_time())?,
            Time::INFINITY,
        ))
    }

    /// Effective pin and touch policy for a slot
    fn policies_for(&self, slot: SlotId) -> (PinPolicy, TouchPolicy) {
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

        (
            self.pin_policy.unwrap_or(*pin),
            self.touch_policy.unwrap_or(*touch),
        )
    }

    /// Management key derived from the subkey generation seed
    fn management_key(&self, token: &YubiKey) -> Result<MgmKey> {
        let _ = token;
        let mgmt_id = u8::from(ManagementSlotId::Management);
        let mgmt_seed = self.subseed.derive(Some(&mgmt_id.to_le_bytes()));
        Ok(MgmKey::from_bytes(mgmt_seed, Some(MgmAlgorithmId::Aes256))?)
    }

    /// Card identifier used in the slot 9E subject.
    ///
    /// Derived from the subkey generation seed rather than read off the card, so that
    /// `certify` (which runs without hardware) and `upload` agree and `check` can compare.
    fn card_id(&self) -> String {
        if let Some(id) = &self.card_id {
            return id.clone();
        }

        let derived = self.subseed.derive(Some(PATH_CARD_ID));
        derived[..4]
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect()
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
            let key = derive_p256_key(&self.subseed, Some(&PATH_ISSUING_CA))?;
            let subject = self
                .identity
                .issuing_dn(self.subkey.as_ref().map(|id| id.as_str()))?;
            let cert = issue(
                PivIssuingCa {
                    subject,
                    issuer: root_dn.clone(),
                },
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
        let user_dn = self.identity.user_dn()?;
        let card_dn = self.identity.card_dn(&self.card_id())?;
        let validity = self.validity()?;

        let mut leaves = Vec::with_capacity(DEFAULT_KEY_SLOTS.len());
        for (slot, role, ..) in DEFAULT_KEY_SLOTS.iter() {
            let key = derive_p256_key(&self.subseed, Some(&u8::from(*slot).to_le_bytes()))?;

            let profile = PivLeaf {
                subject: if role.is_user_bound() {
                    user_dn.clone()
                } else {
                    card_dn.clone()
                },
                issuer: issuer_dn.clone(),
                role: *role,
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

            leaves.push((*slot, cert));
        }

        Ok(CertChain {
            root,
            intermediate: issuing.map(|(_, cert)| cert),
            leaves,
        })
    }

    /// Wipe the card and install the derived management key and user pin
    fn reset_and_lock(&self, token: &mut YubiKey) -> Result<()> {
        // Lock pin (by repeated tries) ...
        log::info!("Locking smart card pin");
        let mut retries = token.get_pin_retries()?;
        while retries > 0 {
            match token.verify_pin(&DUMMY_PIN) {
                Err(CardError::WrongPin { tries }) => {
                    retries = tries;
                    Ok(())
                }
                other => other,
            }?;
        }

        // ... lock puk (by repeated tries) ...
        log::info!("Locking smart card puk");
        retries = 1;
        while retries > 0 {
            match token.unblock_pin(b"", b"") {
                Err(CardError::WrongPin { tries }) => {
                    retries = tries;
                    Ok(())
                }
                Err(CardError::PinLocked) => {
                    retries = 0;
                    Ok(())
                }
                other => other,
            }?;
        }

        // ... to reset the device
        log::info!("Resetting smart card");
        token.reset_device()?;

        // Authenticate with default key
        token.authenticate(&MgmKey::get_default(token)?)?;

        // Update management key
        let mgmt_key = self.management_key(token)?;
        mgmt_key.set_manual(token, true)?;

        println!("[Please touch device to authenticate management access!]");
        token.authenticate(&mgmt_key)?;
        println!();

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
            let bytes = derive_p256_scalar(&self.subseed, Some(&u8::from(*slot).to_le_bytes()))?;
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
                bail!(
                    "Imported key for {:?} does not match the certified key",
                    slot
                );
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
            BasicConstraints {
                ca: true,
                path_len_constraint: Some(self.path_len),
            }
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
            AuthorityKeyIdentifier {
                key_identifier: Some(ski.0.clone()),
                ..Default::default()
            }
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
            BasicConstraints {
                ca: true,
                path_len_constraint: Some(0),
            }
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
