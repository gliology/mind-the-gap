//! The X.509 chain: subject names, the authorities and the slot certificates.
//!
//! Part of the frozen `mtg1` derivation, like `keys`: certificates are compared byte for
//! byte with what a card holds.

use std::str::FromStr;
use std::time::SystemTime;

use super::keys::{SlotKey, SlotSecret};
use super::{CertificateKind, SeededSmartcard, SlotRole};
use crate::backend::cached;
use crate::revocation::{Reason, RevocationKind};
use crate::role::KeyRole;
use crate::seed::{self, Algorithm, CardSerial, Seed256};

use anyhow::{Result, anyhow, bail};

use yubikey::piv::{AlgorithmId, SlotId};

use p256::ecdsa::{DerSignature, SigningKey};

use rsa::RsaPrivateKey;
use rsa::pkcs1v15::{Signature as RsaSignature, SigningKey as RsaSigningKey};
use rsa::sha2::Sha256 as RsaSha256;

use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
use x509_cert::ext::pkix::crl::CrlNumber;
use x509_cert::ext::pkix::crl::dp::DistributionPoint;
use x509_cert::ext::pkix::name::DistributionPointName;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
    SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::ext::pkix::{CrlDistributionPoints, CrlReason};
use x509_cert::ext::{Extension, ToExtension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};
use x509_cert::{Certificate as X509Certificate, PkiPath, TbsCertificate};

use der::referenced::OwnedToRef;
use der::{Decode, DecodePem, Encode, EncodePem};

use sha2::{Digest, Sha256};

use spki::{
    AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, ObjectIdentifier,
    SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef,
};

/// Derivation name for the root certificate authority key
const NAME_ROOT_CA: &str = "root-ca";

/// Derivation name for the intermediate issuing certificate authority key
const NAME_ISSUING_CA: &str = "issuing-ca";

/// `id-PIV-cardAuth` -- NIST SP 800-73-4 Part 1, Appendix B.
///
/// FIPS 201-3 section 4.2.3 requires this extended key usage on the slot 9E certificate.
pub(super) const ID_PIV_CARD_AUTH: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.6.8");

/// Microsoft Smartcard Logon, required by Windows/Active Directory smartcard logon
pub(super) const ID_MS_SMARTCARD_LOGON: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.20.2.2");

/// Distinguished name attributes shared by every tier of the chain
#[derive(Clone, Debug, Default)]
pub(super) struct SubjectName {
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

/// `ub-common-name`, `ub-organization-name` and `ub-organizational-unit-name`, RFC 5280
/// appendix A.1, which strict verifiers hold a certificate to
const UB_NAME: usize = 64;

/// The most a common name adds to the identity's name: the issuing authority's, one longer
/// than the root's longest, ` PIV Root CA curve25519`
const LONGEST_ADDITION: usize = " PIV Issuing CA 00000000".len();

/// The longest name an identity's PIV certificates take, in characters
///
/// One bound whatever the algorithm and whether there is an issuing authority: an identity
/// keeps its name for good, and a second algorithm or an issuing authority may come later.
const NAME_BOUND: usize = UB_NAME - LONGEST_ADDITION;

/// Refuse names no PIV certificate of the identity can carry: a name, organization or unit
/// that is empty or past its bound, counted in characters as given (escaping adds none), or a
/// country that is not two uppercase letters, as the `C` attribute's PrintableString of size
/// two takes it
///
/// `None` is a name left out, which is no problem here.
pub fn refuse_unfit_names(
    name: Option<&str>,
    org: Option<&str>,
    unit: Option<&str>,
    country: Option<&str>,
) -> Result<()> {
    let mut problems = Vec::new();
    let mut bounded = |option: &str, what: &str, value: Option<&str>, bound: usize, why: &str| {
        let Some(value) = value else {
            return;
        };
        let length = value.chars().count();
        if length == 0 {
            problems.push(format!(
                "{option} is empty; a PIV certificate takes {what} of one character or more"
            ));
        } else if length > bound {
            problems.push(format!(
                "{option} is {length} characters, and a PIV certificate takes {what} of at most \
                 {bound}{why}"
            ));
        }
    };
    bounded(
        "--name",
        "a name",
        name,
        NAME_BOUND,
        ": the issuing authority's common name, the name with ` PIV Issuing CA` and an \
         8-digit tag, has to fit the 64 RFC 5280 allows",
    );
    bounded("--org", "an organization", org, UB_NAME, " (RFC 5280)");
    bounded("--unit", "an organizational unit", unit, UB_NAME, " (RFC 5280)");
    if let Some(country) = country
        && !(country.len() == 2 && country.bytes().all(|byte| byte.is_ascii_uppercase()))
    {
        problems.push(format!(
            "--country '{country}' is no country code: a PIV certificate takes two uppercase \
             letters, such as DE"
        ));
    }
    if !problems.is_empty() {
        bail!("{}", problems.join("\n"));
    }
    Ok(())
}

/// Refuse a URL the identity's revocation lists cannot be published by: one without a
/// scheme, without a host where its scheme needs one, with an empty path segment, a query
/// or a fragment, or whose last segment is not a list's name ending in `.crl`
///
/// The URL names the lists' stem, which every list's URL is made from (see
/// [`SeededSmartcard::revocation_list_suffix`]), so the stem has to take a suffix and still
/// be the URL of a list; the list's name is therefore held to the characters a URL carries
/// as they are, while the path before it may be percent-encoded.
pub fn refuse_unfit_crl_url(url: &str) -> Result<()> {
    const EXAMPLE: &str = "such as http://example.org/alice.crl";
    let Some((scheme, rest)) = url.split_once("://") else {
        bail!("'{url}' is no URL; revocation lists are fetched from one, {EXAMPLE}");
    };
    let scheme_fits = scheme.starts_with(|first: char| first.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "+-.".contains(character));
    if !scheme_fits {
        bail!("'{url}' names no scheme; revocation lists are fetched from a URL, {EXAMPLE}");
    }
    if url.contains(['?', '#']) {
        bail!(
            "'{url}' carries a query or a fragment, which the lists' URLs cannot be made from; \
             name the list itself, {EXAMPLE}"
        );
    }
    let Some((authority, path)) = rest.split_once('/') else {
        bail!("'{url}' has no path, which ends in the list's name with .crl, {EXAMPLE}");
    };
    // A file URL names the local machine by leaving the host out; every other scheme
    // fetches from a host
    if authority.is_empty() && !scheme.eq_ignore_ascii_case("file") {
        bail!("'{url}' names no host to fetch the lists from, {EXAMPLE}");
    }
    let (before, name) = path.rsplit_once('/').unwrap_or(("", path));
    let unreserved = |byte: u8| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte);
    let stem = name.strip_suffix(".crl").unwrap_or_default();
    if stem.is_empty() || !stem.bytes().all(unreserved) {
        bail!(
            "'{url}' does not end in a list's name: the last segment of the path is one or more \
             letters, digits, '-', '.', '_' or '~', then .crl, and nothing in it is \
             percent-encoded, {EXAMPLE}"
        );
    }
    if path.split('/').any(str::is_empty) {
        bail!("'{url}' has an empty segment in its path, {EXAMPLE}");
    }
    if !authority
        .bytes()
        .chain(before.bytes())
        .all(|byte| byte.is_ascii_graphic())
    {
        bail!(
            "'{url}' holds a space or a character outside ASCII before the list's name; \
             percent-encode it there"
        );
    }
    Ok(())
}

impl SubjectName {
    /// Build `CN=<cn>[,OU=..][,O=..][,C=..]`.
    ///
    /// `RdnSequence::from_str` reverses the sequence, so writing the attributes in RFC 4514
    /// order yields DER order C, O, OU, CN.
    ///
    /// The names are held to their bounds here, where every subject is made, so that no
    /// certificate carries one past them, whichever setters a caller used and in whatever
    /// order.
    fn dn(&self, common_name: &str) -> Result<Name> {
        refuse_unfit_names(
            Some(&self.name),
            self.org.as_deref(),
            self.org_unit.as_deref(),
            self.country.as_deref(),
        )?;
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

    /// Subject of the self-signed root certificate authority of `algorithm`, named as the
    /// command line spells it (`curve25519`, where the root key's label says `ed25519`)
    ///
    /// The root derives from the key seed and the algorithm alone, so the algorithm is what
    /// tells two roots of one identity apart; it reveals nothing the key does not show.
    fn root_dn(&self, algorithm: Algorithm) -> Result<Name> {
        self.dn(&format!("{} PIV Root CA {algorithm}", self.name))
    }

    /// Subject of the intermediate issuing certificate authority, named by the tag of its own
    /// key (see [`SeededSmartcard::issuing_tag`]) in uppercase hex, as the 9E subject writes
    /// the card id and OpenSSL the key identifier it is cut from
    fn issuing_dn(&self, tag: u32) -> Result<Name> {
        self.dn(&format!("{} PIV Issuing CA {tag:08X}", self.name))
    }

    /// Subject of the person-bound slot certificates (9A, 9C, 9D and the retired slots): the
    /// identity, on every card alike
    ///
    /// Public material carries no device label, as on OpenPGP: which device a certificate is
    /// for is told by its key, which only that device's subkey id derives.
    fn user_dn(&self) -> Result<Name> {
        self.dn(&self.name)
    }
}

/// Subject of the card-bound slot certificate (9E), which names the card and nobody else
fn card_dn(card_id: &str) -> Result<Name> {
    Ok(Name::from_str(&format!("CN={}", escape_rdn(&format!("PIV Card {card_id}"))))?)
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

    /// What a certificate of this chain is, for whoever has to pick one out of several
    ///
    /// The person slots share a subject, so a leaf is named by its slot rather than by it.
    pub fn name_of(&self, cert: &X509Certificate) -> String {
        if std::ptr::eq(cert, &self.root) {
            return "root CA".into();
        }
        if self
            .intermediate
            .as_ref()
            .is_some_and(|issuer| std::ptr::eq(cert, issuer))
        {
            return "issuing CA".into();
        }
        let Some((slot, _)) = self
            .leaves
            .iter()
            .find(|(_, leaf)| std::ptr::eq(leaf, cert))
        else {
            return cert.tbs_certificate().subject().to_string();
        };
        let role = match slot {
            SlotId::Authentication => "authentication",
            SlotId::Signature => "signature",
            SlotId::KeyManagement => "key management",
            SlotId::CardAuthentication => "card authentication",
            SlotId::Retired(_) => "retired key management",
            _ => "other",
        };
        format!("{role} slot {:02X}", u8::from(*slot))
    }
}

/// A certificate authority's signing key, in whichever algorithm the chain is built
pub(super) enum IssuerKey {
    P256(SigningKey),
    P384(p384::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
    Rsa(Box<RsaSigningKey<RsaSha256>>),
}

impl IssuerKey {
    /// Derive the authority key for `name` under `parent`, as a slot key of a signing role
    /// derives
    fn derive(parent: &Seed256, name: &str, algorithm: Algorithm) -> Result<Self> {
        let label = seed::algorithm_label(name, algorithm.signing_segment());
        let algorithm = SlotRole::Signature.card_algorithm(algorithm);
        IssuerKey::try_from(SlotKey::derive(parent, &label, algorithm)?)
    }

    /// The algorithm the key signs with, as a signature names it
    fn signature_algorithm(&self) -> Result<AlgorithmIdentifierOwned> {
        Ok(match self {
            IssuerKey::P256(key) => key.signature_algorithm_identifier()?,
            IssuerKey::P384(key) => key.signature_algorithm_identifier()?,
            IssuerKey::Ed25519(key) => key.signature_algorithm_identifier()?,
            IssuerKey::Rsa(key) => key.signature_algorithm_identifier()?,
        })
    }

    /// Sign `message` as the certificates are signed: deterministically, with the digest the
    /// algorithm names
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        use p256::ecdsa::signature::{SignatureEncoding, Signer};
        Ok(match self {
            IssuerKey::P256(key) => Signer::<DerSignature>::try_sign(key, message)?.to_vec(),
            IssuerKey::P384(key) => {
                Signer::<p384::ecdsa::DerSignature>::try_sign(key, message)?.to_vec()
            }
            IssuerKey::Ed25519(key) => key.try_sign(message)?.to_bytes().to_vec(),
            IssuerKey::Rsa(key) => {
                Signer::<RsaSignature>::try_sign(key.as_ref(), message)?.to_vec()
            }
        })
    }

    /// The public half, as it goes into the authority's own certificate
    fn spki(&self) -> Result<SubjectPublicKeyInfoOwned> {
        Ok(match self {
            IssuerKey::P256(key) => SubjectPublicKeyInfoOwned::from_key(key.verifying_key())?,
            IssuerKey::P384(key) => SubjectPublicKeyInfoOwned::from_key(key.verifying_key())?,
            IssuerKey::Ed25519(key) => SubjectPublicKeyInfoOwned::from_key(&key.verifying_key())?,
            IssuerKey::Rsa(key) => SubjectPublicKeyInfoOwned::from_key(
                AsRef::<RsaPrivateKey>::as_ref(key.as_ref()).as_public_key(),
            )?,
        })
    }
}

impl TryFrom<SlotKey> for IssuerKey {
    type Error = anyhow::Error;

    /// The signing key a slot key is, for a key that signs certificates: an authority's, or
    /// the card authentication key, which signs its own
    fn try_from(key: SlotKey) -> Result<Self> {
        match key.secret {
            SlotSecret::Rsa(rsa) => Ok(IssuerKey::Rsa(Box::new(RsaSigningKey::new(*rsa)))),
            secret => IssuerKey::try_from(&SlotKey { algorithm: key.algorithm, secret }),
        }
    }
}

impl TryFrom<&SlotKey> for IssuerKey {
    type Error = anyhow::Error;

    /// The signing key a slot key is, while the slot key itself stays for the card to import
    fn try_from(key: &SlotKey) -> Result<Self> {
        Ok(match (key.algorithm, &key.secret) {
            // The signer owns its key, so an RSA key is the one secret copied here, and wiped
            // on drop like the original
            (_, SlotSecret::Rsa(rsa)) => {
                IssuerKey::Rsa(Box::new(RsaSigningKey::new(rsa.as_ref().clone())))
            }
            // From the slice, which p256 reads in place rather than as a copy of its own
            (AlgorithmId::EccP256, SlotSecret::Bytes(bytes)) => IssuerKey::P256(
                SigningKey::from_slice(&bytes[..])
                    .map_err(|err| anyhow!("Invalid P-256 scalar: {err}"))?,
            ),
            (AlgorithmId::EccP384, SlotSecret::Bytes(bytes)) => IssuerKey::P384(
                p384::ecdsa::SigningKey::from_slice(bytes)
                    .map_err(|err| anyhow!("Invalid P-384 scalar: {err}"))?,
            ),
            (AlgorithmId::Ed25519, SlotSecret::Bytes(bytes)) => {
                let seed: &[u8; 32] = bytes[..]
                    .try_into()
                    .map_err(|_| anyhow!("Ed25519 key is {} bytes, not 32", bytes.len()))?;
                IssuerKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(seed))
            }
            (other, _) => bail!("{other:?} keys sign no certificate"),
        })
    }
}

/// Serial number from everything a certificate says but its serial and its signature: the
/// to-be-signed certificate built with a placeholder serial, hashed with SHA-256, of which the
/// last 20 bytes are taken
///
/// RFC 5280 4.1.2.2 wants an issuer's serials unique per certificate. Hashing less would hand
/// a certificate re-issued with other emails, another revocation list URL or another issuer
/// the serial of the one it replaces, which relying-party caches and revocation lists key on;
/// with all of it hashed, one seed still re-issues the very same certificate
/// deterministically, and any change to it is a new serial.
fn serial_for(tbs: &[u8]) -> Result<SerialNumber> {
    let mut digest: [u8; 32] = Sha256::digest(tbs).into();
    digest[12] &= 0x7f; // MSB has to be zero
    Ok(SerialNumber::new(&digest[12..32])?)
}

/// Issue a certificate for `subject_pki`, signed by `issuer`
fn issue<P: BuilderProfile + Clone>(
    profile: P,
    validity: Validity,
    subject_pki: SubjectPublicKeyInfoOwned,
    issuer: &IssuerKey,
) -> Result<X509Certificate> {
    // Finalizing adds the profile's extensions and the issuer's algorithm, signing nothing
    let placeholder = SerialNumber::new(&[1])?;
    let mut probe =
        CertificateBuilder::new(profile.clone(), placeholder, validity, subject_pki.clone())?;
    let tbs = match issuer {
        IssuerKey::P256(key) => probe.finalize(key)?,
        IssuerKey::P384(key) => probe.finalize(key)?,
        IssuerKey::Ed25519(key) => probe.finalize(key)?,
        IssuerKey::Rsa(key) => probe.finalize(key.as_ref())?,
    };
    let builder = CertificateBuilder::new(profile, serial_for(&tbs)?, validity, subject_pki)?;

    // The explicit signature type is required: SigningKey implements Signer for more than
    // one signature representation. Deliberately `build`, not `build_with_rng`: ECDSA here
    // uses RFC 6979 deterministic nonces, and Ed25519 and PKCS#1 v1.5 are deterministic by
    // construction, which is what makes the output reproducible.
    Ok(match issuer {
        IssuerKey::P256(key) => builder.build::<_, DerSignature>(key)?,
        IssuerKey::P384(key) => builder.build::<_, p384::ecdsa::DerSignature>(key)?,
        IssuerKey::Ed25519(key) => builder.build::<_, ed25519_dalek::Signature>(key)?,
        IssuerKey::Rsa(key) => builder.build::<_, RsaSignature>(key.as_ref())?,
    })
}

/// A [`BuilderProfile`] for the self-signed root certificate authority
#[derive(Clone)]
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
#[derive(Clone)]
struct PivIssuingCa {
    subject: Name,
    issuer: Name,
    crl: Option<der::asn1::Ia5String>,
}

/// The distribution point naming where the root authority's revocation list is fetched
fn distribution_points(url: &der::asn1::Ia5String) -> CrlDistributionPoints {
    CrlDistributionPoints(vec![DistributionPoint {
        distribution_point: Some(DistributionPointName::FullName(vec![
            GeneralName::UniformResourceIdentifier(url.clone()),
        ])),
        reasons: None,
        crl_issuer: None,
    }])
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

        if let Some(url) = &self.crl {
            extensions.push(distribution_points(url).to_extension(tbs.subject(), &extensions)?);
        }

        Ok(extensions)
    }
}

/// A [`BuilderProfile`] for the end-entity certificate of a single key slot
#[derive(Clone)]
struct PivLeaf {
    subject: Name,
    issuer: Name,
    role: SlotRole,
    alternatives: Vec<GeneralName>,
    /// Where the issuer's revocation list is, for a certificate the root issues itself
    crl: Option<der::asn1::Ia5String>,
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

        let rsa = spk.algorithm.oid == rsa::pkcs1::ALGORITHM_OID;
        extensions
            .push(KeyUsage(self.role.key_usage(rsa)).to_extension(tbs.subject(), &extensions)?);

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

        if let Some(url) = &self.crl {
            extensions.push(distribution_points(url).to_extension(tbs.subject(), &extensions)?);
        }

        // Deliberately no basic constraints: x509-cert always marks them critical and the
        // NIST PIV end-entity profile omits the extension entirely.
        Ok(extensions)
    }
}

impl SeededSmartcard {
    /// Generate the certificate chain of the chosen keys, without touching a card
    ///
    /// The slot certificates only where `kind` selects them: the authorities alone need no
    /// slot key, and an RSA one takes seconds to derive.
    pub fn certify(&self, kind: CertificateKind) -> Result<CertChain> {
        let chain = match kind {
            CertificateKind::Root | CertificateKind::Intermediate => self.chain_of(&[])?,
            CertificateKind::Chain | CertificateKind::Leaves => self.generate_chain()?,
        };
        // Selected here as well, so that `--kind intermediate` without `--intermediate` fails
        // where the chain is made
        chain.select(kind)?;
        Ok(chain)
    }

    /// Creation time of the root authority, which the identity keeps for good
    ///
    /// Defaults to one second after the unix epoch so that the identity stays byte
    /// reproducible, mirroring the OpenPGP backend.
    fn identity_time(&self) -> SystemTime {
        self.identity_time.unwrap_or(seed::epoch_creation())
    }

    /// Validity period of the leaf certificates: from the generation's day on
    fn validity(&self) -> Result<Validity> {
        let not_before = self.path.creation_time();
        let not_after = match self.validity_duration {
            Some(duration) => Time::try_from(not_before + duration)?,
            None => Time::INFINITY,
        };

        Ok(Validity::new(Time::try_from(not_before)?, not_after))
    }

    /// Validity period of a certificate authority created at `not_before`.
    ///
    /// Authorities never expire: they are re-derivable from the mnemonic, and an infinite
    /// notAfter guarantees a leaf can never outlive its issuer.
    fn ca_validity(not_before: SystemTime) -> Result<Validity> {
        Ok(Validity::new(Time::try_from(not_before)?, Time::INFINITY))
    }

    /// The root authority's key
    fn root_key(&self) -> Result<&IssuerKey> {
        cached(&self.derived.root, || {
            IssuerKey::derive(self.seeds.key()?.app(), NAME_ROOT_CA, self.algorithm)
        })
    }

    /// The issuing authority's key, one per device and generation
    fn issuing_key(&self) -> Result<&IssuerKey> {
        cached(&self.derived.issuing, || {
            IssuerKey::derive(self.seeds.key()?.device(), NAME_ISSUING_CA, self.algorithm)
        })
    }

    /// The tag that names the issuing authority and its revocation list: the first four bytes
    /// of its subject key identifier, the RFC 5280 SHA-1 of its key that its certificate
    /// carries anyway
    ///
    /// Public material carries no device label, as on OpenPGP, so the authority is named by
    /// a tag of its key. The key derives under the device, the generation and the
    /// algorithm, so each of them names the authority apart, and the tag says nothing the key
    /// identifier extension does not. The serial cannot serve: it hashes the to-be-signed
    /// certificate, which holds the subject the tag goes into.
    ///
    /// 32 bits, as wide as the 9E card id, suffice because a tag only has to differ among one
    /// identity's authorities: at a hundred of them two share a tag with a chance of about one
    /// in a million, and two that do share a list URL, so verifiers that check revocation
    /// refuse one of them, which is a failure to verify, not a break.
    fn issuing_tag(&self) -> Result<u32> {
        let spki = self.issuing_key()?.spki()?;
        let identifier = SubjectKeyIdentifier::try_from(spki.owned_to_ref())?;
        let prefix = identifier
            .0
            .as_bytes()
            .first_chunk::<4>()
            .ok_or_else(|| anyhow!("The issuing authority's key identifier is too short"))?;
        Ok(u32::from_be_bytes(*prefix))
    }

    /// Derive the chain of the chosen keys from the key seed, without touching a card
    pub(super) fn generate_chain(&self) -> Result<CertChain> {
        self.chain_of(&self.keys)
    }

    /// The chain with the slot certificates of `roles` alone, deriving no other key
    fn chain_of(&self, roles: &[KeyRole]) -> Result<CertChain> {
        let root_key = self.root_key()?;
        let root = self.root_certificate()?;
        let root_dn = root.tbs_certificate().subject().clone();

        // Optional issuing authority, one per device and generation
        let issuing = if self.intermediate {
            let key = self.issuing_key()?;
            let tag = self.issuing_tag()?;
            let subject = self.identity.issuing_dn(tag)?;
            let cert = issue(
                PivIssuingCa { subject, issuer: root_dn.clone(), crl: self.root_list_url()? },
                Self::ca_validity(self.path.creation_time())?,
                key.spki()?,
                root_key,
            )?;
            Some((key, cert, self.list_url(&list_suffix(self.algorithm, Some(tag)))?))
        } else {
            None
        };

        // Each certificate names the list of the authority that issued it: the root's, or the
        // issuing authority's own, which revokes nothing (see `issuing_revocation_list`)
        let (issuer_key, issuer_dn, crl) = match &issuing {
            Some((key, cert, url)) => (*key, cert.tbs_certificate().subject().clone(), url.clone()),
            None => (root_key, root_dn, self.root_list_url()?),
        };

        let validity = self.validity()?;
        let mut leaves = Vec::with_capacity(roles.len());
        for &role in roles {
            let key = self.role_key(role)?;
            let profile = PivLeaf {
                subject: self.identity.user_dn()?,
                issuer: issuer_dn.clone(),
                role: SlotRole::from(role),
                alternatives: self.alternatives.clone(),
                crl: crl.clone(),
            };
            let cert = issue(profile, validity, key.spki()?, issuer_key)?;
            leaves.push((self.slot_of(role), cert));
        }

        Ok(CertChain { root, intermediate: issuing.map(|(_, cert, _)| cert), leaves })
    }

    /// The 9E certificate of the card with this serial: its card authentication key,
    /// certified by itself
    ///
    /// The card seed holds no authority of the identity's, and needs none: the certificate
    /// says which card this is, and whoever relies on that pins the key it carries, the way
    /// a door reader enrols a card. Created at the epoch, like every derivation without a
    /// date, and never expiring, since the card it names does not change.
    pub fn card_authentication_certificate(
        &self,
        algorithm: Algorithm,
        serial: &CardSerial,
    ) -> Result<X509Certificate> {
        let key = self.card_authentication_key(algorithm, serial)?;
        self.card_authentication_certificate_of(&key, serial)
    }

    /// The 9E certificate of the card with this serial, for its card authentication key
    pub(super) fn card_authentication_certificate_of(
        &self,
        key: &SlotKey,
        serial: &CardSerial,
    ) -> Result<X509Certificate> {
        let key = IssuerKey::try_from(key)?;
        let subject = card_dn(&self.card_id(serial)?)?;
        issue(
            PivLeaf {
                subject: subject.clone(),
                issuer: subject,
                role: SlotRole::CardAuthentication,
                alternatives: vec![],
                crl: None,
            },
            Self::ca_validity(seed::epoch_creation())?,
            key.spki()?,
            &key,
        )
    }

    /// The root authority's certificate alone, which names the identity
    pub fn root_certificate(&self) -> Result<X509Certificate> {
        let key = self.root_key()?;
        issue(
            PivRootCa {
                subject: self.identity.root_dn(self.algorithm)?,
                // Fixed, so that the root an identity keeps for good is one certificate
                // whether or not a device of it has an issuing authority below the root
                path_len: 1,
            },
            Self::ca_validity(self.identity_time())?,
            key.spki()?,
            key,
        )
    }

    /// The slot certificate a usable key gets, as the chain issues it
    pub(super) fn leaf(&self, role: KeyRole) -> Result<X509Certificate> {
        if !self.keys.contains(&role) {
            bail!("The {role} key is not among the chosen keys");
        }
        let (_, cert) = self.chain_of(&[role])?.leaves.remove(0);
        Ok(cert)
    }

    /// A revocation list, PEM encoded and signed by the identity's root authority, with the
    /// revocations of `previous` and this one's
    ///
    /// With an issuing authority, the list revokes it, and with it every certificate it
    /// issued for this device and generation. Without one it revokes the chosen keys'
    /// certificates: for `subkeys` only the device's own, the decryption key's only when it
    /// is chosen alone, since every card of the identity holds it; for `certificate` all of
    /// them. A root authority cannot revoke itself, so retiring the whole identity also means
    /// taking its root out of every trust store.
    ///
    /// A list published at a URL has to hold every revocation so far, and this tool keeps no
    /// state: the published list is the state, read back as `previous`, in PEM or DER.
    pub fn revocation_list(
        &self,
        kind: RevocationKind,
        code: u8,
        previous: Option<&[u8]>,
    ) -> Result<String> {
        let previous = previous.map(parse_list).transpose()?;
        let root = self.root_certificate()?;
        // An issuing authority is revoked with everything it issued, so the slot keys need
        // not be derived for it
        let chain = match self.intermediate {
            true => self.chain_of(&[])?,
            false => self.generate_chain()?,
        };
        let decryption_alone = self.keys == [KeyRole::Decryption];

        let serials: Vec<_> = match &chain.intermediate {
            Some(intermediate) => vec![intermediate.tbs_certificate().serial_number().clone()],
            None => self
                .keys
                .iter()
                .zip(&chain.leaves)
                .filter(|(role, _)| {
                    kind == RevocationKind::Certificate
                        || role.is_device_bound()
                        || decryption_alone
                })
                .map(|(_, (_, cert))| cert.tbs_certificate().serial_number().clone())
                .collect(),
        };
        if serials.is_empty() {
            bail!(
                "Every chosen key is shared by every card of the identity; there is nothing to \
                 revoke for this device alone. Revoke the decryption key with --key decryption"
            );
        }
        if kind == RevocationKind::Certificate {
            log::warn!(
                "A root authority cannot revoke itself: take it out of every trust store as well"
            );
        }

        let reason = match Reason::of(code) {
            Some(Reason::Superseded) => CrlReason::Superseded,
            Some(Reason::Compromised) => CrlReason::KeyCompromise,
            Some(Reason::Retired) => CrlReason::CessationOfOperation,
            Some(Reason::Unspecified) | None => CrlReason::Unspecified,
        };
        let now = self.signing_time(previous.as_ref())?;
        let issuer = root.tbs_certificate().subject().clone();
        let mut revoked = self.revoked_so_far(previous.as_ref())?;
        for serial_number in serials {
            if revoked
                .iter()
                .any(|entry| entry.serial_number == serial_number)
            {
                continue;
            }
            revoked.push(RevokedCert {
                serial_number,
                revocation_date: now,
                crl_entry_extensions: Some(vec![reason.to_extension(&issuer, &[])?]),
            });
        }
        self.sign_revocation_list(revoked, now)
    }

    /// The revocation list as it stands, signed afresh: `previous` with a new date, or an
    /// empty one to publish before anything is revoked
    ///
    /// A verifier that finds no list at the URL its certificates name may refuse them, and
    /// one whose cached list has passed its next update refetches; both need a list there.
    pub fn current_revocation_list(&self, previous: Option<&[u8]>) -> Result<String> {
        let previous = previous.map(parse_list).transpose()?;
        let now = self.signing_time(previous.as_ref())?;
        let revoked = self.revoked_so_far(previous.as_ref())?;
        self.sign_revocation_list(revoked, now)
    }

    /// When a list is signed: now, by a clock that has to be plausible, since the list
    /// carries the time and its number is made of it
    ///
    /// An air-gapped machine has no time server, and a clock that was never set reads
    /// whatever the hardware keeps; one that reads before the identity or before the list it
    /// replaces is surely wrong, and would sign a list that verifiers take for an old one.
    fn signing_time(&self, previous: Option<&RevocationList>) -> Result<Time> {
        let now = revocation_time()?;
        let mut floor = self.identity_time();
        if let Some(list) = previous {
            floor = floor.max(list.tbs_cert_list.this_update.to_system_time());
        }
        if now.to_system_time() < floor {
            bail!(
                "The clock reads {}, before the identity or the previous revocation list; set \
                 it (`date -s`) before signing a list",
                humantime::format_rfc3339_seconds(now.to_system_time())
            );
        }
        Ok(now)
    }

    /// The entries of a list this identity's root signed, refused when another signed it
    ///
    /// Every signature here is deterministic, so signing the list's content again and
    /// comparing proves it is the root's without a verifier.
    fn revoked_so_far(&self, previous: Option<&RevocationList>) -> Result<Vec<RevokedCert>> {
        let Some(list) = previous else {
            return Ok(Vec::new());
        };
        let root = self.root_certificate()?;
        let tbs = &list.tbs_cert_list;
        if tbs.issuer != *root.tbs_certificate().subject()
            || self.root_key()?.sign(&tbs.to_der()?)? != list.signature.raw_bytes()
        {
            bail!(
                "The previous revocation list was not signed by this identity's root authority; \
                 it is left as it is"
            );
        }
        Ok(tbs.revoked_certificates.clone().unwrap_or_default())
    }

    /// Sign the root's revocation list holding `revoked`, dated `now`
    fn sign_revocation_list(&self, revoked: Vec<RevokedCert>, now: Time) -> Result<String> {
        let root = self.root_certificate()?;
        // A list at a URL is refetched when it says it is due; one handed over by hand is
        // never due. A year is how often the air-gapped side is asked to sign it again.
        let next_update = match &self.list_stem {
            Some(_) => Time::try_from(now.to_system_time() + REVOCATION_LIST_PERIOD)?,
            None => Time::INFINITY,
        };
        sign_list(self.root_key()?, &root, revoked, now, next_update)
    }

    /// What tells the root's revocation list from the identity's other lists, in its URL and
    /// its file name: the algorithm, as in `-p256`
    ///
    /// Each algorithm has a root of its own, and with it a list of its own, so two algorithms
    /// of one identity given one `--crl-url` still publish two lists.
    pub fn revocation_list_suffix(&self) -> String {
        list_suffix(self.algorithm, None)
    }

    /// Where the list with `suffix` is published: the stem `--crl-url` names, with the suffix,
    /// `jane.crl` naming `jane-p256.crl` for the root's and `jane-p256-issuing-9b3e5d17.crl`
    /// for an issuing authority's
    fn list_url(&self, suffix: &str) -> Result<Option<der::asn1::Ia5String>> {
        let Some(stem) = &self.list_stem else {
            return Ok(None);
        };
        Ok(Some(der::asn1::Ia5String::new(&format!("{stem}{suffix}.crl"))?))
    }

    /// Where the root's list is published, named by what the root issues itself
    fn root_list_url(&self) -> Result<Option<der::asn1::Ia5String>> {
        self.list_url(&self.revocation_list_suffix())
    }

    /// The issuing authority's revocation list, where `--intermediate` gives one: the suffix
    /// that tells it from the identity's other lists in a URL or a file name (see
    /// [`Self::revocation_list_suffix`]), and the list
    ///
    /// The slot certificates name their issuer's list, as RFC 5280 checks each certificate
    /// against the list of whoever issued it; without one, a verifier that checks
    /// revocation refuses them, revoked or not. Revocation happens a level up, where the
    /// root's list names the issuing authority and everything it issued falls with it, so
    /// this list stays empty for good: it is dated from the authority's own start and never
    /// due, the same bytes however often it is signed, and published once.
    pub fn issuing_revocation_list(&self) -> Result<Option<(String, String)>> {
        if !self.intermediate {
            return Ok(None);
        }
        let chain = self.chain_of(&[])?;
        let issuing = chain
            .intermediate
            .as_ref()
            .ok_or_else(|| anyhow!("No issuing authority in the chain"))?;
        let since = issuing.tbs_certificate().validity().not_before;
        let list = sign_list(self.issuing_key()?, issuing, Vec::new(), since, Time::INFINITY)?;
        Ok(Some((list_suffix(self.algorithm, Some(self.issuing_tag()?)), list)))
    }
}

/// What tells one of an identity's revocation lists from the others, in its URL and its file
/// name alike: the algorithm of the root, `-p256`, and for the issuing authority with this
/// tag the tag in lowercase hex as well, `-p256-issuing-9b3e5d17`, which either takes as it is
///
/// One function for both, so that a list's file is always named as its URL is.
fn list_suffix(algorithm: Algorithm, issuing: Option<u32>) -> String {
    match issuing {
        None => format!("-{algorithm}"),
        Some(tag) => format!("-{algorithm}-issuing-{tag:08x}"),
    }
}

/// A revocation list as RFC 5280 profiles it
type RevocationList = CertificateList<x509_cert::certificate::Rfc5280>;

/// A revocation list read back, in PEM or in DER, as `publish --part crl` writes one or the
/// other
fn parse_list(bytes: &[u8]) -> Result<RevocationList> {
    let bytes = bytes.trim_ascii_start();
    let list = match bytes.starts_with(b"-----BEGIN") {
        true => RevocationList::from_pem(bytes),
        false => RevocationList::from_der(bytes),
    };
    list.map_err(|err| anyhow!("The previous revocation list does not parse: {err}"))
}

/// A revocation list read back from where it was published, as far as telling it from
/// another copy goes
pub struct PublishedList {
    /// Its CRL number, which is the second it was signed in, so the newer list has the greater
    pub number: u64,
    /// The list itself, in DER whichever form it was read in
    pub der: Vec<u8>,
    /// The serials it revokes
    pub revoked: Vec<SerialNumber>,
}

/// Read a revocation list back in PEM or DER, for its number and what it revokes
pub fn read_revocation_list(bytes: &[u8]) -> Result<PublishedList> {
    use der::oid::AssociatedOid;

    let list = parse_list(bytes)?;
    let tbs = &list.tbs_cert_list;
    let extension = tbs
        .crl_extensions
        .iter()
        .flatten()
        .find(|extension| extension.extn_id == CrlNumber::OID)
        .ok_or_else(|| anyhow!("The revocation list carries no CRL number"))?;
    let number = CrlNumber::from_der(extension.extn_value.as_bytes())?;
    let digits = number.0.as_bytes();
    let digits = &digits[digits.iter().take_while(|digit| **digit == 0).count()..];
    if digits.len() > 8 {
        bail!("The revocation list's number is no second a list was signed in");
    }
    let mut wide = [0u8; 8];
    wide[8 - digits.len()..].copy_from_slice(digits);
    Ok(PublishedList {
        number: u64::from_be_bytes(wide),
        der: list.to_der()?,
        revoked: tbs
            .revoked_certificates
            .iter()
            .flatten()
            .map(|entry| entry.serial_number.clone())
            .collect(),
    })
}

/// Sign a revocation list as `issuer`, holding `revoked`, dated `this_update`
fn sign_list(
    key: &IssuerKey,
    issuer: &X509Certificate,
    revoked: Vec<RevokedCert>,
    this_update: Time,
    next_update: Time,
) -> Result<String> {
    let algorithm = key.signature_algorithm()?;
    // RFC 5280 5.2.1 and 5.2.3: a list names the key it is signed with, and carries a number
    // that tells the newer of two lists; nothing keeps a counter here, so the number is the
    // second the list is dated, which only grows
    let name = issuer.tbs_certificate().subject();
    let authority = AuthorityKeyIdentifier::try_from(
        issuer
            .tbs_certificate()
            .subject_public_key_info()
            .owned_to_ref(),
    )?;
    let seconds = this_update.to_unix_duration().as_secs();
    let number = CrlNumber(der::asn1::Uint::new(&seconds.to_be_bytes())?);
    let extensions = vec![
        authority.to_extension(name, &[])?,
        number.to_extension(name, &[])?,
    ];
    let tbs = TbsCertList {
        version: x509_cert::Version::V2,
        signature: algorithm.clone(),
        issuer: name.clone(),
        this_update,
        next_update: Some(next_update),
        revoked_certificates: (!revoked.is_empty()).then_some(revoked),
        crl_extensions: Some(extensions),
    };
    let signature = key.sign(&tbs.to_der()?)?;
    let list = CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: algorithm,
        signature: der::asn1::BitString::from_bytes(&signature)?,
    };
    Ok(list.to_pem(der::pem::LineEnding::default())?)
}

/// How long a published revocation list stays current: a year
const REVOCATION_LIST_PERIOD: std::time::Duration = std::time::Duration::from_secs(365 * 86_400);

/// When a revocation is made, in whole seconds: not derived, since the list says when the
/// keys stopped being trusted, which is now
fn revocation_time() -> Result<Time> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    Ok(Time::try_from(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(now))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The issuing authority's common name adds the most to the name, so the one bound fits
    /// every root as well
    #[test]
    fn the_issuing_authority_adds_the_most() {
        use clap::ValueEnum;
        let identity = SubjectName { name: "x".into(), ..Default::default() };
        let added = |name: Name| name.to_string().chars().count() - "CN=x".len();
        assert_eq!(added(identity.issuing_dn(u32::MAX).unwrap()), LONGEST_ADDITION);
        for algorithm in Algorithm::value_variants() {
            let root = identity.root_dn(*algorithm).unwrap();
            assert!(added(root) < LONGEST_ADDITION, "{algorithm}");
        }
        assert_eq!(NAME_BOUND, 40);
    }
}
