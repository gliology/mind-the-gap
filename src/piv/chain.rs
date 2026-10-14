//! The X.509 chain: subject names, the authorities and the slot certificates.
//!
//! Part of the frozen `mtg1` derivation, like `keys`: certificates are compared byte for
//! byte with what a card holds.

use std::str::FromStr;
use std::time::{Duration, SystemTime};

use super::{CertificateKind, SeededSmartcard, SlotRole};
use crate::seed::{self, Algorithm, Seed256, Seed256Derive};

use anyhow::{Result, anyhow};

use yubikey::piv::SlotId;

use p256::ecdsa::{DerSignature, SigningKey};

use rsa::RsaPrivateKey;
use rsa::pkcs1v15::{Signature as RsaSignature, SigningKey as RsaSigningKey};
use rsa::sha2::Sha256 as RsaSha256;

use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
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

use der::EncodePem;

use spki::{ObjectIdentifier, SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};

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

impl SubjectName {
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
    Rsa(Box<RsaSigningKey<RsaSha256>>),
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
            Algorithm::Rsa2048 | Algorithm::Rsa3072 | Algorithm::Rsa4096 => {
                let bits = algorithm.rsa_bits().expect("an RSA algorithm");
                let key = crate::rsa::derive_key(&parent.derive(Some(&label)), bits)?;
                Ok(IssuerKey::Rsa(Box::new(RsaSigningKey::new(key))))
            }
        }
    }

    /// The public half, as it goes into the authority's own certificate
    pub(super) fn spki(&self) -> Result<SubjectPublicKeyInfoOwned> {
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

        // Deliberately no basic constraints: x509-cert always marks them critical and the
        // NIST PIV end-entity profile omits the extension entirely.
        Ok(extensions)
    }
}

impl SeededSmartcard {
    /// Generate the full certificate chain, without touching a card
    pub fn certify(&self, kind: CertificateKind) -> Result<CertChain> {
        // `kind` only selects what is exported later, but validate it eagerly so that
        // `--kind intermediate` without `--intermediate` fails before doing the work.
        let chain = self.generate_chain()?;
        chain.select(kind)?;
        Ok(chain)
    }

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

    /// Derive the whole chain from the seed, without touching a card
    pub(super) fn generate_chain(&self) -> Result<CertChain> {
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
        let live = SlotRole::ALL
            .into_iter()
            .map(|role| (role.slot(), role, None));
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
}
