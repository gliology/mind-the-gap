use mind_the_gap::piv::{CertificateKind, SeededSmartcard, SlotRole};
use mind_the_gap::seed::{Algorithm, KeyPath, Seed256, Seeds};

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, VerifyingKey};

use x509_cert::Certificate;
use x509_cert::der::Encode;
use x509_cert::ext::pkix::{ExtendedKeyUsage, KeyUsage};

use yubikey::piv::SlotId;

mod chain;
mod external;
#[path = "../common/frozen.rs"]
mod frozen;
mod golden;
#[path = "../common/hex.rs"]
mod hex;
mod paths;

const SEED_A: Seed256 = [1u8; 32];
const SEED_B: Seed256 = [2u8; 32];

/// The slots a chain certifies, in chain order: the identity's three usable keys, the card's
/// own 9E key being the card seed's and outside the chain
const SLOTS: [(SlotId, SlotRole); 3] = [
    (SlotId::Authentication, SlotRole::Authentication),
    (SlotId::Signature, SlotRole::Signature),
    (SlotId::KeyManagement, SlotRole::KeyManagement),
];

/// A builder on one seed in both roles, along `path`
fn on_path(seed: &Seed256, path: KeyPath, name: &str, email: &str) -> SeededSmartcard {
    SeededSmartcard::new(Seeds::one(seed), path, name.into())
        .add_email(email)
        .unwrap()
}

/// A builder on one seed in both roles, without a subkey id or a date
fn builder(seed: &Seed256, name: &str, email: &str) -> SeededSmartcard {
    on_path(seed, KeyPath::default(), name, email)
}

fn alice() -> SeededSmartcard {
    builder(&SEED_A, "Alice", "alice@example.com")
}

/// Alice's builder on a device, without a date
fn device(id: &str) -> SeededSmartcard {
    on_path(&SEED_A, KeyPath { subkey: Some(id.into()), date: None }, "Alice", "alice@example.com")
}

/// SHA-256 over the DER encoding, the same identity `check` compares on
fn digest(cert: &Certificate) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(cert.to_der().unwrap()).to_vec()
}

/// The one URL a certificate's CRL distribution point names
fn list_url(cert: &Certificate) -> String {
    use x509_cert::ext::pkix::CrlDistributionPoints;
    use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};

    let (_, points) = cert
        .tbs_certificate()
        .get_extension::<CrlDistributionPoints>()
        .unwrap()
        .expect("the certificate names no revocation list");
    let [point] = points.0.as_slice() else {
        panic!("not one distribution point: {points:?}");
    };
    let Some(DistributionPointName::FullName(names)) = &point.distribution_point else {
        panic!("the distribution point has no full name: {point:?}");
    };
    let [GeneralName::UniformResourceIdentifier(url)] = names.as_slice() else {
        panic!("the distribution point is not one URL: {names:?}");
    };
    url.to_string()
}

/// `id-ecPublicKey`, the SPKI algorithm of every P-256 key (RFC 5480)
const ID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
/// `ecdsa-with-SHA256` (RFC 5758)
const ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
/// `ecdsa-with-SHA384` (RFC 5758)
const ECDSA_WITH_SHA384: &str = "1.2.840.10045.4.3.3";
/// `secp384r1`, the named curve parameter of a P-384 key (RFC 5480)
const SECP384R1: &str = "1.3.132.0.34";
/// `id-Ed25519`, both as key and as signature algorithm (RFC 8410)
const ID_ED25519: &str = "1.3.101.112";
/// `id-X25519` (RFC 8410)
const ID_X25519: &str = "1.3.101.110";
/// `rsaEncryption`, the SPKI algorithm of every RSA key (RFC 8017)
const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
/// `sha256WithRSAEncryption`, PKCS#1 v1.5 over SHA-256 (RFC 8017)
const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";

/// Verify that `issuer` really signed `cert`, in whichever algorithm the issuer uses
fn verifies_under(cert: &Certificate, issuer: &Certificate) -> bool {
    let spki = issuer.tbs_certificate().subject_public_key_info();
    let point = spki.subject_public_key.raw_bytes();
    let tbs = cert.tbs_certificate().to_der().unwrap();

    match spki.algorithm.oid.to_string().as_str() {
        // Both NIST curves share the key algorithm; the uncompressed point's width tells them
        // apart (1 + 2 * 48 bytes on P-384)
        ID_EC_PUBLIC_KEY if point.len() == 97 => {
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
                .unwrap_or_else(|_| panic!("issuer SPKI is not a P-384 point: {spki:?}"));
            let signature =
                p384::ecdsa::DerSignature::from_bytes(cert.signature().raw_bytes()).unwrap();
            key.verify(&tbs, &signature).is_ok()
        }
        ID_EC_PUBLIC_KEY => {
            let key = VerifyingKey::from_sec1_bytes(point)
                .unwrap_or_else(|_| panic!("issuer SPKI is not a P-256 point: {spki:?}"));
            let signature = DerSignature::from_bytes(cert.signature().raw_bytes()).unwrap();
            key.verify(&tbs, &signature).is_ok()
        }
        ID_ED25519 => {
            let key = ed25519_dalek::VerifyingKey::from_bytes(point.try_into().unwrap())
                .unwrap_or_else(|_| panic!("issuer SPKI is not an Ed25519 point: {spki:?}"));
            let signature =
                ed25519_dalek::Signature::from_slice(cert.signature().raw_bytes()).unwrap();
            key.verify(&tbs, &signature).is_ok()
        }
        RSA_ENCRYPTION => {
            use rsa::pkcs8::DecodePublicKey;
            use rsa::signature::Verifier as _;
            let key = rsa::RsaPublicKey::from_public_key_der(&spki.to_der().unwrap()).unwrap();
            let key = rsa::pkcs1v15::VerifyingKey::<rsa::sha2::Sha256>::new(key);
            let signature =
                rsa::pkcs1v15::Signature::try_from(cert.signature().raw_bytes()).unwrap();
            key.verify(&tbs, &signature).is_ok()
        }
        other => panic!("issuer SPKI is on an unexpected algorithm: {other}"),
    }
}

/// The SPKI and signature algorithm identifiers of a certificate
fn algorithms(cert: &Certificate) -> (String, String) {
    (
        cert.tbs_certificate()
            .subject_public_key_info()
            .algorithm
            .oid
            .to_string(),
        cert.signature_algorithm().oid.to_string(),
    )
}

fn key_usage(cert: &Certificate) -> KeyUsage {
    cert.tbs_certificate()
        .get_extension::<KeyUsage>()
        .unwrap()
        .expect("key usage is always present")
        .1
}

fn extended_key_usage(cert: &Certificate) -> Vec<String> {
    cert.tbs_certificate()
        .get_extension::<ExtendedKeyUsage>()
        .unwrap()
        .expect("extended key usage is always present on leaves")
        .1
        .0
        .iter()
        .map(|oid| oid.to_string())
        .collect()
}

// --- Algorithms and separation -----------------------------------------------

/// `--algorithm curve25519` switches the whole chain: Ed25519 authorities signing Ed25519 slot
/// keys, with X25519 in the key management slot, and every signature verifies.
#[test]
fn curve25519_chain_is_ed25519_and_x25519_throughout() {
    let chain = alice()
        .with_algorithm(Algorithm::Curve25519)
        .with_intermediate(true)
        .certify(CertificateKind::Chain)
        .unwrap();

    assert_eq!(algorithms(&chain.root), (ID_ED25519.into(), ID_ED25519.into()));
    let issuer = chain.issuer();
    assert_eq!(algorithms(issuer), (ID_ED25519.into(), ID_ED25519.into()));
    assert!(verifies_under(&chain.root, &chain.root), "root is not self-signed");
    assert!(verifies_under(issuer, &chain.root), "issuing CA is not signed by the root");

    for (slot, cert) in &chain.leaves {
        let expected = match slot {
            SlotId::KeyManagement => ID_X25519,
            _ => ID_ED25519,
        };
        assert_eq!(
            algorithms(cert),
            (expected.into(), ID_ED25519.into()),
            "{slot:?} slot has the wrong algorithms"
        );
        assert!(verifies_under(cert, issuer), "{slot:?} slot is not signed by the issuer");
    }
}

/// `--algorithm rsa2048` switches the whole chain to RSA: authorities, every slot, and
/// PKCS#1 v1.5 signatures that verify.
#[test]
fn rsa_chain_is_rsa_throughout() {
    let chain = alice()
        .with_algorithm(Algorithm::Rsa2048)
        .with_intermediate(true)
        .certify(CertificateKind::Chain)
        .unwrap();

    let rsa = (RSA_ENCRYPTION.to_string(), SHA256_WITH_RSA.to_string());
    assert_eq!(algorithms(&chain.root), rsa);
    let issuer = chain.issuer();
    assert_eq!(algorithms(issuer), rsa);
    assert!(verifies_under(&chain.root, &chain.root), "root is not self-signed");
    assert!(verifies_under(issuer, &chain.root), "issuing CA is not signed by the root");

    for (slot, cert) in &chain.leaves {
        assert_eq!(algorithms(cert), rsa, "{slot:?} slot has the wrong algorithms");
        assert!(verifies_under(cert, issuer), "{slot:?} slot is not signed by the issuer");
    }

    // An RSA key management key transports keys rather than agreeing on them
    let (slot, cert) = &chain.leaves[2];
    assert_eq!(*slot, SlotId::KeyManagement);
    let usage = key_usage(cert);
    assert!(usage.key_encipherment() && !usage.key_agreement());
}

/// The modulus follows the algorithm: each size derives a key of exactly that many bits.
#[test]
fn rsa_sizes_reach_the_certificates() {
    for (algorithm, bits) in [
        (Algorithm::Rsa2048, 2048),
        (Algorithm::Rsa3072, 3072),
        (Algorithm::Rsa4096, 4096),
    ] {
        use rsa::pkcs8::DecodePublicKey;
        use rsa::traits::PublicKeyParts;
        let chain = alice()
            .with_algorithm(algorithm)
            .certify(CertificateKind::Root)
            .unwrap();
        let spki = chain
            .root
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .unwrap();
        let key = rsa::RsaPublicKey::from_public_key_der(&spki).unwrap();
        assert_eq!(key.n().bits(), bits, "{algorithm:?}");
    }
}

/// The default chain stays P-256 end to end, so the algorithm flag changes nothing unasked.
#[test]
fn default_chain_is_p256_throughout() {
    let chain = alice().certify(CertificateKind::Chain).unwrap();

    assert_eq!(algorithms(&chain.root), (ID_EC_PUBLIC_KEY.into(), ECDSA_WITH_SHA256.into()));
    for (slot, cert) in &chain.leaves {
        assert_eq!(
            algorithms(cert),
            (ID_EC_PUBLIC_KEY.into(), ECDSA_WITH_SHA256.into()),
            "{slot:?} slot has the wrong algorithms"
        );
    }
}

/// `--algorithm p384` switches the whole chain to ECDSA P-384 with SHA-384 signatures, the
/// key management slot included, and every signature verifies.
#[test]
fn p384_chain_is_ecdsa_p384_throughout() {
    let chain = alice()
        .with_algorithm(Algorithm::P384)
        .with_intermediate(true)
        .certify(CertificateKind::Chain)
        .unwrap();

    let issuer = chain.issuer();
    assert!(verifies_under(&chain.root, &chain.root), "root is not self-signed");
    assert!(verifies_under(issuer, &chain.root), "issuing CA is not signed by the root");

    for cert in chain.iter() {
        assert_eq!(algorithms(cert), (ID_EC_PUBLIC_KEY.into(), ECDSA_WITH_SHA384.into()));
        let parameters = cert
            .tbs_certificate()
            .subject_public_key_info()
            .algorithm
            .parameters
            .as_ref()
            .unwrap()
            .decode_as::<x509_cert::der::asn1::ObjectIdentifier>()
            .unwrap();
        assert_eq!(parameters.to_string(), SECP384R1);
    }
    for (slot, cert) in &chain.leaves {
        assert!(verifies_under(cert, issuer), "{slot:?} slot is not signed by the issuer");
    }
}

/// The algorithms derive under different labels, so no key appears in two chains.
#[test]
fn curves_share_no_keys() {
    let spkis = |algorithm| {
        let chain = alice()
            .with_algorithm(algorithm)
            .certify(CertificateKind::Chain)
            .unwrap();
        chain
            .iter()
            .map(|cert| {
                cert.tbs_certificate()
                    .subject_public_key_info()
                    .subject_public_key
                    .raw_bytes()
                    .to_vec()
            })
            .collect::<Vec<_>>()
    };

    let chains = [
        Algorithm::P256,
        Algorithm::P384,
        Algorithm::Curve25519,
        Algorithm::Rsa2048,
    ]
    .map(spkis);
    for (i, a) in chains.iter().enumerate() {
        for b in &chains[i + 1..] {
            // Compared on the raw key bits: the algorithm identifiers differ anyway
            assert!(a.iter().all(|key| !b.contains(key)), "a key appears under two algorithms");
        }
    }
}

#[test]
fn certify_differs_by_seed() {
    let a = alice().certify(CertificateKind::Chain).unwrap();
    let b = builder(&SEED_B, "Alice", "alice@example.com")
        .certify(CertificateKind::Chain)
        .unwrap();

    assert_ne!(digest(&a.root), digest(&b.root));
    assert_ne!(digest(&a.leaves[0].1), digest(&b.leaves[0].1));
}

/// A device's own keys move with the subkey id; the root authority, which is the identity,
/// and the decryption key, which every card of the identity shares, do not
#[test]
fn certify_differs_by_subkey() {
    let a = alice().certify(CertificateKind::Chain).unwrap();
    let b = device("work").certify(CertificateKind::Chain).unwrap();

    assert_eq!(digest(&a.root), digest(&b.root));
    for index in [0, 1] {
        assert_ne!(
            digest(&a.leaves[index].1),
            digest(&b.leaves[index].1),
            "{:?}",
            a.leaves[index].0
        );
    }
    assert_eq!(a.leaves[2].0, SlotId::KeyManagement);
    assert_eq!(digest(&a.leaves[2].1), digest(&b.leaves[2].1));
}

#[test]
fn certify_differs_by_name() {
    let a = alice().certify(CertificateKind::Chain).unwrap();
    let b = builder(&SEED_A, "Bob", "alice@example.com")
        .certify(CertificateKind::Chain)
        .unwrap();

    assert_ne!(digest(&a.root), digest(&b.root));
}
