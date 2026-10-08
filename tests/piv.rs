use mind_the_gap::piv::{CertificateKind, SeededSmartcard, SharedSlot, SlotRole};
use mind_the_gap::seed::{Algorithm, Seed256};

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, VerifyingKey};

use x509_cert::Certificate;
use x509_cert::der::{Encode, EncodePem};
use x509_cert::ext::pkix::AuthorityKeyIdentifier;
use x509_cert::ext::pkix::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAltName, SubjectKeyIdentifier,
};

use std::time::{Duration, SystemTime};

use yubikey::piv::{RetiredSlotId, SlotId};

const SEED_A: Seed256 = [1u8; 32];
const SEED_B: Seed256 = [2u8; 32];

const SLOTS: [(SlotId, SlotRole); 4] = [
    (SlotId::Authentication, SlotRole::Authentication),
    (SlotId::Signature, SlotRole::Signature),
    (SlotId::KeyManagement, SlotRole::KeyManagement),
    (SlotId::CardAuthentication, SlotRole::CardAuthentication),
];

fn builder(seed: &Seed256, name: &str, email: &str) -> SeededSmartcard {
    SeededSmartcard::new(seed, None, name.into())
        .add_email(email)
        .unwrap()
        .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
}

fn alice() -> SeededSmartcard {
    builder(&SEED_A, "Alice", "alice@example.com")
}

/// SHA-256 over the DER encoding, the same identity `check` compares on
fn digest(cert: &Certificate) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(cert.to_der().unwrap()).to_vec()
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

// --- Determinism -------------------------------------------------------------

#[test]
fn certify_is_deterministic() {
    let a = alice().certify(CertificateKind::Chain).unwrap();
    let b = alice().certify(CertificateKind::Chain).unwrap();

    assert_eq!(digest(&a.root), digest(&b.root));
    for ((slot, left), (_, right)) in a.leaves.iter().zip(b.leaves.iter()) {
        assert_eq!(digest(left), digest(right), "{slot:?} slot is not reproducible");
    }
}

/// The current `mtg1` scheme is frozen.
///
/// The 1.x versioning promise is that any release re-derives the very same keys -- and,
/// because `check` compares certificates byte for byte, the very same certificates -- from
/// a seed. These vectors are that promise in executable form: a change to a label constant,
/// a prefix, the argon2 parameters, the certificate profile or its encoding would pass
/// every other test while making `check` fail against every provisioned card, and this
/// test is what fails instead. The SPKI digests pin the derived *keys*, the certificate
/// digests pin the *encoding* around them, so a failure says which of the two moved. Do
/// not update these values within a major version; a derivation change ships as `mtg2`
/// behind a new major.
#[test]
fn current_scheme_is_frozen() {
    assert_current_scheme_frozen(
        Algorithm::P256,
        [
            (
                None,
                [
                    (
                        "ab8c5adc194c66ed2163f08d4606a753133005840f5e5448f602a0af93bd6cf4",
                        "861b8296ec2ebe1cb370b18db1e0ade1bc55b4eeb7f117aee85e7260be782c08",
                        "CN=Alice PIV Root CA",
                    ),
                    (
                        "c55a30e8647a8912b07ba6f76d6abb6fcb4efad9dfaa0f7d691320d64c11d6ea",
                        "15c3cd1d34a5be9499f195b6f0a6daa0455b28f15f419335e0bc67a0a8a07c0f",
                        "CN=Alice",
                    ),
                    (
                        "ec7e41c73cd76ec8b7283332a0202a775dbf616096d05d18732ff0a211dfc0b1",
                        "f97b5ee9339aa13a79ff5fe962261c0e6fcff9760d5c96a0043410eb554c8de6",
                        "CN=Alice",
                    ),
                    (
                        "db4389e005f73edf3cfa500c81c9e28683c4beae122192c2ee21ebaedf2fdd00",
                        "6e764fe53fc1c906afc7cf2c215d9c07355fd7d84bdf6600ce91d993f54e38e4",
                        "CN=Alice",
                    ),
                    (
                        "93d0d7b044eb08ad6f62a20668e1f17b0838dc918c472a9cd7020d223f3970c3",
                        "5c2d5504506e5eafec3a6e1d86d6623ccbaca96f6e1d51ab3b89d3204d0c986b",
                        "CN=PIV Card mtg1:5D168619",
                    ),
                ],
            ),
            (
                Some("laptop"),
                [
                    (
                        "ab8c5adc194c66ed2163f08d4606a753133005840f5e5448f602a0af93bd6cf4",
                        "861b8296ec2ebe1cb370b18db1e0ade1bc55b4eeb7f117aee85e7260be782c08",
                        "CN=Alice PIV Root CA",
                    ),
                    (
                        "5f22bc03848271a3b6e524b9e327eaceef0ae31b379ffa4bb3511bb3f189eda7",
                        "d004f480344e9ea8d889cffd004158c1027ba2def6d116a3c08fa6a291d594d1",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "555ad0a77ef68e4eb556d49551d0a948685077c64956d61fc5bda926c7a751ab",
                        "2765c5a08e03db99b74fb7b82fbefbd564e54083bf669f36529e254c9b2cdf37",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "e274fd327152f629470240f968efc8a42fe133a1b6816a920a03aedf422e0cd3",
                        "fbd4b7ffc16fb0622bdad2d2478976148346d3655cdadcb26ee5c9514b3abe2a",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "d8498196b0d80ec125cc48549465624b0eb9d15f2f35c9d98cedbf434a124036",
                        "36f92866b4769436a85e775eeccf50c7f3b187756c92aac6dc75771e2614bd5e",
                        "CN=PIV Card mtg1:95BCA3CF",
                    ),
                ],
            ),
        ],
    );
}

/// The Curve25519 half of the same promise: `--algorithm curve25519` is part of `mtg1` and
/// frozen with it, Ed25519 signatures included (they are deterministic, so the DER pins).
#[test]
fn current_scheme_is_frozen_on_curve25519() {
    assert_current_scheme_frozen(
        Algorithm::Curve25519,
        [
            (
                None,
                [
                    (
                        "215875f0a056960c48ab72d9031eb87fef9e56935bc74220d96739f7eb0890cc",
                        "614b41693fc5d41a9241b3f900737cb38b46aa82d065301cc50e0fad2a1a2618",
                        "CN=Alice PIV Root CA",
                    ),
                    (
                        "39d78d631f03041f9da16a4588cbfbea092404f25cdadae8895c807307e9cc5e",
                        "fcfe945cff1a90da139c9eec97320eb336630495526a11e94600180e33a0b784",
                        "CN=Alice",
                    ),
                    (
                        "d303bcbb992f935e68ba7ea07f8a846410fe13e58169550c3dae3f61c0209f95",
                        "40fa233d768183c48704c0efe1da9120f6f9a87cecd29edb7ad36b7cbde18c85",
                        "CN=Alice",
                    ),
                    (
                        "d32cf40d03e67f4de0ea55541e673b0c64bb3d1861ebc039735e7684ac5e4791",
                        "5d807a2cc1d5b96848925078c051d0c4a6c10345c1ccb6bf56d1942a3e4a7b85",
                        "CN=Alice",
                    ),
                    (
                        "374b218d39ed4756bd703891fc765fbb75b97e3f3e5a3b110423547a622d1c59",
                        "57f022cbbb2c3c69107fecfbd13b1028fe49fa9c42fcd8412c29c592e6f4c810",
                        "CN=PIV Card mtg1:5D168619",
                    ),
                ],
            ),
            (
                Some("laptop"),
                [
                    (
                        "215875f0a056960c48ab72d9031eb87fef9e56935bc74220d96739f7eb0890cc",
                        "614b41693fc5d41a9241b3f900737cb38b46aa82d065301cc50e0fad2a1a2618",
                        "CN=Alice PIV Root CA",
                    ),
                    (
                        "b29e70e6954f77a46ddbfe461e3b873dd8fdd8df5d93b3b556ad3984dcf72fb4",
                        "e68f98eb34a215c78c965ea92aaee4a6952626aca990bf2fdf3e5fcc856308e1",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "8cfc7e206526f869ef0a551255bcc3267f3be9ff9a6e0900c0a0da6e132568be",
                        "2d70219c85a1a174556eee0cfd9c073cfec06987fb03a499a97fe355c6ac0ca6",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "db0dbbf7d26cdbddc439020ba9e717e24459204e53e7c1597935cb9a10b747a4",
                        "bdd7bdcb938dff7fb1abdbe6f37fb04996775bae0892684e2754082909846fab",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "630220975eccb9267282b921887a9166958e837506053a6a2c7398a59b0a4c5e",
                        "82b30e1aa6300c20d27576494ef2e4dd32c844f9851674077392fb835e504a4a",
                        "CN=PIV Card mtg1:95BCA3CF",
                    ),
                ],
            ),
        ],
    );
}

/// The P-384 third of the same promise: `--algorithm p384` derives under its own labels and the
/// documented 48-byte construction, and is frozen with the rest of `mtg1`. ECDSA signatures
/// use RFC 6979 nonces, so the certificate DER pins as well.
#[test]
fn current_scheme_is_frozen_on_p384() {
    assert_current_scheme_frozen(
        Algorithm::P384,
        [
            (
                None,
                [
                    (
                        "189c2070280dba26725e96dbb16fb86a20b98115c8aeb18c4656c25f262f4187",
                        "b5cc125940a7bd667bfc3fe9035a84ededce92f6918490416183aa869c78a04a",
                        "CN=Alice PIV Root CA",
                    ),
                    (
                        "2b3fd7575f7799de806830f0452b473647b42eab745b117c451460e9e0f56302",
                        "8ebbafc08a686ba6822ef7892a76bb44915c82f2f233853e7e81da9db6de583b",
                        "CN=Alice",
                    ),
                    (
                        "bd7177425a6d6234a9b1872b3cafd4d70e399481bab163e50d2ddf967e6ae175",
                        "9f6b68ef3662a2be96ea69b6973f083ff0ddbe948a51e7e1351077850d814fcc",
                        "CN=Alice",
                    ),
                    (
                        "9430d9eda51e0e30bd85972ce5d6584ef35bb48751a3d631fd514e1b0067ee92",
                        "f9264506cdc9cf78b1dbd707e303e307035141eb49c910d5e7b5322b5c193f96",
                        "CN=Alice",
                    ),
                    (
                        "77f5cf472efe6df02b9ff7a0512488575bd384934d41b1702e8adbc71c733d40",
                        "3b57d967b44279224150515024408d298930d8934eda117b3779e794992fa8a7",
                        "CN=PIV Card mtg1:5D168619",
                    ),
                ],
            ),
            (
                Some("laptop"),
                [
                    (
                        "189c2070280dba26725e96dbb16fb86a20b98115c8aeb18c4656c25f262f4187",
                        "b5cc125940a7bd667bfc3fe9035a84ededce92f6918490416183aa869c78a04a",
                        "CN=Alice PIV Root CA",
                    ),
                    (
                        "aaec61040c30ae1e3fdb62590d4ebde9b3f51856aa183db8e6198a9e079e2251",
                        "3d18d4459c45ec40abc62990509ac1cc2f07d67d08607cd40d9fa4207ae6f231",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "224679124975033922323ddb5121c35da9cf86fc0e068bfe7c7f95476769b712",
                        "014312b4000489bed5bbee0411134ea978489330d9d1d99b3c87c166fa56b030",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "ab47865be4c685cb325786744390d17a36c2cdc910c2cc5b3046b72ec29bba6c",
                        "e0487b0eeac20e62b53e367611c38a79b2f0e89bbd7c6479aa6b3eb4ab99313e",
                        "CN=Alice,DNQUALIFIER=mtg1:laptop",
                    ),
                    (
                        "dd2ae81a0cb116f6b0ca40756d99d0b13ff8a90bae404d2b7d840f7fb19db7d6",
                        "73eb90f051f4d81e19873642a1f80ca7da18f5d868e681ef8c327a59ac4a9906",
                        "CN=PIV Card mtg1:95BCA3CF",
                    ),
                ],
            ),
        ],
    );
}

/// One pinned certificate: its SPKI digest, its DER digest, and its subject
type Pinned = (&'static str, &'static str, &'static str);

/// Assert that `algorithm` still derives exactly `vectors`: for each subkey id, the pins for
/// the root and the four slots
fn assert_current_scheme_frozen(algorithm: Algorithm, vectors: [(Option<&str>, [Pinned; 5]); 2]) {
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    for (id, expected) in vectors {
        let chain = SeededSmartcard::new(&SEED_A, id.map(|v| v.to_string()), "Alice".into())
            .with_algorithm(algorithm)
            .add_email("alice@example.com")
            .unwrap()
            .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
            .certify(CertificateKind::Chain)
            .unwrap();

        let mut certs = vec![(&chain.root, "root")];
        certs.extend(chain.leaves.iter().map(|(slot, cert)| {
            (
                cert,
                match slot {
                    SlotId::Authentication => "9A",
                    SlotId::Signature => "9C",
                    SlotId::KeyManagement => "9D",
                    SlotId::CardAuthentication => "9E",
                    other => panic!("unexpected slot {other:?}"),
                },
            )
        }));

        for ((cert, slot), (spki, der, subject)) in certs.into_iter().zip(expected) {
            let got_spki = hex(&digest_bytes(
                cert.tbs_certificate()
                    .subject_public_key_info()
                    .to_der()
                    .unwrap(),
            ));
            assert_eq!(got_spki, spki, "{slot} KEY moved for {id:?} -- derivation broke");
            assert_eq!(
                hex(&digest(cert)),
                der,
                "{slot} certificate encoding moved for {id:?} -- check will fail on provisioned cards"
            );
            assert_eq!(
                cert.tbs_certificate().subject().to_string(),
                subject,
                "{slot} subject moved for {id:?}"
            );
        }
    }

    fn digest_bytes(der: Vec<u8>) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        Sha256::digest(der).to_vec()
    }
}

#[test]
fn certify_is_deterministic_without_date() {
    // Regression test: Validity::infinity() used to anchor notBefore at SystemTime::now(),
    // so the output was not reproducible unless --date was passed.
    let plain = || {
        SeededSmartcard::new(&SEED_A, None, "Alice".into())
            .add_email("alice@example.com")
            .unwrap()
    };

    let a = plain().certify(CertificateKind::Chain).unwrap();
    let b = plain().certify(CertificateKind::Chain).unwrap();

    assert_eq!(digest(&a.root), digest(&b.root));
    assert_eq!(digest(&a.leaves[0].1), digest(&b.leaves[0].1));
}

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

    let a = spkis(Algorithm::P256);
    let b = spkis(Algorithm::Curve25519);
    let c = spkis(Algorithm::P384);
    for key in &a {
        // Compared on the raw key bits: the algorithm identifiers differ anyway
        assert!(!b.contains(key), "a key appears under both algorithms");
        assert!(!c.contains(key), "a key appears on P-256 and P-384");
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

#[test]
fn certify_differs_by_subkey() {
    let a = alice().certify(CertificateKind::Chain).unwrap();
    let b = SeededSmartcard::new(&SEED_A, Some("work".to_string()), "Alice".into())
        .add_email("alice@example.com")
        .unwrap()
        .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        .certify(CertificateKind::Chain)
        .unwrap();

    // The root authority is shared across subkey generations, the slot keys are not
    assert_eq!(digest(&a.root), digest(&b.root));
    assert_ne!(digest(&a.leaves[0].1), digest(&b.leaves[0].1));
}

#[test]
fn certify_differs_by_name() {
    let a = alice().certify(CertificateKind::Chain).unwrap();
    let b = builder(&SEED_A, "Bob", "alice@example.com")
        .certify(CertificateKind::Chain)
        .unwrap();

    assert_ne!(digest(&a.root), digest(&b.root));
}

// --- Chain shape -------------------------------------------------------------

#[test]
fn chain_is_two_tier_by_default() {
    let chain = alice().certify(CertificateKind::Chain).unwrap();

    assert!(chain.intermediate.is_none());
    assert_eq!(chain.leaves.len(), 4);
    assert_eq!(chain.iter().count(), 5);

    let (_, constraints) = chain
        .root
        .tbs_certificate()
        .get_extension::<BasicConstraints>()
        .unwrap()
        .unwrap();
    assert_eq!(constraints.path_len_constraint, Some(0));
}

#[test]
fn chain_is_three_tier_with_intermediate() {
    let chain = alice()
        .with_intermediate(true)
        .certify(CertificateKind::Chain)
        .unwrap();

    let intermediate = chain.intermediate.as_ref().expect("intermediate requested");
    assert_eq!(chain.iter().count(), 6);

    let root_constraints = chain
        .root
        .tbs_certificate()
        .get_extension::<BasicConstraints>()
        .unwrap()
        .unwrap()
        .1;
    let sub_constraints = intermediate
        .tbs_certificate()
        .get_extension::<BasicConstraints>()
        .unwrap()
        .unwrap()
        .1;

    assert_eq!(root_constraints.path_len_constraint, Some(1));
    assert_eq!(sub_constraints.path_len_constraint, Some(0));

    // The intermediate is signed by the root, the leaves by the intermediate
    assert!(verifies_under(intermediate, &chain.root));
    for (slot, leaf) in &chain.leaves {
        assert!(
            verifies_under(leaf, intermediate),
            "{slot:?} slot is not signed by the intermediate"
        );
    }
}

#[test]
fn certify_intermediate_without_intermediate_fails() {
    assert!(alice().certify(CertificateKind::Intermediate).is_err());
    assert!(
        alice()
            .with_intermediate(true)
            .certify(CertificateKind::Intermediate)
            .is_ok()
    );
}

/// The validity window follows the flags: infinite by default, bounded by --validity.
#[test]
fn validity_window_follows_the_flags() {
    let creation = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
    let ten_years = Duration::from_secs(10 * 365 * 24 * 60 * 60);

    // Default: leaves never expire, matching the promise that a derived certificate can be
    // reproduced years later
    let infinite = alice().certify(CertificateKind::Chain).unwrap();
    for (slot, cert) in &infinite.leaves {
        let validity = cert.tbs_certificate().validity();
        assert_eq!(validity.not_before.to_system_time(), creation, "{slot:?} notBefore moved");
        assert_eq!(
            validity.not_after.to_system_time(),
            x509_cert::time::Time::INFINITY.to_system_time(),
            "{slot:?} should not expire by default"
        );
    }

    // Bounded: --validity sets notAfter relative to the creation time, on the leaves only --
    // the authorities never expire, so a leaf can never outlive its issuer
    let bounded = alice()
        .with_validity_duration(ten_years)
        .certify(CertificateKind::Chain)
        .unwrap();
    for (slot, cert) in &bounded.leaves {
        assert_eq!(
            cert.tbs_certificate().validity().not_after.to_system_time(),
            creation + ten_years,
            "{slot:?} notAfter does not honour --validity"
        );
    }
    assert_eq!(
        bounded
            .root
            .tbs_certificate()
            .validity()
            .not_after
            .to_system_time(),
        x509_cert::time::Time::INFINITY.to_system_time(),
        "the root must never expire"
    );
}

/// `cas()` feeds the msroots object: issuing authority first, trust anchor last.
#[test]
fn cas_orders_the_root_last() {
    let plain = alice().certify(CertificateKind::Chain).unwrap();
    let cas = plain.cas();
    assert_eq!(cas.len(), 1);
    assert_eq!(digest(&cas[0]), digest(&plain.root));

    let tiered = alice()
        .with_intermediate(true)
        .certify(CertificateKind::Chain)
        .unwrap();
    let cas = tiered.cas();
    assert_eq!(cas.len(), 2);
    assert_eq!(digest(&cas[0]), digest(tiered.intermediate.as_ref().unwrap()));
    assert_eq!(digest(&cas[1]), digest(&tiered.root));
}

/// The msroots encoding is a degenerate PKCS#7: SignedData carrying only certificates.
///
/// This is what the Windows minidriver expects to find in the object; until now it was
/// asserted only on real hardware, i.e. never in CI.
#[test]
fn msroots_encodes_a_degenerate_pkcs7() {
    use cms::content_info::ContentInfo;
    use x509_cert::der::{Decode, Encode};

    let chain = alice()
        .with_intermediate(true)
        .certify(CertificateKind::Chain)
        .unwrap();

    let encoded = ContentInfo::try_from(chain.cas())
        .expect("authorities do not form a PKCS#7")
        .to_der()
        .expect("PKCS#7 does not encode");

    // Round-trips as a ContentInfo declaring SignedData
    let decoded = ContentInfo::from_der(&encoded).expect("emitted DER does not parse back");
    assert_eq!(decoded.content_type.to_string(), "1.2.840.113549.1.7.2", "not SignedData");

    // Degenerate: both authorities embedded verbatim, root included
    let intermediate = chain.intermediate.as_ref().unwrap().to_der().unwrap();
    let root = chain.root.to_der().unwrap();
    let haystack = encoded.as_slice();
    let contains = |needle: &[u8]| haystack.windows(needle.len()).any(|w| w == needle);
    assert!(contains(&intermediate), "intermediate certificate missing from msroots");
    assert!(contains(&root), "root certificate missing from msroots");
}

// --- Chain integrity ---------------------------------------------------------

#[test]
fn root_is_self_signed() {
    let chain = alice().certify(CertificateKind::Chain).unwrap();
    let root = &chain.root;

    assert_eq!(root.tbs_certificate().issuer(), root.tbs_certificate().subject());
    assert!(verifies_under(root, root));

    // RFC 5280 4.2.1.1: on a self-signed certificate the AKI mirrors the SKI
    let ski = root
        .tbs_certificate()
        .get_extension::<SubjectKeyIdentifier>()
        .unwrap()
        .unwrap()
        .1;
    let aki = root
        .tbs_certificate()
        .get_extension::<AuthorityKeyIdentifier>()
        .unwrap()
        .unwrap()
        .1;
    assert_eq!(aki.key_identifier, Some(ski.0));
}

#[test]
fn leaves_chain_to_issuer() {
    let chain = alice().certify(CertificateKind::Chain).unwrap();
    let issuer = chain.issuer();

    let issuer_ski = issuer
        .tbs_certificate()
        .get_extension::<SubjectKeyIdentifier>()
        .unwrap()
        .unwrap()
        .1;

    for (slot, leaf) in &chain.leaves {
        assert_eq!(
            leaf.tbs_certificate().issuer(),
            issuer.tbs_certificate().subject(),
            "{slot:?} slot has the wrong issuer name"
        );
        assert_ne!(
            leaf.tbs_certificate().issuer(),
            leaf.tbs_certificate().subject(),
            "{slot:?} slot looks self-signed, which breaks path building"
        );

        let aki = leaf
            .tbs_certificate()
            .get_extension::<AuthorityKeyIdentifier>()
            .unwrap()
            .expect("leaves always carry an authority key identifier")
            .1;
        assert_eq!(
            aki.key_identifier,
            Some(issuer_ski.0.clone()),
            "{slot:?} slot does not point at the issuer's subject key identifier"
        );

        assert!(
            verifies_under(leaf, issuer),
            "{slot:?} slot signature does not verify under the issuer"
        );
    }
}

#[test]
fn dns_are_distinct_across_tiers() {
    let chain = alice()
        .with_intermediate(true)
        .certify(CertificateKind::Chain)
        .unwrap();

    let root = chain.root.tbs_certificate().subject();
    let intermediate = chain
        .intermediate
        .as_ref()
        .unwrap()
        .tbs_certificate()
        .subject();
    let user = chain.leaves[0].1.tbs_certificate().subject();

    assert_ne!(root, intermediate);
    assert_ne!(root, user);
    assert_ne!(intermediate, user);
}

#[test]
fn card_authentication_subject_is_not_person_bound() {
    let chain = alice().certify(CertificateKind::Chain).unwrap();

    let user = chain.leaves[0].1.tbs_certificate().subject().to_string();
    let card = chain.leaves[3].1.tbs_certificate().subject().to_string();

    assert_eq!(chain.leaves[3].0, SlotId::CardAuthentication);
    assert_ne!(user, card);
    assert!(card.contains("PIV Card"), "unexpected card subject: {card}");
}

// --- Extensions --------------------------------------------------------------

#[test]
fn slot_key_usages_are_exact() {
    let chain = alice().certify(CertificateKind::Chain).unwrap();

    for ((slot, cert), (_, role)) in chain.leaves.iter().zip(SLOTS.iter()) {
        let usage = key_usage(cert);
        let eku = extended_key_usage(cert);

        match role {
            SlotRole::Authentication => {
                assert!(usage.digital_signature(), "{slot:?}");
                assert!(!usage.key_agreement(), "{slot:?}");
                assert_eq!(eku, vec!["1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2"], "{slot:?}");
            }
            SlotRole::Signature => {
                assert!(usage.digital_signature(), "{slot:?}");
                assert!(usage.non_repudiation(), "{slot:?}");
                assert_eq!(eku, vec!["1.3.6.1.5.5.7.3.4"], "{slot:?}");
            }
            SlotRole::KeyManagement => {
                // ECDH keys take keyAgreement; keyEncipherment is RSA key transport and
                // makes NSS reject the certificate for S/MIME decryption.
                assert!(usage.key_agreement(), "{slot:?}");
                assert!(!usage.key_encipherment(), "{slot:?}");
                assert!(!usage.encipher_only() && !usage.decipher_only(), "{slot:?}");
                assert_eq!(eku, vec!["1.3.6.1.5.5.7.3.4", "1.3.6.1.5.5.7.3.2"], "{slot:?}");
            }
            SlotRole::CardAuthentication => {
                assert!(usage.digital_signature(), "{slot:?}");
                assert_eq!(eku, vec!["2.16.840.1.101.3.6.8"], "{slot:?}");
            }
        }
    }
}

#[test]
fn ca_certs_are_ca_leaves_are_not() {
    let chain = alice()
        .with_intermediate(true)
        .certify(CertificateKind::Chain)
        .unwrap();

    for ca in [&chain.root, chain.intermediate.as_ref().unwrap()] {
        let (critical, constraints) = ca
            .tbs_certificate()
            .get_extension::<BasicConstraints>()
            .unwrap()
            .expect("authorities carry basic constraints");
        assert!(critical, "basic constraints must be critical on a CA");
        assert!(constraints.ca);

        let usage = key_usage(ca);
        assert!(usage.key_cert_sign());
        assert!(usage.crl_sign());

        // An absent EKU keeps the authority unconstrained across clientAuth,
        // emailProtection and id-PIV-cardAuth
        assert!(
            ca.tbs_certificate()
                .get_extension::<ExtendedKeyUsage>()
                .unwrap()
                .is_none()
        );
    }

    for (slot, leaf) in &chain.leaves {
        assert!(
            leaf.tbs_certificate()
                .get_extension::<BasicConstraints>()
                .unwrap()
                .is_none(),
            "{slot:?} slot should not carry basic constraints"
        );
    }
}

#[test]
fn emails_land_in_subject_alt_name() {
    let chain = alice().certify(CertificateKind::Chain).unwrap();

    for (slot, leaf) in &chain.leaves {
        let san = leaf
            .tbs_certificate()
            .get_extension::<SubjectAltName>()
            .unwrap();

        if *slot == SlotId::CardAuthentication {
            assert!(san.is_none(), "the card slot must not be person bound");
        } else {
            let san = san.expect("user slots carry the email addresses").1;
            assert!(format!("{:?}", san.0).contains("alice@example.com"), "{slot:?}");
        }
    }
}

#[test]
fn no_empty_san() {
    // GeneralNames is a SEQUENCE SIZE (1..MAX), so with no emails the extension has to be
    // omitted rather than encoded empty.
    let chain = SeededSmartcard::new(&SEED_A, None, "Alice".into())
        .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        .certify(CertificateKind::Chain)
        .unwrap();

    for (slot, leaf) in &chain.leaves {
        assert!(
            leaf.tbs_certificate()
                .get_extension::<SubjectAltName>()
                .unwrap()
                .is_none(),
            "{slot:?} slot emitted an empty subject alternative name"
        );
    }
}

#[test]
fn dn_attributes_are_applied_to_every_tier() {
    let chain = alice()
        .with_intermediate(true)
        .with_org("Example Corp".into())
        .with_org_unit("Engineering".into())
        .with_country("DE".into())
        .certify(CertificateKind::Chain)
        .unwrap();

    for cert in chain.iter() {
        let subject = cert.tbs_certificate().subject().to_string();
        assert!(subject.contains("O=Example Corp"), "{subject}");
        assert!(subject.contains("OU=Engineering"), "{subject}");
        assert!(subject.contains("C=DE"), "{subject}");
    }
}

#[test]
fn dn_special_characters_are_escaped() {
    let chain = builder(&SEED_A, "Doe, Jane A+B", "jane@example.com")
        .certify(CertificateKind::Chain)
        .unwrap();

    // Round-trips as a single common name rather than splitting into extra RDNs
    let subject = chain.leaves[0].1.tbs_certificate().subject();
    assert_eq!(subject.iter_rdn().count(), 1);
    assert!(subject.to_string().contains("Doe\\, Jane A\\+B"));
}

// --- Serial numbers ----------------------------------------------------------

#[test]
fn serials_are_distinct_and_positive() {
    let chain = alice()
        .with_intermediate(true)
        .certify(CertificateKind::Chain)
        .unwrap();

    let mut seen = Vec::new();
    for cert in chain.iter() {
        let serial = cert.tbs_certificate().serial_number().as_bytes().to_vec();

        assert!(!serial.is_empty() && serial.len() <= 20, "{serial:?}");
        assert!(serial[0] < 0x80, "serial must be positive: {serial:?}");
        assert!(!seen.contains(&serial), "duplicate serial: {serial:?}");

        seen.push(serial);
    }
    assert_eq!(seen.len(), 6);
}

// --- External validation -----------------------------------------------------

/// NSS accepts the chain for the usages the certificates claim, and refuses the rest.
///
/// NSS is a different validator with different opinions than OpenSSL -- it is what
/// Firefox and Thunderbird actually run -- so passing both is much stronger evidence
/// than passing one twice. This needs no card: `certutil` validates the certificates,
/// and those are derived offline.
#[test]
#[cfg_attr(not(has_certutil), ignore = "certutil not found in PATH")]
fn nss_validates_the_chain_usages() {
    let chain = alice().certify(CertificateKind::Chain).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let db = format!("sql:{}", dir.path().display());
    let pem = |cert: &Certificate, name: &str| {
        let path = dir.path().join(name);
        std::fs::write(&path, cert.to_pem(x509_cert::der::pem::LineEnding::LF).unwrap()).unwrap();
        path
    };

    let run = |args: &[&str]| {
        let result = std::process::Command::new("certutil").args(args).output();
        // Gated by cfg(has_certutil): a spawn failure here means the build.rs probe went
        // stale, which must fail loudly, not pass silently (see build.rs)
        result.expect("certutil vanished since the build.rs probe ran")
    };

    let empty = dir.path().join("empty");
    std::fs::write(&empty, b"").unwrap();
    assert!(
        run(&["-N", "-d", &db, "-f", empty.to_str().unwrap()])
            .status
            .success(),
        "cannot create scratch NSS database"
    );

    // Root as a trusted CA, leaves without any trust of their own
    let root = pem(&chain.root, "root.pem");
    assert!(
        run(&[
            "-A",
            "-n",
            "root",
            "-t",
            "CT,C,C",
            "-d",
            &db,
            "-i",
            root.to_str().unwrap()
        ])
        .status
        .success()
    );
    for (slot, name) in [(SlotId::Authentication, "9a"), (SlotId::Signature, "9c")] {
        let cert = &chain.leaves.iter().find(|(id, _)| *id == slot).unwrap().1;
        let path = pem(cert, &format!("{name}.pem"));
        assert!(
            run(&[
                "-A",
                "-n",
                name,
                "-t",
                ",,",
                "-d",
                &db,
                "-i",
                path.to_str().unwrap()
            ])
            .status
            .success()
        );
    }

    let validate = |name: &str, usage: &str| {
        let out = run(&["-V", "-n", name, "-u", usage, "-d", &db]);
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        (out.status.success() && stdout.contains("certificate is valid"), stdout)
    };

    // 9A carries clientAuth (usage C), 9C carries emailProtection (usage S) ...
    let (ok, detail) = validate("9a", "C");
    assert!(ok, "NSS rejects 9A for TLS client auth:\n{detail}");
    let (ok, detail) = validate("9c", "S");
    assert!(ok, "NSS rejects 9C for e-mail signing:\n{detail}");

    // ... and neither passes for the other's purpose, so the usages actually constrain
    let (ok, detail) = validate("9a", "S");
    assert!(!ok, "NSS accepted 9A for e-mail signing:\n{detail}");
}

#[test]
#[cfg_attr(not(has_openssl), ignore = "openssl not found in PATH")]
fn openssl_verifies_chain() {
    for intermediate in [false, true] {
        let chain = alice()
            .with_intermediate(intermediate)
            .certify(CertificateKind::Chain)
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();

        let write = |name: &str, cert: &Certificate| {
            let path = dir.join(name);
            std::fs::write(&path, cert.to_pem(x509_cert::der::pem::LineEnding::LF).unwrap())
                .unwrap();
            path
        };

        let root = write("root.pem", &chain.root);
        let sub = chain.intermediate.as_ref().map(|c| write("sub.pem", c));

        // Each slot certificate has to chain to the root under its intended purpose.
        //
        // Slot 9D is deliberately checked without a purpose: OpenSSL's `smimeencrypt`
        // check (`check_purpose_smime_encrypt`) requires `keyEncipherment`, which RFC 8813
        // forbids on EC keys -- it is an RSA-era check that was never updated for ECDH.
        // The meaningful assertion for 9D is `openssl cms -encrypt`, which is exercised by
        // `openssl_encrypts_to_key_management_cert` below.
        let purposes = [
            ("sslclient", 0usize),
            ("smimesign", 1),
            ("any", 2),
            ("any", 3),
        ];

        for (purpose, index) in purposes {
            let (slot, leaf) = &chain.leaves[index];
            let leaf_path = write(&format!("leaf{index}.pem"), leaf);

            let mut args = vec![
                "verify".to_string(),
                "-CAfile".to_string(),
                root.to_str().unwrap().to_string(),
                "-x509_strict".to_string(),
            ];
            if purpose != "any" {
                args.push("-purpose".to_string());
                args.push(purpose.to_string());
            }
            if let Some(sub) = &sub {
                args.push("-untrusted".to_string());
                args.push(sub.to_str().unwrap().to_string());
            }
            args.push(leaf_path.to_str().unwrap().to_string());

            let result = std::process::Command::new("openssl").args(&args).output();
            // Gated by cfg(has_openssl): a spawn failure here means the build.rs probe went
            // stale, which must fail loudly, not pass silently (see build.rs)
            let output = result.expect("openssl vanished since the build.rs probe ran");

            assert!(
                output.status.success(),
                "openssl verify -purpose {purpose} failed for {slot:?} (intermediate={intermediate}):\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
    }
}

#[test]
#[cfg_attr(not(has_openssl), ignore = "openssl not found in PATH")]
fn openssl_encrypts_to_key_management_cert() {
    // The real end use for slot 9D: CMS enveloping has to pick ECDH key agreement. This is
    // what `-purpose smimeencrypt` cannot tell us, since it only understands RSA transport.
    let chain = alice().certify(CertificateKind::Chain).unwrap();
    let (slot, cert) = &chain.leaves[2];
    assert_eq!(*slot, SlotId::KeyManagement);

    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();

    let recipient = dir.join("9d.pem");
    let message = dir.join("msg.txt");
    let enveloped = dir.join("msg.p7m");
    std::fs::write(&recipient, cert.to_pem(x509_cert::der::pem::LineEnding::LF).unwrap()).unwrap();
    std::fs::write(&message, b"hello").unwrap();

    let result = std::process::Command::new("openssl")
        .args([
            "cms",
            "-encrypt",
            "-aes256",
            "-in",
            message.to_str().unwrap(),
            "-out",
            enveloped.to_str().unwrap(),
            "-outform",
            "DER",
            recipient.to_str().unwrap(),
        ])
        .output();

    // Gated by cfg(has_openssl): a spawn failure here means the build.rs probe went
    // stale, which must fail loudly, not pass silently (see build.rs)
    let output = result.expect("openssl vanished since the build.rs probe ran");

    assert!(
        output.status.success(),
        "openssl cms -encrypt failed for the key management certificate:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );

    // The enveloped data has to use ECDH key agreement, not RSA key transport
    let parsed = std::process::Command::new("openssl")
        .args([
            "asn1parse",
            "-inform",
            "DER",
            "-in",
            enveloped.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let parsed = String::from_utf8_lossy(&parsed.stdout);

    assert!(
        parsed.contains("dhSinglePass"),
        "expected ECDH key agreement in the enveloped data:\n{parsed}"
    );
}

/// `--shared` makes the named slot fall back to the derivation used when no subkey id is
/// given, so the same key lands on every card, while the rest stay card specific.
///
/// Slot 9D is the one worth sharing: a sender encrypts to one specific certificate, so
/// per-card key management keys mean a message can only be opened on the card whose
/// certificate the sender chose.
#[test]
fn shared_slots_ignore_the_subkey_id() {
    let key_in = |chain: &mind_the_gap::piv::CertChain, slot: SlotId| {
        chain
            .leaves
            .iter()
            .find(|(id, _)| *id == slot)
            .map(|(_, cert)| {
                cert.tbs_certificate()
                    .subject_public_key_info()
                    .to_der()
                    .unwrap()
            })
            .unwrap()
    };

    let card = |id: &str| {
        SeededSmartcard::new(&SEED_A, Some(id.to_string()), "Alice".into())
            .add_email("alice@example.com")
            .unwrap()
            .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
            .with_shared(vec![SharedSlot::KeyManagement])
            .certify(CertificateKind::Chain)
            .unwrap()
    };

    let laptop = card("laptop");
    let desktop = card("desktop");
    let plain = alice().certify(CertificateKind::Chain).unwrap();

    // The shared slot is the key a card with no subkey id would have had ...
    assert_eq!(key_in(&laptop, SlotId::KeyManagement), key_in(&plain, SlotId::KeyManagement),);
    assert_eq!(key_in(&laptop, SlotId::KeyManagement), key_in(&desktop, SlotId::KeyManagement),);

    // ... while everything not named stays scoped to its own card
    assert_ne!(key_in(&laptop, SlotId::Authentication), key_in(&desktop, SlotId::Authentication),);
    assert_ne!(key_in(&laptop, SlotId::Authentication), key_in(&plain, SlotId::Authentication),);
}

/// The subkey id and scheme version are recorded in the person-bound subjects, and nowhere
/// they would be wrong.
///
/// One seed provisioning several cards gives every card the same `CN`, so without a qualifier
/// a certificate cannot say which card issued it. `dnQualifier` is the X.500 attribute for
/// exactly that. The root authority is shared by every card and so carries none, and slot 9E
/// already names the card through its derived card id.
#[test]
fn subkey_id_is_recorded_in_subjects() {
    let chain = SeededSmartcard::new(&SEED_A, Some("laptop".to_string()), "Alice".into())
        .add_email("alice@example.com")
        .unwrap()
        .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        .certify(CertificateKind::Chain)
        .unwrap();

    let subject = |cert: &Certificate| cert.tbs_certificate().subject().to_string();

    for (slot, leaf) in &chain.leaves {
        let subject = subject(leaf);

        if *slot == SlotId::CardAuthentication {
            assert!(
                !subject.contains("laptop"),
                "9E is card bound and names the card through its card id: {subject}",
            );
        } else {
            assert!(
                subject.contains("DNQUALIFIER=mtg1:laptop"),
                "{slot:?} subject does not identify the card and its scheme: {subject}",
            );
        }
    }

    assert!(
        !subject(&chain.root).contains("laptop"),
        "the root authority is shared by every card and must not name one",
    );
}

/// Without a subkey id there is nothing to qualify, so the subjects stay as they were.
#[test]
fn subjects_carry_no_qualifier_without_a_subkey_id() {
    let chain = alice().certify(CertificateKind::Chain).unwrap();

    for (_, leaf) in &chain.leaves {
        assert!(
            !leaf
                .tbs_certificate()
                .subject()
                .to_string()
                .contains("DNQUALIFIER")
        );
    }
}

/// Every card names the scheme that produced it, whether or not it has a subkey id.
///
/// The marker is on the published identifier rather than in a derivation label: relabelling
/// already moves every key, so a version in the path would separate nothing, whereas an
/// identifier that names its own scheme can be read off a card and understood.
#[test]
fn identifiers_name_their_scheme() {
    let card_subject = |card: SeededSmartcard| {
        card.certify(CertificateKind::Chain)
            .unwrap()
            .leaves
            .iter()
            .find(|(slot, _)| *slot == SlotId::CardAuthentication)
            .map(|(_, cert)| cert.tbs_certificate().subject().to_string())
            .unwrap()
    };

    assert!(card_subject(alice()).contains("PIV Card mtg1:"));

    let scoped = SeededSmartcard::new(&SEED_A, Some("laptop".to_string()), "Alice".into())
        .add_email("alice@example.com")
        .unwrap()
        .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1));
    assert!(card_subject(scoped).contains("PIV Card mtg1:"));
}

/// An archived key is the very key the generation it came from used live.
///
/// This is what the retired slots are for: data encrypted to an older key management key stays
/// readable after the live one rotates. It only works because slot keys derive by the role
/// they serve rather than the slot they sit in, so `key:key-management` under an older subseed
/// is the same key whether it lives in 9D or in 0x82.
#[test]
fn retired_slots_hold_the_previous_generation() {
    let spki = |chain: &mind_the_gap::piv::CertChain, slot: SlotId| {
        chain
            .leaves
            .iter()
            .find(|(id, _)| *id == slot)
            .map(|(_, cert)| {
                cert.tbs_certificate()
                    .subject_public_key_info()
                    .to_der()
                    .unwrap()
            })
            .unwrap()
    };

    let generation = |id: &str| {
        SeededSmartcard::new(&SEED_A, Some(id.to_string()), "Alice".into())
            .add_email("alice@example.com")
            .unwrap()
            .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
    };

    let old = generation("gen1").certify(CertificateKind::Chain).unwrap();
    let new = generation("gen2")
        .with_retired(vec!["gen1".to_string()])
        .certify(CertificateKind::Chain)
        .unwrap();

    let archived = SlotId::Retired(RetiredSlotId::R1);

    assert_eq!(
        spki(&new, archived),
        spki(&old, SlotId::KeyManagement),
        "the retired slot does not hold gen1's key management key",
    );
    assert_ne!(
        spki(&new, archived),
        spki(&new, SlotId::KeyManagement),
        "the retired slot holds the live key rather than the superseded one",
    );

    // The archived certificate names the generation it belongs to, not the one running the card
    let subject = new
        .leaves
        .iter()
        .find(|(id, _)| *id == archived)
        .map(|(_, cert)| cert.tbs_certificate().subject().to_string())
        .unwrap();
    assert!(
        subject.contains("gen1"),
        "archived certificate does not name its generation: {subject}"
    );
}

/// Generations fill the retired slots in order, and there are only twenty of them.
#[test]
fn retired_generations_fill_slots_in_order() {
    let card = |retired: Vec<String>| {
        SeededSmartcard::new(&SEED_A, Some("live".to_string()), "Alice".into())
            .add_email("alice@example.com")
            .unwrap()
            .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
            .with_retired(retired)
            .certify(CertificateKind::Chain)
    };

    let three = card((1..=3).map(|n| format!("gen{n}")).collect()).unwrap();
    for (index, slot) in [RetiredSlotId::R1, RetiredSlotId::R2, RetiredSlotId::R3]
        .into_iter()
        .enumerate()
    {
        let subject = three
            .leaves
            .iter()
            .find(|(id, _)| *id == SlotId::Retired(slot))
            .map(|(_, cert)| cert.tbs_certificate().subject().to_string())
            .unwrap_or_else(|| panic!("{slot:?} was not provisioned"));

        assert!(subject.contains(&format!("gen{}", index + 1)));
    }

    assert!(
        card((1..=21).map(|n| format!("gen{n}")).collect()).is_err(),
        "a twenty-first generation has no slot to go in",
    );
}

/// A shared key management key has no generations, so there is nothing to archive.
///
/// Under `--shared key-management` the 9D key is derived without any subkey id and never
/// rotates with it. The per-generation derivation `--retire` archives therefore names a key
/// no card ever carried -- and `check` could not catch that, because it compares against the
/// same wrong derivation. The combination must refuse instead of minting a bogus archive.
#[test]
fn retiring_a_shared_key_management_key_is_refused() {
    let result = SeededSmartcard::new(&SEED_A, Some("live".to_string()), "Alice".into())
        .add_email("alice@example.com")
        .unwrap()
        .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        .with_shared(vec![SharedSlot::KeyManagement])
        .with_retired(vec!["gen1".to_string()])
        .certify(CertificateKind::Chain);

    assert!(result.is_err());

    // Sharing a slot that does rotate with the subkey id stays allowed alongside --retire
    SeededSmartcard::new(&SEED_A, Some("live".to_string()), "Alice".into())
        .add_email("alice@example.com")
        .unwrap()
        .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        .with_shared(vec![SharedSlot::Authentication])
        .with_retired(vec!["gen1".to_string()])
        .certify(CertificateKind::Chain)
        .expect("only the key management combination is incoherent");
}
