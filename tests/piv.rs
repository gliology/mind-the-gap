use mind_the_gap::piv::{CertificateKind, SeededSmartcard, SlotRole};
use mind_the_gap::seed::Seed256;

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, VerifyingKey};

use x509_cert::der::{Encode, EncodePem};
use x509_cert::ext::pkix::AuthorityKeyIdentifier;
use x509_cert::ext::pkix::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::Certificate;

use std::time::{Duration, SystemTime};

use yubikey::piv::SlotId;

const SEED_A: Seed256 = [1u8; 32];
const SEED_B: Seed256 = [2u8; 32];

const SLOTS: [(SlotId, SlotRole); 4] = [
    (SlotId::Authentication, SlotRole::Authentication),
    (SlotId::Signature, SlotRole::Signature),
    (SlotId::KeyManagement, SlotRole::KeyManagement),
    (SlotId::CardAuthentication, SlotRole::CardAuthentication),
];

fn builder(seed: Seed256, name: &str, email: &str) -> SeededSmartcard {
    SeededSmartcard::new(seed, None, name.into())
        .add_email(email)
        .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
}

fn alice() -> SeededSmartcard {
    builder(SEED_A, "Alice", "alice@example.com")
}

/// SHA-256 over the DER encoding, the same identity `check` compares on
fn digest(cert: &Certificate) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(cert.to_der().unwrap()).to_vec()
}

/// Verify that `issuer` really signed `cert`
fn verifies_under(cert: &Certificate, issuer: &Certificate) -> bool {
    let spki = issuer
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .unwrap();
    let key = VerifyingKey::from_sec1_bytes(
        issuer
            .tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
            .raw_bytes(),
    )
    .unwrap_or_else(|_| panic!("issuer SPKI is not a P-256 point: {spki:?}"));

    let tbs = cert.tbs_certificate().to_der().unwrap();
    let signature = DerSignature::from_bytes(cert.signature().raw_bytes()).unwrap();

    key.verify(&tbs, &signature).is_ok()
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
        assert_eq!(
            digest(left),
            digest(right),
            "{slot:?} slot is not reproducible"
        );
    }
}

#[test]
fn certify_is_deterministic_without_date() {
    // Regression test: Validity::infinity() used to anchor notBefore at SystemTime::now(),
    // so the output was not reproducible unless --date was passed.
    let plain =
        || SeededSmartcard::new(SEED_A, None, "Alice".into()).add_email("alice@example.com");

    let a = plain().certify(CertificateKind::Chain).unwrap();
    let b = plain().certify(CertificateKind::Chain).unwrap();

    assert_eq!(digest(&a.root), digest(&b.root));
    assert_eq!(digest(&a.leaves[0].1), digest(&b.leaves[0].1));
}

#[test]
fn certify_differs_by_seed() {
    let a = alice().certify(CertificateKind::Chain).unwrap();
    let b = builder(SEED_B, "Alice", "alice@example.com")
        .certify(CertificateKind::Chain)
        .unwrap();

    assert_ne!(digest(&a.root), digest(&b.root));
    assert_ne!(digest(&a.leaves[0].1), digest(&b.leaves[0].1));
}

#[test]
fn certify_differs_by_subkey() {
    let a = alice().certify(CertificateKind::Chain).unwrap();
    let b = SeededSmartcard::new(SEED_A, Some("work".to_string().into()), "Alice".into())
        .add_email("alice@example.com")
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
    let b = builder(SEED_A, "Bob", "alice@example.com")
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
    assert!(alice()
        .with_intermediate(true)
        .certify(CertificateKind::Intermediate)
        .is_ok());
}

// --- Chain integrity ---------------------------------------------------------

#[test]
fn root_is_self_signed() {
    let chain = alice().certify(CertificateKind::Chain).unwrap();
    let root = &chain.root;

    assert_eq!(
        root.tbs_certificate().issuer(),
        root.tbs_certificate().subject()
    );
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
                assert_eq!(
                    eku,
                    vec!["1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2"],
                    "{slot:?}"
                );
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
                assert_eq!(
                    eku,
                    vec!["1.3.6.1.5.5.7.3.4", "1.3.6.1.5.5.7.3.2"],
                    "{slot:?}"
                );
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
        assert!(ca
            .tbs_certificate()
            .get_extension::<ExtendedKeyUsage>()
            .unwrap()
            .is_none());
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
            assert!(
                format!("{:?}", san.0).contains("alice@example.com"),
                "{slot:?}"
            );
        }
    }
}

#[test]
fn no_empty_san() {
    // GeneralNames is a SEQUENCE SIZE (1..MAX), so with no emails the extension has to be
    // omitted rather than encoded empty.
    let chain = SeededSmartcard::new(SEED_A, None, "Alice".into())
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
    let chain = builder(SEED_A, "Doe, Jane A+B", "jane@example.com")
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

#[test]
fn openssl_verifies_chain() {
    for intermediate in [false, true] {
        let chain = alice()
            .with_intermediate(intermediate)
            .certify(CertificateKind::Chain)
            .unwrap();

        let dir = std::env::temp_dir().join(format!(
            "mtg-test-piv-{}-{}",
            std::process::id(),
            intermediate
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let write = |name: &str, cert: &Certificate| {
            let path = dir.join(name);
            std::fs::write(
                &path,
                cert.to_pem(x509_cert::der::pem::LineEnding::LF).unwrap(),
            )
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
            let output = match result {
                Err(_) => {
                    eprintln!("openssl not found, skipping");
                    std::fs::remove_dir_all(&dir).ok();
                    return;
                }
                Ok(output) => output,
            };

            assert!(
                output.status.success(),
                "openssl verify -purpose {purpose} failed for {slot:?} (intermediate={intermediate}):\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }

        std::fs::remove_dir_all(&dir).ok();
    }
}

#[test]
fn openssl_encrypts_to_key_management_cert() {
    // The real end use for slot 9D: CMS enveloping has to pick ECDH key agreement. This is
    // what `-purpose smimeencrypt` cannot tell us, since it only understands RSA transport.
    let chain = alice().certify(CertificateKind::Chain).unwrap();
    let (slot, cert) = &chain.leaves[2];
    assert_eq!(*slot, SlotId::KeyManagement);

    let dir = std::env::temp_dir().join(format!("mtg-test-cms-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let recipient = dir.join("9d.pem");
    let message = dir.join("msg.txt");
    let enveloped = dir.join("msg.p7m");
    std::fs::write(
        &recipient,
        cert.to_pem(x509_cert::der::pem::LineEnding::LF).unwrap(),
    )
    .unwrap();
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

    let output = match result {
        Err(_) => {
            eprintln!("openssl not found, skipping");
            std::fs::remove_dir_all(&dir).ok();
            return;
        }
        Ok(output) => output,
    };

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

    std::fs::remove_dir_all(&dir).ok();

    assert!(
        parsed.contains("dhSinglePass"),
        "expected ECDH key agreement in the enveloped data:\n{parsed}"
    );
}
