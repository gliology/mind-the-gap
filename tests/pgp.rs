use mind_the_gap::pgp::SeededSmartcard;
use mind_the_gap::seed::Seed256;

use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::types::{HashAlgorithm, PublicKeyAlgorithm, SignatureType};
use sequoia_openpgp::crypto::Signer;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::{Cert, Packet};

use std::time::{Duration, SystemTime};

const SEED_A: Seed256 = [1u8; 32];
const SEED_B: Seed256 = [2u8; 32];

fn builder(seed: Seed256, name: &str, email: &str) -> SeededSmartcard {
    SeededSmartcard::new(seed, None, name.into())
        .add_email(email)
        .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
}

// --- Cert structure tests (certify(None)) ---

#[test]
fn certify_has_three_subkeys() {
    let cert = builder(SEED_A, "Alice", "alice@example.com")
        .certify(None)
        .unwrap();
    assert_eq!(cert.keys().subkeys().count(), 3);
}

#[test]
fn certify_subkeys_have_correct_flags_and_algorithms() {
    let cert = builder(SEED_A, "Alice", "alice@example.com")
        .certify(None)
        .unwrap();
    let policy = StandardPolicy::new();
    let vc = cert.with_policy(&policy, None).unwrap();

    let mut has_signing = false;
    let mut has_encryption = false;
    let mut has_authentication = false;

    for ka in vc.keys().subkeys() {
        let flags = ka.key_flags().unwrap();
        let algo = ka.key().pk_algo();
        if flags.for_signing() {
            has_signing = true;
            assert_eq!(algo, PublicKeyAlgorithm::EdDSA, "signing subkey should use EdDSA");
        }
        if flags.for_transport_encryption() && flags.for_storage_encryption() {
            has_encryption = true;
            assert_eq!(algo, PublicKeyAlgorithm::ECDH, "encryption subkey should use ECDH");
        }
        if flags.for_authentication() {
            has_authentication = true;
            assert_eq!(algo, PublicKeyAlgorithm::EdDSA, "auth subkey should use EdDSA");
        }
    }

    assert!(has_signing, "cert should have a signing subkey");
    assert!(has_encryption, "cert should have an encryption subkey");
    assert!(has_authentication, "cert should have an authentication subkey");
}

#[test]
fn certify_has_user_id() {
    let cert = builder(SEED_A, "Alice", "alice@example.com")
        .certify(None)
        .unwrap();
    let uids: Vec<_> = cert.userids().collect();
    assert_eq!(uids.len(), 1);
    let uid_str = String::from_utf8_lossy(uids[0].userid().value());
    assert!(uid_str.contains("Alice"), "UID should contain the name");
    assert!(uid_str.contains("alice@example.com"), "UID should contain the email");
}

#[test]
fn certify_is_deterministic() {
    let cert1 = builder(SEED_A, "Alice", "alice@example.com")
        .certify(None)
        .unwrap();
    let cert2 = builder(SEED_A, "Alice", "alice@example.com")
        .certify(None)
        .unwrap();
    assert_eq!(cert1.fingerprint(), cert2.fingerprint());
}

#[test]
fn certify_differs_by_seed() {
    let cert_a = builder(SEED_A, "Alice", "alice@example.com")
        .certify(None)
        .unwrap();
    let cert_b = builder(SEED_B, "Bob", "bob@example.com")
        .certify(None)
        .unwrap();
    assert_ne!(cert_a.fingerprint(), cert_b.fingerprint());
}

#[test]
fn certify_valid_under_policy() {
    let cert = builder(SEED_A, "Alice", "alice@example.com")
        .certify(None)
        .unwrap();
    let policy = StandardPolicy::new();
    cert.with_policy(&policy, None).unwrap();
}

// --- Export tests ---

#[test]
fn export_has_secret_keys() {
    let cert = builder(SEED_A, "Alice", "alice@example.com")
        .export()
        .unwrap();
    assert!(cert.keys().secret().count() > 0);
}

#[test]
fn export_primary_matches_certify() {
    let exported = builder(SEED_A, "Alice", "alice@example.com")
        .export()
        .unwrap();
    let certified = builder(SEED_A, "Alice", "alice@example.com")
        .certify(None)
        .unwrap();
    assert_eq!(exported.fingerprint(), certified.fingerprint());
}

// --- WoT certification tests (certify(Some(cert))) ---

#[test]
fn wot_preserves_target_fingerprint() {
    let bob_cert = builder(SEED_B, "Bob", "bob@example.com")
        .certify(None)
        .unwrap();
    let bob_fp = bob_cert.fingerprint();

    let certified = builder(SEED_A, "Alice", "alice@example.com")
        .certify(Some(bob_cert))
        .unwrap();

    assert_eq!(certified.fingerprint(), bob_fp);
}

#[test]
fn wot_adds_certification_to_each_uid() {
    // Alice's fingerprint for issuer matching
    let alice_fp = builder(SEED_A, "Alice", "alice@example.com")
        .certify(None)
        .unwrap()
        .fingerprint();

    let bob_cert = builder(SEED_B, "Bob", "bob@example.com")
        .certify(None)
        .unwrap();

    let certified = builder(SEED_A, "Alice", "alice@example.com")
        .certify(Some(bob_cert))
        .unwrap();

    for uid in certified.userids() {
        assert!(
            uid.certifications().any(|sig| {
                sig.issuer_fingerprints().any(|fp| fp == &alice_fp)
            }),
            "each UID should carry a certification from Alice"
        );
    }
}

#[test]
fn wot_certification_not_self_sig() {
    let bob_cert = builder(SEED_B, "Bob", "bob@example.com")
        .certify(None)
        .unwrap();
    let bob_fp = bob_cert.fingerprint();

    let certified = builder(SEED_A, "Alice", "alice@example.com")
        .certify(Some(bob_cert))
        .unwrap();

    // certifications() returns only third-party certs; none should carry Bob's fingerprint
    for uid in certified.userids() {
        for sig in uid.certifications() {
            let from_bob = sig.issuer_fingerprints().any(|fp| fp == &bob_fp);
            assert!(
                !from_bob,
                "WoT certification should not be issued by Bob's own key"
            );
        }
    }
}

// --- Key algorithm tests ---

#[test]
fn certify_primary_uses_ed25519() {
    let cert = builder(SEED_A, "Alice", "alice@example.com")
        .certify(None)
        .unwrap();
    assert_eq!(cert.primary_key().key().pk_algo(), PublicKeyAlgorithm::EdDSA);
}

// --- Revocation packet content test ---

#[test]
fn revoke_packet_is_key_revocation() {
    let packet = builder(SEED_A, "Alice", "alice@example.com")
        .revoke(0, "Unspecified")
        .unwrap();
    match packet {
        Packet::Signature(sig) => assert_eq!(sig.typ(), SignatureType::KeyRevocation),
        other => panic!("expected Signature packet, got {:?}", other),
    }
}

// --- Serialisation round-trip ---

#[test]
fn certify_armor_round_trips() {
    let cert = builder(SEED_A, "Alice", "alice@example.com")
        .certify(None)
        .unwrap();
    // Use the same serialisation path as the CLI (cert.armored().to_vec())
    let armored = cert.armored().to_vec().unwrap();
    let parsed = Cert::from_bytes(&armored).unwrap();
    assert_eq!(cert.fingerprint(), parsed.fingerprint());
    assert_eq!(cert.keys().count(), parsed.keys().count());
    assert_eq!(cert.userids().count(), parsed.userids().count());
}

// --- Cryptographic sign + verify ---

#[test]
fn export_signing_key_can_sign_and_verify() {
    let cert = builder(SEED_A, "Alice", "alice@example.com")
        .export()
        .unwrap();
    let policy = StandardPolicy::new();
    let vc = cert.with_policy(&policy, None).unwrap();

    let ka = vc.keys().secret().for_signing().next()
        .expect("should have a signing subkey");
    let mut keypair = ka.key().clone().into_keypair().unwrap();

    // Hash the test message
    let algo = HashAlgorithm::SHA512;
    let mut ctx = algo.context().unwrap().for_digest();
    ctx.update(b"hello, world");
    let digest = ctx.into_digest().unwrap();

    // Sign with the secret key …
    let sig = keypair.sign(algo, &digest).unwrap();
    // … and verify with the public key material from the same key slot
    ka.key().verify(&sig, algo, &digest).unwrap();
}

// --- CLI interoperability ---

/// Helper: fingerprint as a continuous uppercase hex string (no spaces).
fn fp_hex(cert: &Cert) -> String {
    cert.fingerprint()
        .as_bytes()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect()
}

#[test]
fn sq_inspect_accepts_exported_cert() {
    let cert = builder(SEED_A, "Alice", "alice@example.com")
        .certify(None)
        .unwrap();
    let armored = cert.armored().to_vec().unwrap();

    let tmp = std::env::temp_dir()
        .join(format!("mtg-test-sq-{}.asc", std::process::id()));
    std::fs::write(&tmp, &armored).unwrap();

    let result = std::process::Command::new("sq")
        .args(["inspect", tmp.to_str().unwrap()])
        .output();
    std::fs::remove_file(&tmp).ok();

    let output = match result {
        Err(_) => { eprintln!("sq not found, skipping"); return; }
        Ok(o) => o,
    };
    assert!(output.status.success(),
        "sq inspect failed:\n{}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Strip whitespace so we match regardless of the spaced-hex display format
    let stdout_nows: String = stdout.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(stdout_nows.to_uppercase().contains(&fp_hex(&cert)),
        "fingerprint not found in sq output:\n{}", stdout);
    assert!(stdout.contains("alice@example.com"),
        "UID not found in sq output:\n{}", stdout);
}

#[test]
fn gpg_accepts_exported_cert() {
    let cert = builder(SEED_A, "Alice", "alice@example.com")
        .certify(None)
        .unwrap();
    let armored = cert.armored().to_vec().unwrap();

    let tmp = std::env::temp_dir()
        .join(format!("mtg-test-gpg-{}.asc", std::process::id()));
    std::fs::write(&tmp, &armored).unwrap();

    // --show-keys parses and displays key info without importing or touching GNUPGHOME
    let result = std::process::Command::new("gpg")
        .args(["--show-keys", "--with-colons", tmp.to_str().unwrap()])
        .output();
    std::fs::remove_file(&tmp).ok();

    let output = match result {
        Err(_) => { eprintln!("gpg not found, skipping"); return; }
        Ok(o) => o,
    };
    assert!(output.status.success(),
        "gpg --show-keys failed:\n{}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    // In colon format fingerprints appear as "fpr::::::<40-char-hex>:" — uppercase, no spaces
    assert!(stdout.to_uppercase().contains(&fp_hex(&cert)),
        "fingerprint not found in gpg output:\n{}", stdout);
    // At least one uid record should contain the email
    assert!(stdout.contains("alice@example.com"),
        "UID not found in gpg output:\n{}", stdout);
}
