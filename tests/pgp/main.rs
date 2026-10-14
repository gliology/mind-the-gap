use mind_the_gap::pgp::{CertificateKind, Scheme, SeededSmartcard, SharedKey, VerificationKind};
use mind_the_gap::seed::{Algorithm, Seed256};

use sequoia_openpgp::crypto::Signer;
use sequoia_openpgp::crypto::mpi;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::types::{
    Curve as PgpCurve, HashAlgorithm, PublicKeyAlgorithm, SignatureType, SymmetricAlgorithm,
};
use sequoia_openpgp::{Cert, Packet};

use std::time::{Duration, SystemTime};

mod golden;

const SEED_A: Seed256 = [1u8; 32];
const SEED_B: Seed256 = [2u8; 32];

fn builder(seed: &Seed256, name: &str, email: &str) -> SeededSmartcard {
    SeededSmartcard::new(seed, None, name.into())
        .add_email(email)
        .unwrap()
        .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
}

// --- Cert structure tests ---

#[test]
fn certify_has_three_subkeys() {
    let cert = builder(&SEED_A, "Alice", "alice@example.com")
        .certify(CertificateKind::default())
        .unwrap();
    assert_eq!(cert.keys().subkeys().count(), 3);
}

#[test]
fn certify_subkeys_have_correct_flags_and_algorithms() {
    let cert = builder(&SEED_A, "Alice", "alice@example.com")
        .certify(CertificateKind::default())
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
    let cert = builder(&SEED_A, "Alice", "alice@example.com")
        .certify(CertificateKind::default())
        .unwrap();
    let uids: Vec<_> = cert.userids().collect();
    assert_eq!(uids.len(), 1);
    let uid_str = String::from_utf8_lossy(uids[0].userid().value());
    assert!(uid_str.contains("Alice"), "UID should contain the name");
    assert!(uid_str.contains("alice@example.com"), "UID should contain the email");
}

#[test]
fn certify_is_deterministic() {
    let cert1 = builder(&SEED_A, "Alice", "alice@example.com")
        .certify(CertificateKind::default())
        .unwrap();
    let cert2 = builder(&SEED_A, "Alice", "alice@example.com")
        .certify(CertificateKind::default())
        .unwrap();
    assert_eq!(cert1.fingerprint(), cert2.fingerprint());
}

#[test]
fn certify_differs_by_seed() {
    let cert_a = builder(&SEED_A, "Alice", "alice@example.com")
        .certify(CertificateKind::default())
        .unwrap();
    let cert_b = builder(&SEED_B, "Bob", "bob@example.com")
        .certify(CertificateKind::default())
        .unwrap();
    assert_ne!(cert_a.fingerprint(), cert_b.fingerprint());
}

#[test]
fn certify_valid_under_policy() {
    let cert = builder(&SEED_A, "Alice", "alice@example.com")
        .certify(CertificateKind::default())
        .unwrap();
    let policy = StandardPolicy::new();
    cert.with_policy(&policy, None).unwrap();
}

// --- Export tests ---

#[test]
fn export_has_secret_keys() {
    let cert = builder(&SEED_A, "Alice", "alice@example.com")
        .export()
        .unwrap();
    assert!(cert.keys().secret().count() > 0);
}

#[test]
fn export_primary_matches_certify() {
    let exported = builder(&SEED_A, "Alice", "alice@example.com")
        .export()
        .unwrap();
    let certified = builder(&SEED_A, "Alice", "alice@example.com")
        .certify(CertificateKind::default())
        .unwrap();
    assert_eq!(exported.fingerprint(), certified.fingerprint());
}

// --- WoT certification tests ---

#[test]
fn wot_preserves_target_fingerprint() {
    let bob_cert = builder(&SEED_B, "Bob", "bob@example.com")
        .certify(CertificateKind::default())
        .unwrap();
    let bob_fp = bob_cert.fingerprint();

    let certified = builder(&SEED_A, "Alice", "alice@example.com")
        .trust(bob_cert, VerificationKind::default())
        .unwrap();

    assert_eq!(certified.fingerprint(), bob_fp);
}

#[test]
fn wot_adds_certification_to_each_uid() {
    // Alice's fingerprint for issuer matching
    let alice_fp = builder(&SEED_A, "Alice", "alice@example.com")
        .certify(CertificateKind::default())
        .unwrap()
        .fingerprint();

    let bob_cert = builder(&SEED_B, "Bob", "bob@example.com")
        .certify(CertificateKind::default())
        .unwrap();

    let certified = builder(&SEED_A, "Alice", "alice@example.com")
        .trust(bob_cert, VerificationKind::default())
        .unwrap();

    for uid in certified.userids() {
        assert!(
            uid.certifications()
                .any(|sig| { sig.issuer_fingerprints().any(|fp| fp == &alice_fp) }),
            "each UID should carry a certification from Alice"
        );
    }
}

#[test]
fn wot_certification_not_self_sig() {
    let bob_cert = builder(&SEED_B, "Bob", "bob@example.com")
        .certify(CertificateKind::default())
        .unwrap();
    let bob_fp = bob_cert.fingerprint();

    let certified = builder(&SEED_A, "Alice", "alice@example.com")
        .trust(bob_cert, VerificationKind::default())
        .unwrap();

    // certifications() returns only third-party certs; none should carry Bob's fingerprint
    for uid in certified.userids() {
        for sig in uid.certifications() {
            let from_bob = sig.issuer_fingerprints().any(|fp| fp == &bob_fp);
            assert!(!from_bob, "WoT certification should not be issued by Bob's own key");
        }
    }
}

// --- Key algorithm tests ---

#[test]
fn certify_primary_uses_ed25519() {
    let cert = builder(&SEED_A, "Alice", "alice@example.com")
        .certify(CertificateKind::default())
        .unwrap();
    assert_eq!(cert.primary_key().key().pk_algo(), PublicKeyAlgorithm::EdDSA);
}

/// `--algorithm p256` switches the whole certificate: ECDSA primary, signing and authentication
/// subkeys, an ECDH decryption subkey, all on NIST P-256 with the RFC 6637 KDF parameters.
#[test]
fn p256_certificate_is_ecdsa_and_ecdh_throughout() {
    let cert = builder(&SEED_A, "Alice", "alice@example.com")
        .with_algorithm(Algorithm::P256)
        .unwrap()
        .certify(CertificateKind::default())
        .unwrap();

    assert_eq!(cert.primary_key().key().pk_algo(), PublicKeyAlgorithm::ECDSA);
    match cert.primary_key().key().mpis() {
        mpi::PublicKey::ECDSA { curve, .. } => assert_eq!(*curve, PgpCurve::NistP256),
        other => panic!("primary key is not an ECDSA key: {other:?}"),
    }

    let policy = StandardPolicy::new();
    let vc = cert.with_policy(&policy, None).unwrap();
    assert_eq!(vc.keys().subkeys().count(), 3);

    for ka in vc.keys().subkeys() {
        let flags = ka.key_flags().unwrap();
        match ka.key().mpis() {
            mpi::PublicKey::ECDH { curve, hash, sym, .. } => {
                assert!(flags.for_transport_encryption(), "ECDH on a non-encryption subkey");
                assert_eq!(*curve, PgpCurve::NistP256);
                assert_eq!(*hash, HashAlgorithm::SHA256, "KDF hash is not the RFC 6637 one");
                assert_eq!(*sym, SymmetricAlgorithm::AES128, "KDF cipher is not the RFC 6637 one");
            }
            mpi::PublicKey::ECDSA { curve, .. } => {
                assert!(
                    flags.for_signing() || flags.for_authentication(),
                    "ECDSA on the encryption subkey"
                );
                assert_eq!(*curve, PgpCurve::NistP256);
            }
            other => panic!("subkey has the wrong algorithm: {other:?}"),
        }
    }
}

/// A P-256 certificate is usable, not just well formed: the signing subkey signs under
/// the policy and the certificate validates.
#[test]
fn p256_certificate_is_valid_under_policy() {
    let cert = builder(&SEED_A, "Alice", "alice@example.com")
        .with_algorithm(Algorithm::P256)
        .unwrap()
        .certify(CertificateKind::default())
        .unwrap();
    let policy = StandardPolicy::new();
    let vc = cert.with_policy(&policy, None).unwrap();
    assert!(vc.keys().subkeys().for_signing().next().is_some());
    assert!(
        vc.keys()
            .subkeys()
            .for_transport_encryption()
            .next()
            .is_some()
    );
    assert!(vc.keys().subkeys().for_authentication().next().is_some());
}

/// `--algorithm rsa2048` makes every key an RSA key of that size, each usable for what
/// its flags say, and the certificate is valid under the standard policy.
#[test]
fn rsa_certificate_is_rsa_throughout() {
    let cert = builder(&SEED_A, "Alice", "alice@example.com")
        .with_algorithm(Algorithm::Rsa2048)
        .unwrap()
        .certify(CertificateKind::default())
        .unwrap();

    let policy = StandardPolicy::new();
    let vc = cert.with_policy(&policy, None).unwrap();
    assert_eq!(vc.keys().count(), 4);
    for ka in vc.keys() {
        assert_eq!(ka.key().pk_algo(), PublicKeyAlgorithm::RSAEncryptSign);
        match ka.key().mpis() {
            mpi::PublicKey::RSA { e, n } => {
                assert_eq!(e.value(), [1, 0, 1], "public exponent is not 65537");
                assert_eq!(n.bits(), 2048, "modulus has the wrong size");
            }
            other => panic!("not an RSA key: {other:?}"),
        }
    }
    assert!(vc.keys().subkeys().for_signing().next().is_some());
    assert!(
        vc.keys()
            .subkeys()
            .for_transport_encryption()
            .next()
            .is_some()
    );
    assert!(vc.keys().subkeys().for_authentication().next().is_some());
}

/// The legacy scheme refuses RSA like any other algorithm it never derived.
#[test]
fn legacy_scheme_refuses_rsa() {
    let result = SeededSmartcard::with_scheme(&SEED_A, None, "Alice".into(), Scheme::Legacy)
        .with_algorithm(Algorithm::Rsa2048);
    assert!(result.is_err(), "the legacy scheme accepted RSA");
}

/// The algorithms derive under different labels, so they never share a key.
#[test]
fn curves_share_no_keys() {
    let fingerprints = |algorithm| {
        let cert = builder(&SEED_A, "Alice", "alice@example.com")
            .with_algorithm(algorithm)
            .unwrap()
            .certify(CertificateKind::default())
            .unwrap();
        cert.keys()
            .map(|key| key.key().fingerprint())
            .collect::<Vec<_>>()
    };

    let sets = [Algorithm::Curve25519, Algorithm::P256, Algorithm::Rsa2048].map(fingerprints);
    for (i, a) in sets.iter().enumerate() {
        for b in &sets[i + 1..] {
            for fp in a {
                assert!(!b.contains(fp), "{fp} appears under two algorithms");
            }
        }
    }
}

/// The legacy scheme predates the algorithm segment and only ever produced Curve25519 keys.
#[test]
fn legacy_scheme_refuses_p256() {
    let err = match SeededSmartcard::with_scheme(&SEED_A, None, "Alice".into(), Scheme::Legacy)
        .with_algorithm(Algorithm::P256)
    {
        Ok(_) => panic!("the legacy scheme accepted P-256"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("--legacy"), "error does not name the cause: {err}");

    // Asking for the algorithm it already derives is not an error
    SeededSmartcard::with_scheme(&SEED_A, None, "Alice".into(), Scheme::Legacy)
        .with_algorithm(Algorithm::Curve25519)
        .unwrap();
}

/// P-384 is a PIV-only curve: the OpenPGP backend refuses it rather than derive under
/// labels no OpenPGP card asked for.
#[test]
fn p384_is_refused() {
    let err =
        match SeededSmartcard::new(&SEED_A, None, "Alice".into()).with_algorithm(Algorithm::P384) {
            Ok(_) => panic!("the OpenPGP backend accepted P-384"),
            Err(err) => err,
        };
    assert!(err.to_string().contains("PIV-only"), "error does not name the cause: {err}");
}

// --- Revocation packet content test ---

#[test]
fn revoke_packet_is_key_revocation() {
    use mind_the_gap::pgp::RevocationKind;
    use sequoia_openpgp::parse::Parse;

    let raw = builder(&SEED_A, "Alice", "alice@example.com")
        .revoke(RevocationKind::Certificate, 0, "Unspecified")
        .unwrap();

    match Packet::from_bytes(&raw).unwrap() {
        Packet::Signature(sig) => assert_eq!(sig.typ(), SignatureType::KeyRevocation),
        other => panic!("expected Signature packet, got {:?}", other),
    }
}

// --- Serialisation round-trip ---

#[test]
fn certify_armor_round_trips() {
    let cert = builder(&SEED_A, "Alice", "alice@example.com")
        .certify(CertificateKind::default())
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
    let cert = builder(&SEED_A, "Alice", "alice@example.com")
        .export()
        .unwrap();
    let policy = StandardPolicy::new();
    let vc = cert.with_policy(&policy, None).unwrap();

    let ka = vc
        .keys()
        .secret()
        .for_signing()
        .next()
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
#[cfg_attr(not(has_sq), ignore = "sq not found in PATH")]
fn sq_inspect_accepts_exported_cert() {
    for algorithm in [Algorithm::Curve25519, Algorithm::Rsa2048] {
        let cert = builder(&SEED_A, "Alice", "alice@example.com")
            .with_algorithm(algorithm)
            .unwrap()
            .certify(CertificateKind::default())
            .unwrap();
        let armored = cert.armored().to_vec().unwrap();

        let tmp = tempfile::Builder::new().suffix(".asc").tempfile().unwrap();
        std::fs::write(tmp.path(), &armored).unwrap();

        let result = std::process::Command::new("sq")
            .args(["inspect", tmp.path().to_str().unwrap()])
            .output();

        // Gated by cfg(has_sq): a spawn failure here means the build.rs probe went
        // stale, which must fail loudly, not pass silently (see build.rs)
        let output = result.expect("sq vanished since the build.rs probe ran");
        assert!(
            output.status.success(),
            "sq inspect failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Strip whitespace so we match regardless of the spaced-hex display format
        let stdout_nows: String = stdout.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(
            stdout_nows.to_uppercase().contains(&fp_hex(&cert)),
            "fingerprint not found in sq output:\n{}",
            stdout
        );
        assert!(stdout.contains("alice@example.com"), "UID not found in sq output:\n{}", stdout);
    }
}

#[test]
#[cfg_attr(not(has_gpg), ignore = "gpg not found in PATH")]
fn gpg_accepts_exported_cert() {
    for algorithm in [Algorithm::Curve25519, Algorithm::Rsa2048] {
        let cert = builder(&SEED_A, "Alice", "alice@example.com")
            .with_algorithm(algorithm)
            .unwrap()
            .certify(CertificateKind::default())
            .unwrap();
        let armored = cert.armored().to_vec().unwrap();

        let tmp = tempfile::Builder::new().suffix(".asc").tempfile().unwrap();
        std::fs::write(tmp.path(), &armored).unwrap();

        // --show-keys parses and displays key info without importing or touching GNUPGHOME
        let result = std::process::Command::new("gpg")
            .args(["--show-keys", "--with-colons", tmp.path().to_str().unwrap()])
            .output();

        // Gated by cfg(has_gpg): a spawn failure here means the build.rs probe went
        // stale, which must fail loudly, not pass silently (see build.rs)
        let output = result.expect("gpg vanished since the build.rs probe ran");
        assert!(
            output.status.success(),
            "gpg --show-keys failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        // In colon format fingerprints appear as "fpr::::::<40-char-hex>:" — uppercase, no spaces
        assert!(
            stdout.to_uppercase().contains(&fp_hex(&cert)),
            "fingerprint not found in gpg output:\n{}",
            stdout
        );
        // At least one uid record should contain the email
        assert!(stdout.contains("alice@example.com"), "UID not found in gpg output:\n{}", stdout);
    }
}

/// `--shared` makes the named subkey fall back to the derivation used when no subkey id is
/// given, so the same key lands on every card, while the rest stay card specific.
///
/// This is what makes multi-card OpenPGP workable: a client encrypts to exactly *one* of a
/// certificate's encryption subkeys, so per-card decryption keys mean a message can only be
/// opened on whichever card the sender happened to pick.
#[test]
fn shared_subkeys_ignore_the_subkey_id() {
    let fingerprints = |card: SeededSmartcard| {
        let cert = card.certify(CertificateKind::default()).unwrap();
        let policy = StandardPolicy::new();
        let valid = cert.with_policy(&policy, None).unwrap();

        let find = |want_encryption: bool| {
            valid
                .keys()
                .subkeys()
                .find(|key| {
                    key.key_flags().is_some_and(|flags| {
                        (flags.for_transport_encryption() || flags.for_storage_encryption())
                            == want_encryption
                            && (want_encryption || flags.for_signing())
                    })
                })
                .map(|key| key.key().fingerprint())
                .unwrap()
        };

        (find(true), find(false))
    };

    let card = |id: &str| {
        SeededSmartcard::new(&SEED_A, Some(id.to_string()), "Alice".into())
            .add_email("alice@example.com")
            .unwrap()
            .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
            .with_shared(vec![SharedKey::Decryption])
    };

    let (shared_encryption, shared_signing) = fingerprints(card("laptop"));
    let (other_encryption, other_signing) = fingerprints(card("desktop"));
    let (plain_encryption, plain_signing) =
        fingerprints(builder(&SEED_A, "Alice", "alice@example.com"));

    // The shared subkey is the one a card with no subkey id would have had ...
    assert_eq!(shared_encryption, plain_encryption);
    assert_eq!(shared_encryption, other_encryption);

    // ... while everything not named stays scoped to its own card
    assert_ne!(shared_signing, other_signing);
    assert_ne!(shared_signing, plain_signing);
}

/// The subkey id rides on the subkey binding signature, not on a user id.
///
/// A user id is bound to the primary key, and the primary is identical on every card, so a
/// comment there would label one shared identity with one card's name -- and merging two
/// cards' certificates would leave two user ids for the same person. The binding signature is
/// the only part that is genuinely per card.
#[test]
fn subkey_id_is_recorded_on_the_binding() {
    const NOTATION: &str = "subkey@mind-the-gap.gli.al";

    let cert = SeededSmartcard::new(&SEED_A, Some("laptop".to_string()), "Alice".into())
        .add_email("alice@example.com")
        .unwrap()
        .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        .certify(CertificateKind::default())
        .unwrap();

    let policy = StandardPolicy::new();
    let valid = cert.with_policy(&policy, None).unwrap();

    for subkey in valid.keys().subkeys() {
        let found = subkey
            .binding_signature()
            .notation(NOTATION)
            .any(|value| value == b"mtg1:laptop");

        assert!(found, "{} carries no card notation", subkey.key().fingerprint());
    }

    // Exactly one identity, however many cards are merged together later
    assert_eq!(cert.userids().count(), 1);
}

/// Without a subkey id there is no card to name, so no notation is added.
#[test]
fn bindings_carry_no_notation_without_a_subkey_id() {
    let cert = builder(&SEED_A, "Alice", "alice@example.com")
        .certify(CertificateKind::default())
        .unwrap();

    let policy = StandardPolicy::new();
    let valid = cert.with_policy(&policy, None).unwrap();

    for subkey in valid.keys().subkeys() {
        assert_eq!(
            subkey
                .binding_signature()
                .notation("subkey@mind-the-gap.gli.al")
                .count(),
            0
        );
    }
}

/// A lost card can be retired without taking the identity with it.
///
/// This is what provisioning each card under its own subkey id is for. The primary is
/// re-derivable from the seed, and a subkey is revoked by its primary, so the card need not be
/// present -- which is the whole point when it has been lost.
#[test]
fn subkeys_can_be_revoked_without_the_identity() {
    use mind_the_gap::pgp::RevocationKind;
    use sequoia_openpgp::parse::Parse;
    use sequoia_openpgp::types::RevocationStatus;

    let card = SeededSmartcard::new(&SEED_A, Some("laptop".to_string()), "Alice".into())
        .add_email("alice@example.com")
        .unwrap()
        .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1));

    let raw = card
        .revoke(RevocationKind::Subkeys, 1, "laptop lost")
        .unwrap();
    let revoked = Cert::from_bytes(&raw).unwrap();

    let policy = StandardPolicy::new();

    // The identity survives ...
    assert!(
        matches!(revoked.revocation_status(&policy, None), RevocationStatus::NotAsFarAsWeKnow),
        "revoking this card's subkeys also retired the identity",
    );

    // ... while every one of this card's subkeys is retired
    let mut subkeys = 0;
    for subkey in revoked.keys().subkeys() {
        subkeys += 1;
        assert!(
            !matches!(subkey.revocation_status(&policy, None), RevocationStatus::NotAsFarAsWeKnow),
            "{} was not revoked",
            subkey.key().fingerprint(),
        );
    }
    assert_eq!(subkeys, 3);
}

/// Revoking one card's subkeys leaves a shared subkey in service.
///
/// A subkey derived without the subkey id is byte-identical on every card; revoking it while
/// retiring one card would retire it fleet-wide, which is exactly what `--kind subkeys`
/// promises not to do.
#[test]
fn shared_subkeys_survive_a_card_revocation() {
    use mind_the_gap::pgp::{RevocationKind, SharedKey};
    use sequoia_openpgp::cert::amalgamation::ValidAmalgamation;
    use sequoia_openpgp::parse::Parse;
    use sequoia_openpgp::types::RevocationStatus;

    let card = || {
        SeededSmartcard::new(&SEED_A, Some("laptop".to_string()), "Alice".into())
            .add_email("alice@example.com")
            .unwrap()
            .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
            .with_shared(vec![SharedKey::Decryption])
    };

    let raw = card()
        .revoke(RevocationKind::Subkeys, 1, "laptop lost")
        .unwrap();
    let revoked = Cert::from_bytes(&raw).unwrap();

    let policy = StandardPolicy::new();
    let valid = revoked.with_policy(&policy, None).unwrap();
    for subkey in valid.keys().subkeys() {
        let flags = subkey.key_flags().unwrap();
        let untouched = matches!(subkey.revocation_status(), RevocationStatus::NotAsFarAsWeKnow);

        if flags.for_transport_encryption() || flags.for_storage_encryption() {
            assert!(untouched, "the fleet-wide decryption subkey was revoked");
        } else {
            assert!(!untouched, "{} was not revoked", subkey.key().fingerprint());
        }
    }

    // With every subkey shared there is nothing left to revoke for this card alone
    let all = card()
        .with_shared(vec![
            SharedKey::Signing,
            SharedKey::Decryption,
            SharedKey::Authentication,
        ])
        .revoke(RevocationKind::Subkeys, 1, "laptop lost");
    assert!(all.is_err());
}
