//! The chain as other tools see it: OpenSSL, NSS and friends validate it offline.

use crate::{SEED_A, alice};

use mind_the_gap::piv::{CertificateKind, SeededSmartcard, SharedSlot};
use mind_the_gap::seed::Algorithm;

use x509_cert::Certificate;
use x509_cert::der::{Encode, EncodePem};

use std::time::{Duration, SystemTime};

use yubikey::piv::{RetiredSlotId, SlotId};

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

/// The RSA counterpart: openssl enciphers the content key to the 9D certificate with RSA
/// key transport, which is what `keyEncipherment` allows.
#[test]
#[cfg_attr(not(has_openssl), ignore = "openssl not found in PATH")]
fn openssl_encrypts_to_rsa_key_management_cert() {
    let chain = alice()
        .with_algorithm(Algorithm::Rsa2048)
        .certify(CertificateKind::Chain)
        .unwrap();
    let (slot, cert) = &chain.leaves[2];
    assert_eq!(*slot, SlotId::KeyManagement);

    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let recipient = dir.join("9d.pem");
    let message = dir.join("msg.txt");
    let enveloped = dir.join("msg.p7m");
    std::fs::write(&recipient, cert.to_pem(x509_cert::der::pem::LineEnding::LF).unwrap()).unwrap();
    std::fs::write(&message, b"hello").unwrap();

    let output = std::process::Command::new("openssl")
        .args(["cms", "-encrypt", "-aes256", "-in"])
        .arg(&message)
        .arg("-out")
        .arg(&enveloped)
        .args(["-outform", "DER"])
        .arg(&recipient)
        .output()
        .expect("openssl vanished since the build.rs probe ran");
    assert!(
        output.status.success(),
        "openssl cms -encrypt failed for the RSA key management certificate:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );

    let parsed = std::process::Command::new("openssl")
        .args(["asn1parse", "-inform", "DER", "-in"])
        .arg(&enveloped)
        .output()
        .unwrap();
    let parsed = String::from_utf8_lossy(&parsed.stdout);
    assert!(
        parsed.contains("rsaEncryption"),
        "expected RSA key transport in the enveloped data:\n{parsed}"
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
