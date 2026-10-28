//! The chain as other tools see it: OpenSSL, NSS and friends validate it offline.

use crate::{alice, device, list_url};

use mind_the_gap::piv::{CertificateKind, SeededSmartcard};
use mind_the_gap::revocation::RevocationKind;
use mind_the_gap::role::KeyRole;
use mind_the_gap::seed::{Algorithm, CardSerial, KeyPath, Seeds};

use x509_cert::Certificate;
use x509_cert::der::EncodePem;

use yubikey::piv::SlotId;

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
        let purposes = [("sslclient", 0usize), ("smimesign", 1), ("any", 2)];

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

/// No public material names the device or its generation: neither the subkey id nor the
/// date as written appears in the bytes of any certificate of a device's chain, of either
/// revocation list, or of the URL the issuing authority's list is at, two tiers or three.
///
/// Public material carries no device label, as on OpenPGP: every card of an identity has the
/// identity's subject on its person-bound certificates, which its keys tell apart. The date
/// is in the validity alone, as UTCTime, which is a different text.
#[test]
fn no_public_material_names_the_device() {
    use x509_cert::crl::CertificateList;
    use x509_cert::der::{DecodePem, Encode};

    let id = "laptop-7f3e";
    let date = "2026-05-01";
    let path = KeyPath { subkey: Some(id.into()), date: Some(date.parse().unwrap()) };
    let contains = |haystack: &[u8], needle: &str| {
        haystack
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
    };
    let list = |pem: &str| {
        CertificateList::<x509_cert::certificate::Rfc5280>::from_pem(pem.as_bytes())
            .unwrap()
            .to_der()
            .unwrap()
    };

    for intermediate in [false, true] {
        let card = SeededSmartcard::new(Seeds::one(&[1u8; 32]), path.clone(), "Alice".into())
            .add_email("alice@example.com")
            .unwrap()
            .with_crl_url("http://example.org/alice.crl")
            .unwrap()
            .with_intermediate(intermediate);
        let chain = card.certify(CertificateKind::Chain).unwrap();

        let mut published: Vec<(String, Vec<u8>)> = chain
            .iter()
            .map(|cert| (chain.name_of(cert), cert.to_der().unwrap()))
            .collect();
        published
            .push(("the root's list".into(), list(&card.current_revocation_list(None).unwrap())));
        published.push((
            "the root's list revoking the device".into(),
            list(
                &card
                    .revocation_list(RevocationKind::Subkeys, 1, None)
                    .unwrap(),
            ),
        ));
        if let Some((suffix, issuing)) = card.issuing_revocation_list().unwrap() {
            published.push(("the issuing authority's list".into(), list(&issuing)));
            published.push(("the issuing authority's list suffix".into(), suffix.into_bytes()));
        }
        assert_eq!(published.len(), if intermediate { 9 } else { 6 });

        for (what, bytes) in &published {
            for needle in [id, "laptop", "7f3e", date, "20260501"] {
                assert!(
                    !contains(bytes, needle),
                    "{what} names the device: {needle} (intermediate={intermediate})"
                );
            }
        }
        for (slot, leaf) in &chain.leaves {
            assert_eq!(
                leaf.tbs_certificate().subject().to_string(),
                "CN=Alice",
                "{slot:?} is not the identity's subject (intermediate={intermediate})"
            );
        }
    }
}

/// Every card names the scheme that produced it.
///
/// The marker is on the published identifier rather than in a derivation label: relabelling
/// already moves every key, so a version in the path would separate nothing, whereas an
/// identifier that names its own scheme can be read off a card and understood.
#[test]
fn identifiers_name_their_scheme() {
    let nine_e = alice()
        .card_authentication_certificate(Algorithm::P256, &CardSerial::piv(12345678))
        .unwrap();
    let subject = nine_e.tbs_certificate().subject().to_string();
    assert!(subject.contains("PIV Card mtg1:"), "{subject}");
}

/// Write a PEM file in `dir`
fn write_pem<T: EncodePem>(dir: &std::path::Path, name: &str, value: &T) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, value.to_pem(x509_cert::der::pem::LineEnding::LF).unwrap()).unwrap();
    path
}

/// Run openssl, which the build.rs probe found
fn openssl(args: &[&std::ffi::OsStr]) -> std::process::Output {
    // Gated by cfg(has_openssl): a spawn failure here means the build.rs probe went
    // stale, which must fail loudly, not pass silently (see build.rs)
    std::process::Command::new("openssl")
        .args(args)
        .output()
        .expect("openssl vanished since the build.rs probe ran")
}

/// The 9E certificate is its own issuer, and OpenSSL takes it as one: a self-signed
/// certificate whose key is the card's, for a reader that pins it
#[test]
#[cfg_attr(not(has_openssl), ignore = "openssl not found in PATH")]
fn openssl_verifies_the_self_signed_card_authentication_certificate() {
    for algorithm in [Algorithm::P256, Algorithm::Curve25519] {
        let nine_e = alice()
            .with_algorithm(algorithm)
            .card_authentication_certificate(algorithm, &CardSerial::piv(12345678))
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = write_pem(dir.path(), "9e.pem", &nine_e);
        let output = openssl(&[
            "verify".as_ref(),
            "-x509_strict".as_ref(),
            "-check_ss_sig".as_ref(),
            "-CAfile".as_ref(),
            path.as_os_str(),
            path.as_os_str(),
        ]);
        assert!(
            output.status.success(),
            "openssl verify failed for the {algorithm:?} 9E certificate:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

/// Verify `leaf` against `root` with openssl, with a revocation list and an untrusted issuing
/// authority where given; the result and everything openssl said
fn verify_with(
    root: &std::path::Path,
    crl: Option<&std::path::Path>,
    untrusted: Option<&std::path::Path>,
    leaf: &std::path::Path,
) -> (bool, String) {
    let mut args: Vec<&std::ffi::OsStr> =
        vec!["verify".as_ref(), "-CAfile".as_ref(), root.as_os_str()];
    if let Some(crl) = crl {
        args.extend(["-crl_check".as_ref(), "-CRLfile".as_ref(), crl.as_os_str()]);
    }
    if let Some(untrusted) = untrusted {
        args.extend(["-untrusted".as_ref(), untrusted.as_os_str()]);
    }
    args.push(leaf.as_os_str());
    let output = openssl(&args);
    let said = String::from_utf8_lossy(&output.stdout).into_owned()
        + &String::from_utf8_lossy(&output.stderr);
    (output.status.success(), said)
}

/// A revocation list is what OpenSSL checks a chain against: signed by the root, it turns a
/// verification of the revoked certificates into a failure and leaves the others standing
#[test]
#[cfg_attr(not(has_openssl), ignore = "openssl not found in PATH")]
fn openssl_refuses_what_the_revocation_list_revokes() {
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();

    // Two tiers: the device's own certificates are revoked, the shared decryption key's not
    let card = device("laptop");
    let chain = card.certify(CertificateKind::Chain).unwrap();
    let root = write_pem(dir, "root.pem", &chain.root);
    let crl = dir.join("crl.pem");
    std::fs::write(
        &crl,
        card.revocation_list(RevocationKind::Subkeys, 2, None)
            .unwrap(),
    )
    .unwrap();

    let parsed = openssl(&[
        "crl".as_ref(),
        "-noout".as_ref(),
        "-text".as_ref(),
        "-in".as_ref(),
        crl.as_os_str(),
    ]);
    let text = String::from_utf8_lossy(&parsed.stdout);
    assert!(parsed.status.success() && text.contains("Key Compromise"), "{text}");

    for (index, (slot, leaf)) in chain.leaves.iter().enumerate() {
        let leaf = write_pem(dir, &format!("leaf{index}.pem"), leaf);
        assert!(
            verify_with(&root, None, None, &leaf).0,
            "{slot:?} does not verify without the list"
        );
        let (ok, said) = verify_with(&root, Some(&crl), None, &leaf);
        if *slot == SlotId::KeyManagement {
            assert!(ok, "the shared 9D was revoked with the device:\n{said}");
        } else {
            assert!(!ok && said.contains("revoked"), "{slot:?} survived its revocation:\n{said}");
        }
    }

    // Three tiers: the device's issuing authority is revoked, which takes everything it issued
    // with it; a relying party checks the authority against the root's list
    let card = device("laptop").with_intermediate(true);
    let chain = card.certify(CertificateKind::Chain).unwrap();
    let root = write_pem(dir, "root3.pem", &chain.root);
    let sub = write_pem(dir, "sub3.pem", chain.intermediate.as_ref().unwrap());
    std::fs::write(
        &crl,
        card.revocation_list(RevocationKind::Subkeys, 3, None)
            .unwrap(),
    )
    .unwrap();
    let leaf = write_pem(dir, "leaf3.pem", &chain.leaves[0].1);
    assert!(verify_with(&root, None, Some(&sub), &leaf).0);
    let (ok, said) = verify_with(&root, Some(&crl), None, &sub);
    assert!(!ok && said.contains("revoked"), "{said}");
}

/// Sibling devices under one root share a subject, and revocation tells them apart by serial:
/// the root's list revoking the laptop's authentication certificate makes OpenSSL refuse it
/// and still accept the desktop's, whose subject is the very same
#[test]
#[cfg_attr(not(has_openssl), ignore = "openssl not found in PATH")]
fn openssl_revokes_one_sibling_of_one_subject() {
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();

    let laptop = device("laptop");
    let lost = laptop.certify(CertificateKind::Chain).unwrap();
    let kept = device("desktop").certify(CertificateKind::Chain).unwrap();
    assert_eq!(lost.root, kept.root, "siblings under two roots");
    let root = write_pem(dir, "root.pem", &lost.root);
    let (slot, lost) = &lost.leaves[0];
    let (_, kept) = &kept.leaves[0];
    assert_eq!(*slot, SlotId::Authentication);
    assert_eq!(lost.tbs_certificate().subject(), kept.tbs_certificate().subject());
    assert_ne!(lost.tbs_certificate().serial_number(), kept.tbs_certificate().serial_number());

    let crl = dir.join("crl.pem");
    std::fs::write(
        &crl,
        laptop
            .revocation_list(RevocationKind::Subkeys, 1, None)
            .unwrap(),
    )
    .unwrap();
    let lost = write_pem(dir, "lost.pem", lost);
    let kept = write_pem(dir, "kept.pem", kept);

    let (ok, said) = verify_with(&root, Some(&crl), None, &lost);
    assert!(!ok && said.contains("revoked"), "the revoked sibling verified:\n{said}");
    let (ok, said) = verify_with(&root, Some(&crl), None, &kept);
    assert!(ok, "the sibling of the revoked certificate fell with it:\n{said}");
}

/// A verifier that checks every certificate of a three-tier chain takes the slot
/// certificates with both lists, the root's and the issuing authority's, and refuses them
/// once the root's list revokes the authority; without the authority's own list it refuses
/// them unrevoked, which is what that list is for
#[test]
#[cfg_attr(not(has_openssl), ignore = "openssl not found in PATH")]
fn every_certificate_of_three_tiers_has_its_list() {
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let card = device("laptop")
        .with_crl_url("http://example.org/alice.crl")
        .unwrap()
        .with_intermediate(true);
    let chain = card.certify(CertificateKind::Chain).unwrap();
    let root = write_pem(dir, "root.pem", &chain.root);
    let sub = write_pem(dir, "sub.pem", chain.intermediate.as_ref().unwrap());
    let leaf = write_pem(dir, "leaf.pem", &chain.leaves[0].1);
    let (_, issuing) = card.issuing_revocation_list().unwrap().unwrap();
    assert_eq!(issuing, card.issuing_revocation_list().unwrap().unwrap().1, "not the same bytes");

    let verify = |lists: &[String]| {
        let crls = dir.join("crls.pem");
        std::fs::write(&crls, lists.concat()).unwrap();
        let output = openssl(&[
            "verify".as_ref(),
            "-crl_check_all".as_ref(),
            "-CAfile".as_ref(),
            root.as_os_str(),
            "-untrusted".as_ref(),
            sub.as_os_str(),
            "-CRLfile".as_ref(),
            crls.as_os_str(),
            leaf.as_os_str(),
        ]);
        let said = String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr);
        (output.status.success(), said)
    };
    let current = card.current_revocation_list(None).unwrap();
    let (ok, said) = verify(&[current.clone(), issuing.clone()]);
    assert!(ok, "an unrevoked three-tier chain did not verify:\n{said}");
    let (ok, said) = verify(&[current]);
    assert!(!ok && said.contains("unable to get certificate CRL"), "{said}");

    let revoked = card
        .revocation_list(RevocationKind::Subkeys, 3, None)
        .unwrap();
    let (ok, said) = verify(&[revoked, issuing]);
    assert!(
        !ok && said.contains("revoked"),
        "the revoked authority's certificates verified:\n{said}"
    );
}

/// NSS, which Firefox and Thunderbird run, takes the same three-tier chain only with both
/// lists when it is told to require fresh revocation information for every certificate,
/// and refuses it once the root's list revokes the issuing authority. vfychain and crlutil
/// ship with certutil, in NSS's tools.
#[test]
#[cfg_attr(not(has_certutil), ignore = "certutil not found in PATH")]
fn nss_checks_every_certificate_of_three_tiers() {
    use x509_cert::crl::CertificateList;
    use x509_cert::der::{DecodePem, Encode};

    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let card = device("laptop")
        .with_crl_url("http://example.org/alice.crl")
        .unwrap()
        .with_intermediate(true);
    let chain = card.certify(CertificateKind::Chain).unwrap();
    let root = write_pem(dir, "root.pem", &chain.root);
    let sub = write_pem(dir, "sub.pem", chain.intermediate.as_ref().unwrap());
    let leaf = write_pem(dir, "leaf.pem", &chain.leaves[0].1);
    let (_, issuing) = card.issuing_revocation_list().unwrap().unwrap();

    let tool = |program: &str, args: &[&std::ffi::OsStr]| {
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .unwrap_or_else(|err| panic!("cannot run {program}: {err}"));
        let said = String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr);
        (output.status.success(), said)
    };
    // A fresh database each time, holding the root as trusted for clients, the issuing
    // authority, and the lists given, which crlutil takes in DER
    let verify = |name: &str, lists: &[&str]| {
        let db_dir = dir.join(name);
        std::fs::create_dir(&db_dir).unwrap();
        let db = format!("sql:{}", db_dir.display());
        let db: &std::ffi::OsStr = db.as_ref();
        let (ok, said) = tool(
            "certutil",
            &[
                "-N".as_ref(),
                "-d".as_ref(),
                db,
                "--empty-password".as_ref(),
            ],
        );
        assert!(ok, "{said}");
        for (nick, trust, file) in [("root", "CT,CT,CT", &root), ("sub", ",,", &sub)] {
            let (ok, said) = tool(
                "certutil",
                &[
                    "-A".as_ref(),
                    "-d".as_ref(),
                    db,
                    "-n".as_ref(),
                    nick.as_ref(),
                    "-t".as_ref(),
                    trust.as_ref(),
                    "-a".as_ref(),
                    "-i".as_ref(),
                    file.as_os_str(),
                ],
            );
            assert!(ok, "{said}");
        }
        for (index, list) in lists.iter().enumerate() {
            let der = CertificateList::<x509_cert::certificate::Rfc5280>::from_pem(list.as_bytes())
                .unwrap()
                .to_der()
                .unwrap();
            let file = db_dir.join(format!("list{index}.der"));
            std::fs::write(&file, der).unwrap();
            let (ok, said) = tool(
                "crlutil",
                &[
                    "-I".as_ref(),
                    "-d".as_ref(),
                    db,
                    "-t".as_ref(),
                    "1".as_ref(),
                    "-i".as_ref(),
                    file.as_os_str(),
                ],
            );
            assert!(ok, "{said}");
        }
        // libpkix, a TLS client certificate, CRLs required fresh for the leaf and the chain
        let check: Vec<&str> = "-pp -u 0 -g leaf -h requireFreshInfo -m crl -s requireFreshInfo \
             -g chain -h requireFreshInfo -m crl -a"
            .split_whitespace()
            .collect();
        let mut args: Vec<&std::ffi::OsStr> = vec!["-d".as_ref(), db];
        args.extend(check.iter().map(|arg| -> &std::ffi::OsStr { arg.as_ref() }));
        args.push(leaf.as_os_str());
        tool("vfychain", &args)
    };

    let current = card.current_revocation_list(None).unwrap();
    let (ok, said) = verify("both", &[&current, &issuing]);
    assert!(ok, "NSS refused an unrevoked three-tier chain:\n{said}");
    let (ok, said) = verify("root-only", &[&current]);
    assert!(!ok, "NSS took the chain without the issuing authority's list:\n{said}");
    let revoked = card
        .revocation_list(RevocationKind::Subkeys, 3, None)
        .unwrap();
    let (ok, said) = verify("revoked", &[&revoked, &issuing]);
    assert!(!ok && said.contains("revoked"), "NSS took a revoked authority's certificate:\n{said}");
}

/// What a revocation list revokes, by kind and choice of keys: a device's own keys, the
/// decryption key only when chosen alone, everything for the whole identity
#[test]
fn revocation_lists_revoke_what_was_chosen() {
    use x509_cert::crl::CertificateList;
    use x509_cert::der::DecodePem;

    let revoked = |card: SeededSmartcard, kind| {
        let pem = card.revocation_list(kind, 0, None).unwrap();
        CertificateList::from_pem(pem.as_bytes())
            .unwrap()
            .tbs_cert_list
            .revoked_certificates
            .unwrap_or_default()
            .into_iter()
            .map(|entry| entry.serial_number)
            .collect::<Vec<_>>()
    };
    let serials = |card: SeededSmartcard| {
        card.certify(CertificateKind::Chain)
            .unwrap()
            .leaves
            .into_iter()
            .map(|(slot, cert)| (slot, cert.tbs_certificate().serial_number().clone()))
            .collect::<Vec<_>>()
    };
    let all = serials(device("laptop"));

    let device_only = revoked(device("laptop"), RevocationKind::Subkeys);
    assert_eq!(device_only, vec![all[0].1.clone(), all[1].1.clone()]);

    let identity = revoked(device("laptop"), RevocationKind::Certificate);
    assert_eq!(
        identity,
        all.iter()
            .map(|(_, serial)| serial.clone())
            .collect::<Vec<_>>()
    );

    let decryption = device("laptop").with_keys(&[KeyRole::Decryption]).unwrap();
    assert_eq!(revoked(decryption, RevocationKind::Subkeys), vec![all[2].1.clone()]);
}

/// A revocation list published at a URL holds every revocation so far: the next one is made
/// from the last, keeps its entries, and refuses a list another identity signed
#[test]
fn revocation_lists_accumulate_and_refuse_strangers() {
    use x509_cert::crl::CertificateList;
    use x509_cert::der::DecodePem;

    let url = "http://example.org/alice.crl";
    let entries = |pem: &str| {
        CertificateList::<x509_cert::certificate::Rfc5280>::from_pem(pem.as_bytes())
            .unwrap()
            .tbs_cert_list
            .revoked_certificates
            .unwrap_or_default()
            .len()
    };
    let laptop = device("laptop").with_crl_url(url).unwrap();
    let empty = laptop.current_revocation_list(None).unwrap();
    assert_eq!(entries(&empty), 0);

    // RFC 5280 5.2: every list names the key that signed it and carries its number
    let extensions: Vec<String> =
        CertificateList::<x509_cert::certificate::Rfc5280>::from_pem(empty.as_bytes())
            .unwrap()
            .tbs_cert_list
            .crl_extensions
            .unwrap_or_default()
            .iter()
            .map(|extension| extension.extn_id.to_string())
            .collect();
    assert_eq!(extensions, ["2.5.29.35", "2.5.29.20"], "authority key id and CRL number");

    let first = laptop
        .revocation_list(RevocationKind::Subkeys, 2, Some(empty.as_bytes()))
        .unwrap();
    let phone = device("phone").with_crl_url(url).unwrap();
    let second = phone
        .revocation_list(RevocationKind::Subkeys, 3, Some(first.as_bytes()))
        .unwrap();
    assert_eq!(entries(&second), 4, "the laptop's revocations were dropped");
    // Revoking the same keys again adds nothing
    let again = laptop
        .revocation_list(RevocationKind::Subkeys, 2, Some(second.as_bytes()))
        .unwrap();
    assert_eq!(entries(&again), 4);
    assert_eq!(
        entries(
            &laptop
                .current_revocation_list(Some(again.as_bytes()))
                .unwrap()
        ),
        4
    );

    // A list at the URL is due again within the year; one handed over by hand never is
    let due = |pem: &str| {
        CertificateList::<x509_cert::certificate::Rfc5280>::from_pem(pem.as_bytes())
            .unwrap()
            .tbs_cert_list
            .next_update
            .unwrap()
    };
    assert_ne!(due(&second), x509_cert::time::Time::INFINITY);
    let by_hand = device("laptop").current_revocation_list(None).unwrap();
    assert_eq!(due(&by_hand), x509_cert::time::Time::INFINITY);

    // Another identity's list, or this one's altered, is not this identity's to extend
    let stranger =
        SeededSmartcard::new(Seeds::one(&[9u8; 32]), KeyPath::default(), "Mallory".into())
            .current_revocation_list(None)
            .unwrap();
    assert!(
        laptop
            .current_revocation_list(Some(stranger.as_bytes()))
            .is_err()
    );
}

/// A previous list is read in either form `publish --part crl` writes, DER as PEM: its entries
/// are kept, its date is the floor the clock is held to, and one that parses as neither is
/// refused rather than read as no list
#[test]
fn previous_lists_are_read_as_pem_or_der() {
    use x509_cert::crl::CertificateList;
    use x509_cert::der::{Decode, DecodePem, Encode};
    type List = CertificateList<x509_cert::certificate::Rfc5280>;

    let url = "http://example.org/alice.crl";
    let entries = |pem: &str| {
        List::from_pem(pem.as_bytes())
            .unwrap()
            .tbs_cert_list
            .revoked_certificates
            .unwrap_or_default()
            .len()
    };
    let laptop = device("laptop").with_crl_url(url).unwrap();
    let phone = device("phone").with_crl_url(url).unwrap();
    let first = laptop
        .revocation_list(RevocationKind::Subkeys, 2, None)
        .unwrap();
    let der = List::from_pem(first.as_bytes()).unwrap().to_der().unwrap();
    assert_eq!(
        entries(
            &phone
                .revocation_list(RevocationKind::Subkeys, 3, Some(&der))
                .unwrap()
        ),
        4
    );
    assert_eq!(entries(&laptop.current_revocation_list(Some(&der)).unwrap()), 2);

    // A list dated after the clock means the clock is wrong, in either form
    let mut future = List::from_der(&der).unwrap();
    let decade = std::time::Duration::from_secs(10 * 365 * 86_400);
    future.tbs_cert_list.this_update =
        x509_cert::time::Time::try_from(std::time::SystemTime::now() + decade).unwrap();
    let forms = [
        future.to_der().unwrap(),
        future
            .to_pem(x509_cert::der::pem::LineEnding::LF)
            .unwrap()
            .into_bytes(),
    ];
    for previous in &forms {
        let err = laptop
            .revocation_list(RevocationKind::Subkeys, 2, Some(previous))
            .unwrap_err();
        assert!(err.to_string().contains("The clock reads"), "{err}");
        let err = laptop.current_revocation_list(Some(previous)).unwrap_err();
        assert!(err.to_string().contains("The clock reads"), "{err}");
    }

    for garbage in [
        b"-----BEGIN X509 CRL-----\nnot a list\n-----END X509 CRL-----\n".as_slice(),
        b"\x30\x03\x02\x01\x00",
        b"no list at all",
    ] {
        let err = laptop.current_revocation_list(Some(garbage)).unwrap_err();
        assert!(err.to_string().contains("does not parse"), "{err}");
        let err = laptop
            .revocation_list(RevocationKind::Subkeys, 2, Some(garbage))
            .unwrap_err();
        assert!(err.to_string().contains("does not parse"), "{err}");
    }
}

/// The distribution point goes on what the root issues itself: the slot certificates, or
/// the issuing authority in their place, never behind it, and never on the root or 9E
#[test]
fn distribution_points_name_the_roots_list() {
    use x509_cert::ext::pkix::CrlDistributionPoints;

    let has = |cert: &x509_cert::Certificate| {
        cert.tbs_certificate()
            .get_extension::<CrlDistributionPoints>()
            .unwrap()
            .is_some()
    };
    let url = "http://example.org/alice.crl";
    let card = device("laptop").with_crl_url(url).unwrap();
    let chain = card.certify(CertificateKind::Chain).unwrap();
    assert!(!has(&chain.root));
    assert!(chain.leaves.iter().all(|(_, cert)| has(cert)));
    // The root's list is published under the stem with the root's suffix, the algorithm
    assert_eq!(card.revocation_list_suffix(), "-p256");
    for (slot, cert) in &chain.leaves {
        assert_eq!(list_url(cert), "http://example.org/alice-p256.crl", "{slot:?}");
    }

    let card = device("laptop")
        .with_crl_url(url)
        .unwrap()
        .with_intermediate(true);
    let chain = card.certify(CertificateKind::Chain).unwrap();
    assert!(has(chain.intermediate.as_ref().unwrap()));
    assert_eq!(list_url(chain.intermediate.as_ref().unwrap()), "http://example.org/alice-p256.crl");
    // Behind an issuing authority, the slot certificates name that authority's own list, at
    // the URL it is published under
    let (suffix, _) = card.issuing_revocation_list().unwrap().unwrap();
    for (slot, cert) in &chain.leaves {
        assert_eq!(list_url(cert), format!("http://example.org/alice{suffix}.crl"), "{slot:?}");
    }

    assert!(device("laptop").with_crl_url("example.org").is_err());
}

/// Two algorithms of one identity given one URL have roots of their own names, and publish
/// their lists apart: each list's URL carries the root's algorithm
#[test]
fn algorithms_publish_their_lists_apart() {
    let url = "http://example.org/alice.crl";
    let names = [Algorithm::P256, Algorithm::Curve25519, Algorithm::Rsa2048].map(|algorithm| {
        let card = device("laptop")
            .with_algorithm(algorithm)
            .with_crl_url(url)
            .unwrap();
        let chain = card.certify(CertificateKind::Chain).unwrap();
        let urls: Vec<_> = chain
            .leaves
            .iter()
            .map(|(_, leaf)| list_url(leaf))
            .collect();
        assert!(urls.iter().all(|url| *url == urls[0]), "{urls:?}");
        (chain.root.tbs_certificate().subject().to_string(), urls[0].clone())
    });
    assert_eq!(
        names,
        [
            (
                "CN=Alice PIV Root CA p256".to_string(),
                "http://example.org/alice-p256.crl".to_string()
            ),
            (
                "CN=Alice PIV Root CA curve25519".to_string(),
                "http://example.org/alice-curve25519.crl".to_string()
            ),
            (
                "CN=Alice PIV Root CA rsa2048".to_string(),
                "http://example.org/alice-rsa2048.crl".to_string()
            ),
        ]
    );
}
/// A URL the lists cannot be named from is refused, by the builder and by the function the
/// command line judges it with before any seed is stretched; each refusal says what to
/// change, and following it gives a URL that is taken
#[test]
fn list_urls_name_a_list() {
    for url in [
        "http://example.org/alice.crl",
        "https://pki.example.org/lists/alice_2.crl",
        "file:///srv/lists/alice.crl",
        "FILE:///srv/alice.crl",
        "http://example.org/my%20lists/alice.crl",
        "http://example.org:8080/a/b/alice~1.crl",
    ] {
        assert!(device("laptop").with_crl_url(url).is_ok(), "{url} was refused");
    }
    for (url, why) in [
        ("example.org/alice.crl", "is no URL"),
        ("1http://example.org/alice.crl", "names no scheme"),
        ("http://example.org", "has no path"),
        ("http:///jane.crl", "names no host"),
        ("https:///lists/jane.crl", "names no host"),
        ("http://example.org//jane.crl", "empty segment"),
        ("http://example.org/lists//jane.crl", "empty segment"),
        ("http://example.org/alice", "does not end in a list's name"),
        ("http://example.org/alice.pem", "does not end in a list's name"),
        ("http://alice.crl", "has no path"),
        ("http://example.org/alice.crl/", "does not end in a list's name"),
        ("http://example.org/.crl", "does not end in a list's name"),
        ("http://example.org/al%20ice.crl", "nothing in it is percent-encoded"),
        ("http://example.org/al ice.crl", "nothing in it is percent-encoded"),
        ("http://example.org/älice.crl", "nothing in it is percent-encoded"),
        ("http://example.org/alice.crl?version=2", "query or a fragment"),
        ("http://example.org/alice.crl#top", "query or a fragment"),
        ("http://example.org/my lists/alice.crl", "percent-encode it there"),
        ("http://exämple.org/alice.crl", "percent-encode it there"),
    ] {
        let err = match device("laptop").with_crl_url(url) {
            Ok(_) => panic!("{url} was taken"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains(why), "{url}: {err}");
        assert_eq!(
            mind_the_gap::piv::refuse_unfit_crl_url(url)
                .unwrap_err()
                .to_string(),
            err
        );
    }
    // The list's name takes no percent-encoding, the path before it does
    let err = mind_the_gap::piv::refuse_unfit_crl_url("http://example.org/al ice.crl")
        .unwrap_err()
        .to_string();
    assert!(!err.contains("percent-encode it there"), "{err}");
}

/// A key out of the gap is the key its certificate names: openssl decrypts the PKCS#8 with
/// the passphrase, on every algorithm, and finds the certified public key in it
#[test]
#[cfg_attr(not(has_openssl), ignore = "openssl not found in PATH")]
fn openssl_reads_the_exported_keys() {
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    for algorithm in [
        Algorithm::P256,
        Algorithm::P384,
        Algorithm::Curve25519,
        Algorithm::Rsa2048,
    ] {
        let card = device("laptop").with_algorithm(algorithm);
        for (role, key, cert) in card.secret_keys(Some("p\u{e4}ss phrase")).unwrap() {
            assert!(key.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
            let key_file = dir.join(format!("{role}.key"));
            let cert_file = dir.join(format!("{role}.pem"));
            std::fs::write(&key_file, key.as_bytes()).unwrap();
            std::fs::write(&cert_file, cert.as_bytes()).unwrap();
            let from_key = openssl(&[
                "pkey".as_ref(),
                "-in".as_ref(),
                key_file.as_os_str(),
                "-passin".as_ref(),
                "pass:p\u{e4}ss phrase".as_ref(),
                "-pubout".as_ref(),
            ]);
            assert!(
                from_key.status.success(),
                "{algorithm:?} {role}: {}",
                String::from_utf8_lossy(&from_key.stderr)
            );
            let from_cert = openssl(&[
                "x509".as_ref(),
                "-in".as_ref(),
                cert_file.as_os_str(),
                "-pubkey".as_ref(),
                "-noout".as_ref(),
            ]);
            assert_eq!(from_key.stdout, from_cert.stdout, "{algorithm:?} {role}: another key");
        }
    }

    // Every key is encrypted alike, and each try costs openssl the full 600,000 rounds, so a
    // wrong passphrase is tried on one of them
    let wrong = openssl(&[
        "pkey".as_ref(),
        "-in".as_ref(),
        dir.join("authentication.key").as_os_str(),
        "-passin".as_ref(),
        "pass:guess".as_ref(),
    ]);
    assert!(!wrong.status.success(), "opened with a wrong passphrase");

    // Without a passphrase the same key comes out as plain PKCS#8
    let (_, key, _) = device("laptop").secret_keys(None).unwrap().remove(0);
    assert!(key.starts_with("-----BEGIN PRIVATE KEY-----"));
}
