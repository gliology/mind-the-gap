//! What leaves the gap: publish, ungap, trust and revoke, and the files they write.

use crate::{OTHER_PHRASE, WHO, bin, mode, root_subject, seeded, stderr, stdout};

use std::path::Path;

/// Publishing writes each applet's material in each format, named to tell them apart.
#[test]
fn publish_writes_every_format() {
    let dir = tempfile::tempdir().unwrap();
    let to = |name: &str| format!("{}/{name}/", dir.path().display());

    let out = seeded(
        &[
            &["publish", "-k", "laptop"][..],
            &WHO,
            &["--to", &to("text")],
        ]
        .concat(),
    );
    assert!(out.status.success(), "text publish failed:\n{}", stderr(&out));
    let chain = std::fs::read_to_string(dir.path().join("text/piv-chain.pem")).unwrap();
    assert_eq!(chain.matches("BEGIN CERTIFICATE").count(), 4, "not the root and three slots");
    let cert = std::fs::read_to_string(dir.path().join("text/pgp.asc")).unwrap();
    assert!(cert.contains("BEGIN PGP PUBLIC KEY BLOCK"));

    let out = seeded(
        &[
            &["publish", "--format", "binary"][..],
            &WHO,
            &["--to", &to("bin")],
        ]
        .concat(),
    );
    assert!(out.status.success(), "binary publish failed:\n{}", stderr(&out));
    let names: Vec<_> = std::fs::read_dir(dir.path().join("bin"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(names.contains(&"pgp.gpg".to_string()), "{names:?}");
    assert_eq!(names.iter().filter(|name| name.ends_with(".der")).count(), 4, "{names:?}");

    let out = seeded(
        &[
            &["publish", "--format", "ssh"][..],
            &WHO,
            &["--to", &to("ssh")],
        ]
        .concat(),
    );
    assert!(out.status.success(), "ssh publish failed:\n{}", stderr(&out));
    let piv = std::fs::read_to_string(dir.path().join("ssh/piv-authentication.pub")).unwrap();
    let pgp = std::fs::read_to_string(dir.path().join("ssh/pgp-authentication.pub")).unwrap();
    assert!(piv.starts_with("ecdsa-sha2-nistp256 "), "{piv}");
    assert!(pgp.starts_with("ssh-ed25519 "), "{pgp}");
    assert!(piv.trim_end().ends_with(" alice@example.com"), "{piv}");

    // SSH takes the authentication key whatever the part names, on both applets
    for part in ["identity", "keys"] {
        let out = seeded(
            &[
                &["publish", "--part", part, "--format", "ssh"][..],
                &WHO,
                &["--to", &to(&format!("ssh-{part}"))],
            ]
            .concat(),
        );
        assert!(out.status.success(), "{part} ssh publish failed:\n{}", stderr(&out));
        let read = |name: &str| {
            std::fs::read_to_string(dir.path().join(format!("ssh-{part}/{name}"))).unwrap()
        };
        assert_eq!(read("piv-authentication.pub"), piv, "the {part} part changed the PIV key");
        assert_eq!(read("pgp-authentication.pub"), pgp, "the {part} part changed the pgp key");
    }

    let out = seeded(
        &[
            &["publish", "--format", "wkd"][..],
            &WHO,
            &["--to", &to("wkd")],
        ]
        .concat(),
    );
    assert!(out.status.success(), "wkd publish failed:\n{}", stderr(&out));
    // z-base-32 of the SHA-1 of "alice", as gpg-wks-client lays a directory out
    let entry = dir
        .path()
        .join("wkd/example.com/hu/kei1q4tipxxu1yj79k9kfukdhfy631xe");
    assert!(entry.exists(), "no WKD entry for alice");
    assert!(dir.path().join("wkd/example.com/policy").exists(), "no WKD policy");
    assert_eq!(std::fs::read(entry).unwrap(), {
        let out = seeded(
            &[
                &["publish", "--app", "pgp", "--format", "binary"][..],
                &WHO,
                &["--to", "-"],
            ]
            .concat(),
        );
        out.stdout
    });
}

/// Public material may go to stdout; several pieces need a directory, not a file.
#[test]
fn publish_to_stdout_and_files() {
    let out = seeded(
        &[
            &["publish", "--app", "piv", "--part", "identity"][..],
            &WHO,
            &["--to", "-"],
        ]
        .concat(),
    );
    assert!(out.status.success(), "publish to stdout failed:\n{}", stderr(&out));
    assert_eq!(root_subject(&out.stdout), "CN=Alice PIV Root CA p256");

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("both.pem");
    let out = seeded(&[&["publish"][..], &WHO, &["--to", file.to_str().unwrap()]].concat());
    assert!(!out.status.success(), "two applets went into one file");
    assert!(stderr(&out).contains("need a directory"), "{}", stderr(&out));
}

/// Without `--to`, the chain comes out as QR codes, one per certificate, each named.
#[test]
fn chain_without_output_is_one_code_per_certificate() {
    let out = seeded(&[&["publish", "--app", "piv"][..], &WHO].concat());
    let text = stdout(&out);

    assert!(out.status.success(), "publish without --to failed: {:?}", out);
    for name in [
        "authentication slot 9A",
        "signature slot 9C",
        "key management slot 9D",
    ] {
        assert!(text.contains(name), "no code titled {name}:\n{text}");
    }
    assert!(text.contains("root CA"), "no code for the root:\n{text}");
}

/// Secret keys leave the gap only into a file of the owner's; without a pin they say so.
#[test]
fn ungap_restricts_the_file_and_warns_without_a_pin() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret.asc");

    let out = seeded(
        &[
            &["ungap", "--app", "pgp"][..],
            &WHO,
            &["--to", path.to_str().unwrap()],
        ]
        .concat(),
    );
    let err = stderr(&out);
    assert!(out.status.success(), "ungap failed:\n{err}");
    assert!(err.contains("UNENCRYPTED"), "no warning about the missing pin:\n{err}");
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("PRIVATE KEY BLOCK")
    );
    #[cfg(unix)]
    assert_eq!(mode(&path), 0o600, "secret export is not owner-only");

    let out = seeded(
        &[
            &["ungap", "--app", "pgp", "--pin", "a long secret"][..],
            &WHO,
            &["--to", path.to_str().unwrap()],
        ]
        .concat(),
    );
    assert!(out.status.success(), "ungap with a pin failed:\n{}", stderr(&out));
    assert!(!stderr(&out).contains("UNENCRYPTED"), "warned although protected");

    // Secret keys carry user ids, which take the emails
    let out = seeded(&[
        "ungap",
        "--app",
        "pgp",
        "-n",
        "Alice",
        "--to",
        path.to_str().unwrap(),
    ]);
    assert!(!out.status.success(), "ungap without emails exited zero");
    assert!(stderr(&out).contains("--emails"), "{}", stderr(&out));
}

/// A certificate of someone else's comes back certified by the identity.
#[test]
fn trust_certifies_another_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let [theirs, certified] = ["bob.asc", "certified.asc"].map(|name| dir.path().join(name));
    let mut cmd = bin();
    let out = cmd
        .args([
            "-s",
            OTHER_PHRASE,
            "publish",
            "--app",
            "pgp",
            "-n",
            "Bob",
            "-m",
            "bob@example.org",
        ])
        .args(["--to", theirs.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "Bob's certificate failed:\n{}", stderr(&out));

    let out = seeded(
        &[
            &["trust", theirs.to_str().unwrap(), "--level", "positive"][..],
            &WHO,
            &["--to", certified.to_str().unwrap()],
        ]
        .concat(),
    );
    let err = stderr(&out);
    assert!(out.status.success(), "trust failed:\n{err}");
    assert!(err.contains("Signing userid 'Bob <bob@example.org>'"), "{err}");
    assert!(
        std::fs::read_to_string(certified)
            .unwrap()
            .contains("BEGIN PGP PUBLIC KEY BLOCK")
    );
}

/// An OpenPGP revocation is a capability and written owner-only; a PIV revocation list is
/// signed when the keys are revoked, to be published, and written like any certificate.
#[test]
fn revoke_writes_capabilities_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let to = format!("{}/rev/", dir.path().display());
    let out = seeded(&[
        "revoke", "--kind", "subkeys", "-k", "laptop", "-n", "Alice", "--to", &to,
    ]);
    let err = stderr(&out);
    assert!(out.status.success(), "revoke failed:\n{err}");
    assert!(err.contains("Leaving the decryption subkey"), "the shared key was revoked:\n{err}");

    let crl = dir.path().join("rev/piv-revocation-p256.crl.pem");
    let pgp = dir.path().join("rev/pgp-revocation.asc");
    assert!(
        std::fs::read_to_string(&crl)
            .unwrap()
            .starts_with("-----BEGIN X509 CRL-----")
    );
    assert!(
        std::fs::read_to_string(&pgp)
            .unwrap()
            .contains("BEGIN PGP PUBLIC KEY BLOCK")
    );
    #[cfg(unix)]
    assert_eq!(mode(&pgp), 0o600, "{} is not owner-only", pgp.display());
    #[cfg(unix)]
    assert_ne!(mode(&crl), 0o600, "the revocation list is kept from being published");

    // What a revocation covers has no default
    let out = seeded(&["revoke", "-n", "Alice"]);
    assert!(!out.status.success(), "revoke without --kind ran");
    assert!(stderr(&out).contains("--kind"), "{}", stderr(&out));
}

/// The URLs every certificate in `pem` names for its issuer's revocation list
fn list_urls(pem: &[u8]) -> Vec<String> {
    use x509_cert::ext::pkix::CrlDistributionPoints;
    use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};

    let mut urls = Vec::new();
    for cert in x509_cert::Certificate::load_pem_chain(pem).unwrap() {
        let Some((_, points)) = cert
            .tbs_certificate()
            .get_extension::<CrlDistributionPoints>()
            .unwrap()
        else {
            continue;
        };
        let Some(DistributionPointName::FullName(names)) = &points.0[0].distribution_point else {
            panic!("no full name: {points:?}");
        };
        let [GeneralName::UniformResourceIdentifier(url)] = names.as_slice() else {
            panic!("not one URL: {names:?}");
        };
        urls.push(url.to_string());
    }
    urls
}

/// The names of the files in `dir`, sorted
fn files_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// `publish --part crl` writes every list a chain's certificates name, each file named with
/// the suffix its URL carries: the root's list by the algorithm, and with an issuing
/// authority its own list by the algorithm and the authority's tag, so that the files go up
/// as they are. Two algorithms of one identity have roots, URLs and files of their own.
#[test]
fn list_files_are_named_as_their_urls() {
    let dir = tempfile::tempdir().unwrap();
    let mut roots = Vec::new();
    let mut every_suffix = Vec::new();
    for algorithm in ["p256", "curve25519"] {
        for intermediate in [false, true] {
            let mut options = vec![
                "--app",
                "piv",
                "-k",
                "laptop",
                "--algorithm",
                algorithm,
                "--crl-url",
                "http://example.org/alice.crl",
            ];
            if intermediate {
                options.push("--intermediate");
            }
            let to =
                |what: &str| format!("{}/{algorithm}-{intermediate}-{what}/", dir.path().display());

            let out = seeded(
                &[
                    &["publish", "--part", "crl"][..],
                    &options,
                    &WHO,
                    &["--to", &to("crl")],
                ]
                .concat(),
            );
            assert!(out.status.success(), "publishing the lists failed:\n{}", stderr(&out));
            let mut files: Vec<String> =
                files_in(&dir.path().join(format!("{algorithm}-{intermediate}-crl")))
                    .iter()
                    .map(|file| {
                        file.strip_prefix("piv-revocation")
                            .and_then(|rest| rest.strip_suffix(".crl.pem"))
                            .unwrap_or_else(|| panic!("not a list's file: {file}"))
                            .to_string()
                    })
                    .collect();
            files.sort();

            let out = seeded(&[&["publish"][..], &options, &WHO, &["--to", &to("chain")]].concat());
            assert!(out.status.success(), "publishing the chain failed:\n{}", stderr(&out));
            let pem = std::fs::read(
                dir.path()
                    .join(format!("{algorithm}-{intermediate}-chain/piv-chain.pem")),
            )
            .unwrap();
            let mut urls: Vec<String> = list_urls(&pem)
                .iter()
                .map(|url| {
                    url.strip_prefix("http://example.org/alice")
                        .and_then(|rest| rest.strip_suffix(".crl"))
                        .unwrap_or_else(|| panic!("not a list's URL: {url}"))
                        .to_string()
                })
                .collect();
            urls.sort();
            urls.dedup();

            assert_eq!(files, urls, "{algorithm} intermediate={intermediate}");
            assert_eq!(files.len(), if intermediate { 2 } else { 1 }, "{files:?}");
            let root = format!("-{algorithm}");
            assert!(files.contains(&root), "no root list {root}: {files:?}");
            for suffix in &files {
                let tag = suffix.strip_prefix(&format!("{root}-issuing-"));
                assert!(
                    *suffix == root
                        || tag.is_some_and(|tag| tag.len() == 8
                            && tag
                                .bytes()
                                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))),
                    "neither the root's list nor an issuing authority's: {suffix}"
                );
            }
            every_suffix.extend(files);

            let out = seeded(
                &[
                    &["publish", "--part", "identity"][..],
                    &options,
                    &WHO,
                    &["--to", "-"],
                ]
                .concat(),
            );
            assert!(out.status.success(), "publishing the root failed:\n{}", stderr(&out));
            roots.push(root_subject(&out.stdout));
        }
    }
    assert_eq!(
        roots,
        [
            "CN=Alice PIV Root CA p256",
            "CN=Alice PIV Root CA p256",
            "CN=Alice PIV Root CA curve25519",
            "CN=Alice PIV Root CA curve25519",
        ]
    );
    // One root list per algorithm, and an issuing authority's list per algorithm
    every_suffix.sort();
    every_suffix.dedup();
    assert_eq!(every_suffix.len(), 4, "{every_suffix:?}");
}

/// The entries of the revocation list in `bytes`, PEM or DER
fn revoked(bytes: &[u8]) -> usize {
    use x509_cert::crl::CertificateList;
    use x509_cert::der::{Decode, DecodePem};
    let list = match bytes.starts_with(b"-----BEGIN") {
        true => CertificateList::<x509_cert::certificate::Rfc5280>::from_pem(bytes).unwrap(),
        false => CertificateList::<x509_cert::certificate::Rfc5280>::from_der(bytes).unwrap(),
    };
    list.tbs_cert_list
        .revoked_certificates
        .unwrap_or_default()
        .len()
}

/// Two algorithms of one identity keep their lists in one directory side by side, and each
/// `revoke` reads back and extends its own
#[test]
fn each_algorithm_keeps_its_own_list() {
    let dir = tempfile::tempdir().unwrap();
    let to = format!("{}/lists/", dir.path().display());
    let revoke = |algorithm: &str, device: &str| {
        let out = seeded(
            &[
                &[
                    "revoke",
                    "--app",
                    "piv",
                    "--kind",
                    "subkeys",
                    "--algorithm",
                    algorithm,
                    "-k",
                    device,
                    "--to",
                    &to,
                ][..],
                &WHO,
            ]
            .concat(),
        );
        assert!(out.status.success(), "revoking {device} on {algorithm} failed:\n{}", stderr(&out));
    };
    let entries = |algorithm: &str| {
        revoked(
            &std::fs::read(
                dir.path()
                    .join(format!("lists/piv-revocation-{algorithm}.crl.pem")),
            )
            .unwrap(),
        )
    };

    revoke("p256", "laptop");
    revoke("curve25519", "laptop");
    assert_eq!((entries("p256"), entries("curve25519")), (2, 2));
    revoke("p256", "phone");
    assert_eq!((entries("p256"), entries("curve25519")), (4, 2), "a list lost its entries");
    revoke("curve25519", "phone");
    assert_eq!((entries("p256"), entries("curve25519")), (4, 4), "a list lost its entries");
    assert_eq!(
        files_in(&dir.path().join("lists")),
        [
            "piv-revocation-curve25519.crl.pem",
            "piv-revocation-p256.crl.pem"
        ]
    );
}

/// `--format binary` writes each list as the DER its PEM holds, ready to serve at its URL,
/// into a directory, a file or stdout; a list kept as DER is read back as the previous one,
/// and QR codes carry the PEM
#[test]
fn lists_are_written_as_der_with_binary() {
    use x509_cert::crl::CertificateList;
    use x509_cert::der::{Decode, DecodePem};
    type List = CertificateList<x509_cert::certificate::Rfc5280>;

    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name);
    let options = [
        "--app",
        "piv",
        "-k",
        "laptop",
        "--intermediate",
        "--crl-url",
        "http://example.org/alice.crl",
    ];
    let publish = |format: &str, to: &str| {
        let out = seeded(
            &[
                &["publish", "--part", "crl", "--format", format][..],
                &options,
                &WHO,
                &["--to", to],
            ]
            .concat(),
        );
        assert!(out.status.success(), "publishing as {format} failed:\n{}", stderr(&out));
        out
    };

    publish("text", &format!("{}/", path("text").display()));
    publish("binary", &format!("{}/", path("binary").display()));
    let text = files_in(&path("text"));
    let binary = files_in(&path("binary"));
    assert_eq!(text.len(), 2, "{text:?}");
    assert_eq!(
        binary,
        text.iter()
            .map(|name| name.strip_suffix(".pem").unwrap().to_string())
            .collect::<Vec<_>>()
    );
    for (pem, der) in text.iter().zip(&binary) {
        let pem = List::from_pem(std::fs::read(path("text").join(pem)).unwrap()).unwrap();
        let der = List::from_der(&std::fs::read(path("binary").join(der)).unwrap()).unwrap();
        // The issuing authority's list is the same bytes whenever it is signed, the root's
        // is dated by the clock
        assert_eq!(pem.tbs_cert_list.issuer, der.tbs_cert_list.issuer);
        assert_eq!(pem.tbs_cert_list.revoked_certificates, der.tbs_cert_list.revoked_certificates);
        if pem.tbs_cert_list.next_update == Some(x509_cert::time::Time::INFINITY) {
            assert_eq!(pem, der, "the issuing authority's list differs as DER");
        }
    }

    // One list, without an issuing authority, to a file and to stdout
    let one = ["--app", "piv", "-k", "laptop"];
    let single = |format: &str, to: &str| {
        let out = seeded(
            &[
                &["publish", "--part", "crl", "--format", format][..],
                &one,
                &WHO,
                &["--to", to],
            ]
            .concat(),
        );
        assert!(out.status.success(), "{format} to {to} failed:\n{}", stderr(&out));
        out
    };
    let file = path("alice-p256.crl");
    single("binary", file.to_str().unwrap());
    let written = std::fs::read(&file).unwrap();
    assert!(List::from_der(&written).is_ok(), "not DER");
    let out = single("binary", "-");
    assert!(List::from_der(&out.stdout).is_ok(), "not DER on stdout");
    let out = single("text", "-");
    assert!(stdout(&out).starts_with("-----BEGIN X509 CRL-----"), "{}", stdout(&out));

    // A DER list at --to is the previous one: `revoke` keeps its entries, and writes PEM
    let revoke = |device: &str| {
        let out = seeded(
            &[
                &["revoke", "--kind", "subkeys", "-k", device][..],
                &one[..2],
                &WHO,
                &["--to", file.to_str().unwrap()],
            ]
            .concat(),
        );
        assert!(out.status.success(), "revoke failed:\n{}", stderr(&out));
    };
    revoke("laptop");
    assert_eq!(revoked(&std::fs::read(&file).unwrap()), 2);
    single("binary", file.to_str().unwrap());
    assert!(List::from_der(&std::fs::read(&file).unwrap()).is_ok(), "not DER");
    revoke("phone");
    assert_eq!(revoked(&std::fs::read(&file).unwrap()), 4, "the DER list's entries were lost");

    // A dry run names the list and writes nothing
    let out = seeded(
        &[
            &["revoke", "--kind", "subkeys", "--dry-run", "--to", "-"][..],
            &one,
            &WHO,
        ]
        .concat(),
    );
    assert!(out.status.success(), "the dry run failed:\n{}", stderr(&out));
    assert!(stdout(&out).contains("Would write the PIV revocation list"), "{}", stdout(&out));

    // QR codes are read as text, whatever the format
    let out = seeded(
        &[
            &["publish", "--part", "crl", "--format", "binary"][..],
            &one,
            &WHO,
        ]
        .concat(),
    );
    assert!(out.status.success(), "the codes failed:\n{}", stderr(&out));
    assert!(stdout(&out).contains("PIV revocation list"), "{}", stdout(&out));

    // An SSH key line is no form of a list
    let out = seeded(
        &[
            &["publish", "--part", "crl", "--format", "ssh", "--to", "-"][..],
            &one,
            &WHO,
        ]
        .concat(),
    );
    assert!(!out.status.success(), "a list went out as SSH");
    assert!(stderr(&out).contains("--format binary"), "{}", stderr(&out));
}

/// A directory's previous list is the root's list in whichever form it holds: the DER alone
/// keeps its revocations through `publish --part crl --format binary` and through `revoke`
/// as well as the PEM does
#[test]
fn a_directory_of_the_der_alone_keeps_its_revocations() {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name);
    let to = |name: &str| format!("{}/", path(name).display());
    let run = |args: &[&str], to: &str| {
        let out = seeded(&[args, &["--app", "piv"][..], &WHO, &["--to", to]].concat());
        assert!(out.status.success(), "{args:?} failed:\n{}", stderr(&out));
    };
    let revoke = |device: &str, to: &str| {
        run(&["revoke", "--kind", "subkeys", "-k", device], to);
    };
    let publish = |to: &str| run(&["publish", "--part", "crl", "--format", "binary"], to);
    let der = |dir: &str| std::fs::read(path(dir).join("piv-revocation-p256.crl")).unwrap();
    let pem = |dir: &str| std::fs::read(path(dir).join("piv-revocation-p256.crl.pem")).unwrap();

    revoke("laptop", &to("srv"));
    publish(&to("srv"));
    assert_eq!(revoked(&der("srv")), 2);

    for only in ["publish", "revoke"] {
        std::fs::create_dir(path(only)).unwrap();
        std::fs::copy(
            path("srv").join("piv-revocation-p256.crl"),
            path(only).join("piv-revocation-p256.crl"),
        )
        .unwrap();
    }
    publish(&to("publish"));
    assert_eq!(revoked(&der("publish")), 2, "the DER's revocations were dropped");
    assert_eq!(files_in(&path("publish")), ["piv-revocation-p256.crl"]);

    revoke("phone", &to("revoke"));
    assert_eq!(revoked(&pem("revoke")), 4, "the DER's revocations were dropped");
    // Both forms now, the PEM the newer: it is the one read, and the DER is replaced by it
    publish(&to("revoke"));
    assert_eq!(revoked(&der("revoke")), 4);
}

/// Two forms of the root's list in one directory that disagree are refused rather than one
/// of them chosen: two lists of one number, or a newer list that lacks what the older revokes;
/// and a list file this run did not read is never replaced by another
#[test]
fn lists_that_disagree_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name);
    let to = |name: &str| format!("{}/", path(name).display());
    let run = |args: &[&str], to: &str| {
        seeded(&[args, &["--app", "piv"][..], &WHO, &["--to", to]].concat())
    };
    let succeeded = |out: std::process::Output| {
        assert!(out.status.success(), "failed:\n{}", stderr(&out));
    };
    let pem = "piv-revocation-p256.crl.pem";
    let der = "piv-revocation-p256.crl";

    // The same list in both forms is one list
    succeeded(run(&["revoke", "--kind", "subkeys", "-k", "laptop"], &to("old")));
    succeeded(run(&["publish", "--part", "crl", "--format", "binary"], &to("old")));
    succeeded(run(&["publish", "--part", "crl"], &to("old")));

    // Another list of the same number: the DER with its signature altered
    std::fs::create_dir(path("same")).unwrap();
    let list = std::fs::read(path("old").join(der)).unwrap();
    let mut forged = list.clone();
    *forged.last_mut().unwrap() ^= 1;
    std::fs::write(path("same").join(der), &forged).unwrap();
    let as_pem = {
        use x509_cert::der::{Decode, EncodePem};
        x509_cert::crl::CertificateList::<x509_cert::certificate::Rfc5280>::from_der(&list)
            .unwrap()
            .to_pem(x509_cert::der::pem::LineEnding::LF)
            .unwrap()
    };
    std::fs::write(path("same").join(pem), as_pem).unwrap();
    let out = run(&["publish", "--part", "crl"], &to("same"));
    assert!(!out.status.success(), "two lists of one number were taken");
    let err = stderr(&out);
    assert!(err.contains("two different revocation lists of one number"), "{err}");
    assert!(err.contains(pem) && err.contains(der), "the files are not named:\n{err}");

    // A newer list that lacks the older's revocations: the empty list, signed a second later
    std::thread::sleep(std::time::Duration::from_millis(1100));
    std::fs::create_dir(path("lost")).unwrap();
    std::fs::copy(path("old").join(pem), path("lost").join(pem)).unwrap();
    let empty = run(&["publish", "--part", "crl", "--format", "binary"], "-");
    assert!(empty.status.success(), "{}", stderr(&empty));
    std::fs::write(path("lost").join(der), &empty.stdout).unwrap();
    for args in [
        &["publish", "--part", "crl"][..],
        &["revoke", "--kind", "subkeys", "-k", "phone"],
    ] {
        let out = run(args, &to("lost"));
        assert!(!out.status.success(), "{args:?} dropped the older list's revocations");
        let err = stderr(&out);
        assert!(err.contains("the newer list, does not"), "{err}");
    }
    assert_eq!(std::fs::read(path("lost").join(der)).unwrap(), empty.stdout, "a list was written");

    // An issuing authority's list file holding something else is not written over
    std::fs::create_dir(path("issuing")).unwrap();
    let intermediate = ["--intermediate", "-k", "laptop"];
    let out = run(&[&["publish", "--part", "crl"][..], &intermediate].concat(), &to("issuing"));
    assert!(out.status.success(), "{}", stderr(&out));
    let issuing = files_in(&path("issuing"))
        .into_iter()
        .find(|name| name.contains("-issuing-"))
        .unwrap();
    std::fs::write(path("issuing").join(&issuing), b"another list").unwrap();
    let out = run(&[&["publish", "--part", "crl"][..], &intermediate].concat(), &to("issuing"));
    assert!(!out.status.success(), "another list was written over");
    assert!(stderr(&out).contains("holds another revocation list"), "{}", stderr(&out));
    assert_eq!(std::fs::read(path("issuing").join(&issuing)).unwrap(), b"another list");
}

/// PIV keys leave the gap as encrypted PKCS#8, each next to its certificate, the keys
/// written owner-only
#[test]
fn ungap_writes_piv_keys_with_their_certificates() {
    let dir = tempfile::tempdir().unwrap();
    let to = format!("{}/keys/", dir.path().display());
    let out = seeded(
        &[
            &[
                "ungap",
                "--app",
                "piv",
                "--key",
                "decryption",
                "--pin",
                "passphrase",
            ][..],
            &["--to", &to],
            &WHO,
        ]
        .concat(),
    );
    assert!(out.status.success(), "ungap failed:\n{}", stderr(&out));
    let key = dir.path().join("keys/piv-decryption.key.pem");
    let cert = dir.path().join("keys/piv-decryption.pem");
    assert!(
        std::fs::read_to_string(&key)
            .unwrap()
            .starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----")
    );
    assert!(
        std::fs::read_to_string(&cert)
            .unwrap()
            .starts_with("-----BEGIN CERTIFICATE-----")
    );
    assert!(!dir.path().join("keys/piv-signature.key.pem").exists(), "an unchosen key left");
    #[cfg(unix)]
    assert_eq!(mode(&key), 0o600, "the key is not owner-only");
}
