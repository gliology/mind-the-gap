//! gpg on the provisioned card: it sees the three keys, and signs, authenticates and decrypts
//! with them.

use crate::TEST_PIN;

use openpgp_card::ocard::KeyType;

use sequoia_openpgp::cert::Cert;

/// Stops any `scdaemon` this test started, however the test ends.
///
/// Asking gpg to talk to a card leaves an scdaemon holding it exclusively, which would break
/// every later card test in the same `cargo test` run. `Drop` rather than a call at the end of
/// the test, so that it also runs when an assertion panics.
struct ScdaemonGuard {
    home: std::path::PathBuf,
}

impl Drop for ScdaemonGuard {
    fn drop(&mut self) {
        let _ = std::process::Command::new("gpgconf")
            .env("GNUPGHOME", &self.home)
            .args(["--kill", "scdaemon"])
            .output();
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

/// Confirm gpg itself finds the three keys, and clean up the scdaemon that costs.
///
/// Uses a throwaway GNUPGHOME so the caller's keyring and agent are untouched, and forces
/// scdaemon through PC/SC -- its internal CCID driver claims the USB interface directly and
/// fails with "No such device" whenever pcscd already holds the reader.
///
/// The card is named by its serial number throughout, because scdaemon otherwise takes
/// whichever OpenPGP card it likes when several are attached, as on a test host, and the
/// test identity is the same on all of them.
#[cfg(has_gpg)]
pub(super) fn gpg_sees_the_keys(expected: &[(KeyType, [u8; 20])], cert: &Cert, serialno: &str) {
    // tempfile gives an unpredictable path, so nothing can pre-place a directory or
    // symlink there; into_path hands ownership to the ScdaemonGuard below
    let home = tempfile::tempdir()
        .expect("cannot create throwaway GNUPGHOME")
        .keep();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
            .expect("cannot restrict GNUPGHOME permissions");
    }

    std::fs::write(home.join("scdaemon.conf"), "disable-ccid\n")
        .expect("cannot write scdaemon.conf");

    // Armed before gpg runs, so the daemon is stopped even if an assertion below panics
    let _guard = ScdaemonGuard { home: home.clone() };

    // scdaemon names a card after its AID but may zero the version field (it does for every
    // YubiKey), so find ours among the cards it sees by manufacturer and serial number
    let cards = std::process::Command::new("gpg-card")
        .env("GNUPGHOME", &home)
        .args(["--no-history", "list", "--cards"])
        .output()
        .expect("cannot run gpg-card");
    let cards = String::from_utf8_lossy(&cards.stdout);
    let serialno = cards
        .split_whitespace()
        .find(|word| word.len() == 32 && word.get(16..28) == serialno.get(16..28))
        .unwrap_or_else(|| panic!("gpg sees no card with serial number {serialno}:\n{cards}"));

    // Make the card current and have the agent learn its keys: the key stubs it writes record
    // this serial number, so the signing and decryption below go to this card and no other
    let learned = std::process::Command::new("gpg-connect-agent")
        .env("GNUPGHOME", &home)
        .args([
            &format!("scd switchcard {serialno}"),
            "learn --force",
            "/bye",
        ])
        .output()
        .expect("cannot run gpg-connect-agent");
    let replies = String::from_utf8_lossy(&learned.stdout);
    assert!(
        learned.status.success() && !replies.lines().any(|line| line.starts_with("ERR")),
        "gpg-agent cannot learn card {serialno}:\n{replies}\n{}",
        String::from_utf8_lossy(&learned.stderr),
    );

    // `gpg --card-status` asks for no card in particular; gpg-card lists the one named
    let output = std::process::Command::new("gpg-card")
        .env("GNUPGHOME", &home)
        .args(["--no-history", "list", serialno])
        .output()
        .expect("cannot run gpg-card");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "gpg-card list failed:\n{}\n{}",
        stdout,
        String::from_utf8_lossy(&output.stderr),
    );

    // gpg prints fingerprints spaced in four-character groups, so compare on a normalised copy
    let normalised: String = stdout.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let normalised = normalised.to_uppercase();

    for (kind, fingerprint) in expected {
        let hex = fingerprint
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>();

        assert!(
            normalised.contains(&hex),
            "gpg does not report the {kind:?} key ({hex}):\n{stdout}",
        );
    }

    gpg_uses_the_keys(&home, cert);
}

/// gpg signs and decrypts with the card, end to end, the way a mail client would.
///
/// The low-level checks above prove the keys; this proves the whole client path around them,
/// the ECDH key derivation and session key unwrapping included, which only a real client does.
#[cfg(has_gpg)]
fn gpg_uses_the_keys(home: &std::path::Path, cert: &Cert) {
    use sequoia_openpgp::serialize::SerializeInto;
    use std::io::Write;

    let gpg = |args: &[&str], input: &[u8]| -> std::process::Output {
        let mut child = std::process::Command::new("gpg")
            .env("GNUPGHOME", home)
            .args([
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                TEST_PIN,
            ])
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("cannot run gpg");
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().expect("gpg did not finish")
    };
    let ok = |output: std::process::Output, what: &str| -> Vec<u8> {
        assert!(
            output.status.success(),
            "gpg {what} failed:\n{}",
            String::from_utf8_lossy(&output.stderr),
        );
        output.stdout
    };

    // The public certificate turns the card status stubs into usable keys
    ok(gpg(&["--import"], &cert.armored().to_vec().unwrap()), "--import");
    let fingerprint = cert.fingerprint().to_hex();

    let message = b"signed and sealed on the card";
    let signed = ok(gpg(&["--local-user", &fingerprint, "--sign"], message), "--sign");
    let verified = ok(gpg(&["--decrypt"], &signed), "--verify of a card signature");
    assert_eq!(verified, message, "gpg verified a different message");

    let sealed = ok(
        gpg(
            &[
                "--trust-model",
                "always",
                "--recipient",
                &fingerprint,
                "--encrypt",
            ],
            message,
        ),
        "--encrypt",
    );
    let opened = ok(gpg(&["--decrypt"], &sealed), "--decrypt on the card");
    assert_eq!(opened, message, "gpg decrypted to a different message");
}

#[cfg(not(has_gpg))]
pub(super) fn gpg_sees_the_keys(_expected: &[(KeyType, [u8; 20])], _cert: &Cert, _serialno: &str) {
    // A destructive run that cannot finish its last assertion must say so in the result,
    // not in a line of buffered output: a pass with a skipped step is not a pass. The card
    // itself is fine -- provisioning succeeded before this step.
    panic!(
        "gpg is not in PATH, so the final cross-check cannot run; the card is provisioned \
         fine -- install gpg (or enter the dev shell) and rerun to complete the suite"
    );
}
