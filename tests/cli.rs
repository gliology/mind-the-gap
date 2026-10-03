//! Tests that drive the real binary, covering the interactive guard rails.
//!
//! Everything here runs the compiled `mind-the-gap` with a fixed test seed on the command
//! line and asserts on exit status and stderr. None of these invocations may ever reach a
//! card: each one is expected to stop at a validation or confirmation step that comes
//! before any hardware is opened.

use mind_the_gap::cli::{command, repl_command};

use std::process::{Command, Stdio};

/// Fixed test mnemonic, never a real one: this phrase is in the repository
const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon abandon abandon abandon abandon art";

/// The compiled binary with a hermetic environment.
///
/// `MIND_THE_...` variables from the calling shell must not leak in -- a developer's
/// exported seed or defaults would otherwise change what these tests exercise.
fn bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mind-the-gap"));
    for (name, _) in std::env::vars_os() {
        let name = name.to_string_lossy().into_owned();
        if name.starts_with("MIND_THE_") {
            cmd.env_remove(name);
        }
    }
    cmd.stdin(Stdio::null());
    cmd
}

fn identity(cmd: &mut Command) -> &mut Command {
    cmd.args(["-s", TEST_PHRASE, "-n", "Alice", "-m", "alice@example.com"])
}

#[test]
fn cmd_debug_assert() {
    command().debug_assert()
}

#[test]
fn repl_cmd_debug_assert() {
    repl_command().debug_assert()
}

/// Run the binary as an interactive session with the given stdin script.
fn repl(input: &str, args: &[&str]) -> std::process::Output {
    use std::io::Write;

    let mut child = {
        let mut cmd = bin();
        cmd.args(args);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd.spawn().unwrap()
    };
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// A full session: identity set per line, a certificate produced, a clean exit.
#[test]
fn repl_session_certifies() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cert.asc");
    let script = format!(
        "set -n 'Jane Doe' -m jane@example.com
pgp certify --kind full -o {}
exit
",
        path.display()
    );

    let out = repl(&script, &["-s", TEST_PHRASE]);
    assert!(out.status.success(), "session exited nonzero: {:?}", out);
    let cert = std::fs::read_to_string(&path).unwrap();
    assert!(cert.contains("BEGIN PGP PUBLIC KEY BLOCK"));
}

/// A bad line is reported and the session continues instead of dying.
#[test]
fn repl_recovers_from_errors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cert.asc");
    let script = format!(
        "bogus command
pgp certify --kind full -o {} -n Jane -m jane@example.com
exit
",
        path.display()
    );

    let out = repl(&script, &["-s", TEST_PHRASE]);
    assert!(out.status.success(), "session exited nonzero: {:?}", out);
    assert!(path.exists(), "the command after the bad line did not run");
}

/// Secrets cannot be named on a session line.
#[test]
fn repl_rejects_secret_arguments() {
    for line in [
        "pgp --seed foo certify",
        "pgp --password=x certify",
        "pgp --password x certify",
        "pgp -p x certify",
        "pgp -sabandon certify",
        "set -s foo",
    ] {
        let out = repl(
            &format!(
                "{line}
exit
"
            ),
            &[],
        );
        let stderr = String::from_utf8_lossy(&out.stderr);

        assert!(out.status.success(), "session exited nonzero on {line:?}");
        assert!(
            stderr.contains("fixed for the session"),
            "no rejection for {line:?}:
{stderr}",
        );
    }
}

/// A piped session never prompts: a seed-needing line without a seed is an error,
/// the session survives it, and the next line still runs.
#[test]
fn piped_session_never_prompts_for_seed() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("after.asc");
    let script = format!(
        "pgp certify --kind full -n Jane -m jane@example.com -o x.asc
pgp certify --kind full -n Jane -m jane@example.com -o {} --help
exit
",
        marker.display()
    );

    let out = repl(&script, &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(out.status.success(), "session died: {:?}", out);
    assert!(
        stderr.contains("piped session never prompts"),
        "missing-seed error does not explain the piped rule:\n{stderr}"
    );
}

/// A piped upload without --yes refuses without eating the next script line.
#[test]
fn piped_confirm_does_not_eat_lines() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cert.asc");
    // If confirm() consumed stdin, the "yes" fed here would answer it and the certify
    // line after it would be swallowed as a stray answer
    let script = format!(
        "pgp upload
yes
pgp certify --kind full -o {}
exit
",
        path.display()
    );

    let out = repl(&script, &["-s", TEST_PHRASE, "-n", "Jane", "-m", "jane@example.com"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(out.status.success(), "session died: {:?}", out);
    assert!(stderr.contains("--yes"), "upload did not point at --yes:\n{stderr}");
    assert!(path.exists(), "a later script line was consumed as a confirmation answer");
}

/// A piped session cannot replace a loaded seed with generate.
#[test]
fn piped_generate_cannot_replace_seed() {
    let out = repl("generate\nexit\n", &["-s", TEST_PHRASE]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(out.status.success(), "session died: {:?}", out);
    assert!(
        stderr.contains("cannot replace"),
        "generate over a loaded seed was not refused:\n{stderr}"
    );
}

/// The password verb is interactive-only and takes no arguments.
#[test]
fn password_verb_rejects_piped_and_args() {
    let out = repl("password\nexit\n", &["-s", TEST_PHRASE]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success());
    assert!(stderr.contains("never prompts"), "piped password verb not refused:\n{stderr}");

    let out = repl("password now\nexit\n", &["-s", TEST_PHRASE]);
    assert!(out.status.success(), "session died on bad args: {:?}", out);
}

/// `set` stores backend defaults; a line's own option wins.
#[test]
fn set_stickies_apply_and_lines_win() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.pem");
    let b = dir.path().join("b.pem");
    let script = format!(
        "set --date 2026-01-01
piv certify --kind root -o {a}
piv certify --kind root -d 2027-01-01 -o {b}
exit
",
        a = a.display(),
        b = b.display()
    );

    let out = repl(&script, &["-s", TEST_PHRASE, "-n", "Jane"]);
    assert!(out.status.success(), "session died: {:?}", out);
    let a = std::fs::read(&a).unwrap();
    let b = std::fs::read(&b).unwrap();
    assert_ne!(a, b, "the line's own --date did not override the stored default");
}

/// The version verb prints name and version inside the session.
#[test]
fn version_verb_works_in_session() {
    let out = repl("version\nexit\n", &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "version verb printed no version:\n{stdout}"
    );
}

/// PGP commands that build no user ids no longer demand emails.
#[test]
fn pgp_check_needs_no_emails() {
    let out = bin()
        .args(["-s", TEST_PHRASE, "-n", "Alice", "pgp", "check"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    // Fails for want of a card, never for want of emails
    assert!(!stderr.contains("No email given"), "pgp check still demands emails:\n{stderr}");
}

/// An immediately closed stdin is an ordinary, successful end of session.
#[test]
fn repl_handles_immediate_eof() {
    let out = repl("", &[]);
    assert!(out.status.success(), "empty session exited nonzero: {:?}", out);
}

/// `set` values persist across lines and land in the produced certificate.
#[test]
fn repl_set_identity_persists() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cert.asc");
    let script = format!(
        "set -n 'Jane Doe' -m jane@example.com
pgp certify --kind uids -o {}
exit
",
        path.display()
    );

    let out = repl(&script, &["-s", TEST_PHRASE]);
    assert!(out.status.success(), "session exited nonzero: {:?}", out);
    let cert = std::fs::read_to_string(&path).unwrap();
    assert!(cert.contains("BEGIN PGP PUBLIC KEY BLOCK"));
}

/// Provisioning without --pin warns about the factory pin before anything else happens.
#[test]
fn factory_pin_warns() {
    for backend in ["pgp", "piv"] {
        let out = identity(&mut bin())
            .args([backend, "upload"])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);

        // The run still dies at the confirmation prompt (stdin is closed), but the
        // factory pin warning must already be on record by then
        assert!(!out.status.success(), "{backend} upload with a closed stdin exited zero");
        assert!(
            stderr.contains("factory user pin"),
            "{backend} upload does not warn about the factory pin:\n{stderr}",
        );
    }
}

/// The confirmation prompt treats a closed stdin as "no", before any card is opened.
#[test]
fn confirm_prompt_aborts_on_eof() {
    let out = identity(&mut bin())
        .args(["pgp", "upload"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(!out.status.success(), "upload with a closed stdin exited zero");
    assert!(stderr.contains("confirmation"), "the EOF abort does not explain itself:\n{stderr}",);
}

/// The PIV pin is validated for length before anything else happens.
#[test]
fn piv_pin_length_is_validated() {
    for pin in ["123", "123456789"] {
        let out = identity(&mut bin())
            .args(["piv", "upload", "-i", pin])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);

        assert!(!out.status.success(), "piv upload accepted pin {pin:?}");
        assert!(stderr.contains("6 and 8"), "unexpected pin error:\n{stderr}");
    }
}

/// A malformed email is an error with the address named, never a panic.
#[test]
fn malformed_email_is_an_error_not_a_panic() {
    let out = bin()
        .args(["-s", TEST_PHRASE, "-n", "Alice", "-m", "not<an@address"])
        .args(["pgp", "certify"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(!out.status.success());
    assert!(!stderr.contains("panicked"), "a bad email crashed the binary:\n{stderr}");
    assert!(stderr.contains("not<an@address"), "the offending address is not named:\n{stderr}");
}

/// A half-quoted line is rejected without killing the session, like any other bad line.
#[test]
fn repl_survives_unbalanced_quotes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cert.asc");
    let script = format!(
        "pgp certify --kind full -o x \"half quoted
pgp certify --kind full -o {} -n Jane -m jane@example.com
exit
",
        path.display()
    );

    let out = repl(&script, &["-s", TEST_PHRASE]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(out.status.success(), "session exited nonzero: {:?}", out);
    assert!(stderr.contains("Unbalanced quotes"), "the bad line is not called out:\n{stderr}");
    assert!(path.exists(), "the command after the bad line did not run");
}

/// Commands that derive nothing keep working without a seed.
#[test]
fn status_needs_no_seed() {
    for backend in ["pgp", "piv"] {
        let out = bin().args([backend, "status"]).output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);

        // Without a card attached status may fail, but never for want of a seed
        assert!(!stderr.contains("No seed phrase"), "{backend} status demanded a seed:\n{stderr}");
    }
}

/// The derivation password changes every derived key.
#[test]
fn password_changes_derivation() {
    let dir = tempfile::tempdir().unwrap();
    let certify = |args: &[&str], path: &std::path::Path| {
        let out = identity(&mut bin())
            .args(args)
            .args(["pgp", "-d", "2026-01-01", "certify", "--kind", "full"])
            .args(["-o", path.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(out.status.success(), "certify failed: {:?}", out);
        std::fs::read(path).unwrap()
    };

    let plain = certify(&[], &dir.path().join("plain.asc"));
    let salted = certify(&["-p", "hunter2"], &dir.path().join("salted.asc"));
    assert_ne!(plain, salted, "the password did not change the derived keys");
}

/// A one-shot invocation without a seed fails instead of stopping on a prompt.
#[test]
fn missing_seed_is_an_error_not_a_prompt() {
    let out = bin()
        .args(["-n", "Alice", "-m", "alice@example.com", "pgp", "certify"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(!out.status.success(), "certify without a seed exited zero");
    assert!(stderr.contains("No seed phrase"), "the failure does not explain itself:\n{stderr}");
    assert!(
        stderr.contains("interactive session"),
        "the failure does not point at the session:\n{stderr}"
    );
}

/// Errors surface through the exit status, and success is exit zero.
#[test]
fn exit_status_reflects_the_outcome() {
    // Missing identity arguments fail...
    let out = bin()
        .args(["-s", TEST_PHRASE, "pgp", "certify"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "certify without a name exited zero");

    // ... while a complete offline invocation succeeds
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cert.asc");
    let out = identity(&mut bin())
        .args([
            "pgp",
            "certify",
            "--kind",
            "full",
            "-o",
            path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "offline certify failed:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(path.exists());
}

/// Exporting secret keys without a pin says so, and the file is owner-only.
#[test]
fn unprotected_export_warns_and_restricts_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key.asc");

    let out = identity(&mut bin())
        .args(["pgp", "export", "-o", path.to_str().unwrap()])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(out.status.success(), "export failed:\n{stderr}");
    assert!(stderr.contains("UNENCRYPTED"), "no warning about the missing pin:\n{stderr}");

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600, "secret export is not owner-only");
    }
}

/// `generate` refuses to run without a controlling terminal instead of spilling the
/// ceremony into a redirected stdout.
#[test]
#[cfg(unix)]
fn generate_refuses_without_a_terminal() {
    use std::os::unix::process::CommandExt;

    let mut cmd = bin();
    cmd.arg("generate")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // A fresh session has no controlling terminal, so /dev/tty cannot resolve to the
    // developer's own -- without this the test would prompt (and hang) locally
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }

    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(!out.status.success(), "generate ran without a terminal");
    assert!(stderr.contains("terminal"), "the refusal does not explain itself:\n{stderr}");
    assert!(stdout.is_empty(), "the ceremony leaked onto stdout:\n{stdout}");
}
