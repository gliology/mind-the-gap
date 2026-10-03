//! Tests that drive the real binary, covering the interactive guard rails.
//!
//! Everything here runs the compiled `mind-the-gap` with a fixed test seed on the command
//! line and asserts on exit status and stderr. None of these invocations may ever reach a
//! card: each one is expected to stop at a validation or confirmation step that comes
//! before any hardware is opened.

use mind_the_gap::cli::command;

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

/// Provisioning without --pin refuses before anything else happens.
#[test]
fn factory_pin_is_refused() {
    for backend in ["pgp", "piv"] {
        let out = identity(&mut bin())
            .args([backend, "upload"])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);

        assert!(!out.status.success(), "{backend} upload without --pin exited zero");
        assert!(
            stderr.contains("--keep-factory-pin"),
            "{backend} upload refusal does not name the override:\n{stderr}",
        );
    }
}

/// The confirmation prompt treats a closed stdin as "no", before any card is opened.
#[test]
fn confirm_prompt_aborts_on_eof() {
    let out = identity(&mut bin())
        .args(["pgp", "upload", "--keep-factory-pin"])
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
