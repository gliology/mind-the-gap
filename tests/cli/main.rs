//! Tests that drive the real binary: the grammar, the session, defaults, ceremonies, plumbing
//! and everything that leaves the gap.
//!
//! Everything here runs the compiled `mind-the-gap` with a fixed test seed and asserts on exit
//! status, stdout and stderr. None of these invocations may ever change a card: every command
//! that could reach one names a card that cannot exist, and is expected to stop at a
//! validation step or at that missing card before any hardware is written to. `list` is not
//! run at all, since it reads whatever cards happen to be attached.

use std::path::Path;
use std::process::{Command, Output, Stdio};

mod cards;
mod ceremony;
mod dates;
mod defaults;
mod files;
mod grammar;
#[path = "../common/hex.rs"]
mod hex;
mod plumbing;
mod seeds;
mod session;

/// Fixed test mnemonic, never a real one: this phrase is in the repository
const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon abandon abandon abandon abandon art";

/// A second fixed test mnemonic, for a key seed apart from the seed
const OTHER_PHRASE: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

/// Card serial for commands that must fail to find their card
///
/// Passed wherever a test runs a command that would otherwise pick the one card attached:
/// should a regression ever carry such a run past its guard rails, it finds no card to
/// reset rather than the developer's. It parses as a PIV serial, and as an OpenPGP
/// identifier it matches nothing, those always carrying a colon.
const NO_CARD: &str = "4294967295";

/// The identity every certificate here is issued to
const WHO: [&str; 4] = ["-n", "Alice", "-m", "alice@example.com"];

/// The compiled binary with a hermetic environment.
///
/// `MIND_THE_...` variables from the calling shell must not leak in -- a developer's
/// exported seed or defaults would otherwise change what these tests exercise -- and neither
/// may a developer's config file, so the user's config directory points nowhere. Nor may the
/// developer's terminal: what a closed stdin cannot answer is asked on the controlling
/// terminal instead, so every run starts a session of its own, without one, and a prompt
/// fails where it would otherwise wait on that terminal, or be answered from it.
fn bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mind-the-gap"));
    for (name, _) in std::env::vars_os() {
        let name = name.to_string_lossy().into_owned();
        if name.starts_with("MIND_THE_") {
            cmd.env_remove(name);
        }
    }
    cmd.env("XDG_CONFIG_HOME", "/nonexistent/mind-the-gap-tests");
    cmd.stdin(Stdio::null());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid is async-signal-safe and touches no state of the parent
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }

    cmd
}

/// Run the binary with the test seed and `args`
fn seeded(args: &[&str]) -> Output {
    bin().args(["-s", TEST_PHRASE]).args(args).output().unwrap()
}

/// Run the binary as a session with the given stdin script
fn repl(input: &str, args: &[&str]) -> Output {
    repl_with(bin(), input, args)
}

/// Run `cmd` as a session with the given stdin script
fn repl_with(mut cmd: Command, input: &str, args: &[&str]) -> Output {
    use std::io::Write;

    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// Assert a piped session tried every line and reports how many failed: it carries on past
/// a failing line, and its status says that one did
fn carried_on(out: &Output, failed: usize) {
    let err = stderr(out);
    assert_eq!(out.status.code(), Some(1), "the session did not report its failures:\n{err}");
    assert!(
        err.contains(&format!("{failed} of the session's lines failed")),
        "not {failed} failed lines:\n{err}"
    );
}

/// Whether a `set` listing has the default `name = value` behind `layer`, its column
fn listed(text: &str, layer: &str, setting: &str) -> bool {
    let wanted = format!("{layer} {setting}");
    text.lines()
        .any(|line| line.split_whitespace().collect::<Vec<_>>().join(" ") == wanted)
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The permission bits of a file
#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).unwrap().mode() & 0o777
}

/// The subject of the PIV root authority a `publish --part identity` wrote
fn root_subject(pem: &[u8]) -> String {
    use x509_cert::der::DecodePem;
    x509_cert::Certificate::from_pem(pem)
        .unwrap()
        .tbs_certificate()
        .subject()
        .to_string()
}

/// The PIV root authority's PEM, published to stdout
fn root_pem(cmd: Command, args: &[&str]) -> Vec<u8> {
    let mut cmd = cmd;
    let out = cmd
        .args([
            "-s",
            TEST_PHRASE,
            "publish",
            "--app",
            "piv",
            "--part",
            "identity",
        ])
        .args(["--to", "-"])
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "publish of the root failed:\n{}", stderr(&out));
    out.stdout
}
