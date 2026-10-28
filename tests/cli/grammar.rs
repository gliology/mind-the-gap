//! The command line itself: what a one-shot invocation refuses, the shortest spellings, the
//! exit status, and the pages and completions made from it.

use crate::hex::hex;
use crate::{NO_CARD, TEST_PHRASE, WHO, bin, carried_on, repl, root_pem, seeded, stderr, stdout};
use mind_the_gap::cli::command;

use std::path::Path;
use std::process::Command;

#[test]
fn cmd_debug_assert() {
    command().debug_assert()
}

/// A one-shot invocation without the seed fails instead of stopping on a prompt, and the
/// error names the ways out.
#[test]
fn missing_seed_is_an_error_not_a_prompt() {
    let out = bin().args(["publish"]).args(WHO).output().unwrap();
    let err = stderr(&out);

    assert!(!out.status.success(), "publish without a seed exited zero");
    assert!(err.contains("No seed phrase given"), "the failure does not explain itself:\n{err}");
    assert!(err.contains("--seed (or MIND_THE_SEED)"), "no flag named:\n{err}");
    assert!(err.contains("interactive session"), "the session is not pointed at:\n{err}");
}

/// A key seed asked for without a value cannot be asked for in a one-shot invocation; the
/// error names how to give it instead.
#[test]
fn bare_key_seed_is_refused_without_a_session() {
    let out = seeded(&[
        "--key-seed",
        "publish",
        "-n",
        "Alice",
        "-m",
        "alice@example.com",
    ]);
    let err = stderr(&out);

    assert!(!out.status.success(), "a bare --key-seed was taken without a session");
    assert!(err.contains("No key seed phrase given"), "no explanation:\n{err}");
    assert!(err.contains("--key-seed=PHRASE"), "the way out is not named:\n{err}");
}

/// What the command line takes and refuses at its edges: a Web Key Directory is no stream,
/// addresses typed with a space after the comma are the same addresses, and `revoke`, which
/// asks nothing, takes no `--yes`.
#[test]
fn small_edges_of_the_command_line() {
    let out = seeded(
        &[
            &["publish", "--app", "pgp", "--format", "wkd", "--to", "-"][..],
            &WHO,
        ]
        .concat(),
    );
    assert!(!out.status.success(), "a WKD layout went to stdout");
    assert!(stderr(&out).contains("needs a directory"), "{}", stderr(&out));

    let spaced = seeded(&[
        "publish",
        "--app",
        "pgp",
        "-n",
        "Alice",
        "-m",
        "a@example.org, b@example.org",
        "--to",
        "-",
    ]);
    let tight = seeded(&[
        "publish",
        "--app",
        "pgp",
        "-n",
        "Alice",
        "-m",
        "a@example.org,b@example.org",
        "--to",
        "-",
    ]);
    assert!(spaced.status.success(), "a space after the comma was refused:\n{}", stderr(&spaced));
    assert_eq!(spaced.stdout, tight.stdout, "the space changed the certificate");

    let out = seeded(
        &[
            &[
                "revoke", "--app", "pgp", "--kind", "subkeys", "--yes", "--to", "-",
            ][..],
            &WHO,
        ]
        .concat(),
    );
    assert!(!out.status.success(), "revoke took --yes");
}

/// What the options alone decide is judged before any seed is stretched, and all of it at
/// once. The phrase given here is no phrase at all, so a command that reached the seed would
/// fail on it instead: each refusal below proves it came first.
#[test]
fn options_are_judged_before_the_seed() {
    const NOT_A_PHRASE: &str = "not a phrase";
    let run = |args: &[&str]| {
        let out = bin()
            .args(["-s", NOT_A_PHRASE])
            .args(args)
            .output()
            .unwrap();
        let err = stderr(&out);
        assert!(!out.status.success(), "{args:?} ran");
        assert!(!err.contains("BIP-39"), "{args:?} reached the seed first:\n{err}");
        err
    };

    let err = run(&["publish", "--validity", "2y", "--to", "-"]);
    for told in ["--name", "--emails", "A validity of 2y counts"] {
        assert!(err.contains(told), "publish did not tell {told}:\n{err}");
    }

    // A validity past the last day an end can be told on, for both applets at once
    let err = run(&[
        &[
            "publish",
            "--date",
            "2026-01-01",
            "--validity",
            "81y",
            "--to",
            "-",
        ][..],
        &WHO,
    ]
    .concat());
    assert!(err.contains("ends after 2106-02-07"), "{err}");

    let err = run(&["upload", "--app", "piv", "--slot", "82", "--card", NO_CARD]);
    assert!(err.contains("--name") && err.contains("--key decryption"), "{err}");

    let err = run(&[
        "check",
        "--app",
        "pgp",
        "--algorithm",
        "p384",
        "--card",
        NO_CARD,
    ]);
    assert!(err.contains("PIV-only curve"), "{err}");

    let err = run(&["rotate", "--card", NO_CARD, "-n", "Alice"]);
    assert!(err.contains("--from-key-seed"), "{err}");

    let err = run(&["ungap", "--app", "pgp", "--to", "-"]);
    assert!(err.contains("--name") && err.contains("--emails"), "{err}");

    let err = run(&["init", "--app", "pgp", "--legacy", "--card", NO_CARD]);
    assert!(err.contains("current scheme"), "{err}");

    // A pin reset takes the card seed, which is only asked for once the pins are there
    let out = bin()
        .args(["pin", "--reset", "--card", NO_CARD])
        .output()
        .unwrap();
    let err = stderr(&out);
    assert!(err.contains("No new pin given"), "{err}");
    assert!(!err.contains("No seed phrase"), "the seed was asked for before the pin:\n{err}");

    // And with everything there, the seed is what fails
    let out = bin()
        .args(["-s", NOT_A_PHRASE, "publish", "--to", "-"])
        .args(WHO)
        .output()
        .unwrap();
    assert!(stderr(&out).contains("BIP-39"), "{}", stderr(&out));
}

/// Names a PIV certificate cannot carry and a list URL no list can be named from are refused
/// with the rest, before any seed is stretched, wherever PIV is among the applets: a name
/// past 40 characters, counted in characters, an organization or unit past 64, a country that
/// is not two uppercase letters
#[test]
fn names_and_list_urls_are_judged_before_the_seed() {
    const NOT_A_PHRASE: &str = "not a phrase";
    let run = |args: &[&str]| {
        bin()
            .args(["-s", NOT_A_PHRASE])
            .args(args)
            .args(["-m", "alice@example.com"])
            .output()
            .unwrap()
    };
    let refused = |args: &[&str]| {
        let out = run(args);
        let err = stderr(&out);
        assert!(!out.status.success(), "{args:?} ran");
        assert!(!err.contains("BIP-39"), "{args:?} reached the seed first:\n{err}");
        err
    };
    let long = "\u{e9}".repeat(41);
    let org = "O".repeat(65);

    let err = refused(&[
        "publish",
        "--app",
        "piv",
        "-n",
        &long,
        "--org",
        &org,
        "--unit",
        &"\u{f6}".repeat(65),
        "--country",
        "de",
        "--crl-url",
        "http://example.org/alice",
        "--to",
        "-",
    ]);
    for told in [
        "--name is 41 characters",
        "at most 40",
        "--org is 65 characters",
        "--unit is 65 characters",
        "--country 'de'",
        "does not end in a list's name",
    ] {
        assert!(err.contains(told), "{told} untold:\n{err}");
    }
    for verb in [
        &["revoke", "--app", "piv", "--kind", "subkeys", "--to", "-"][..],
        &["ungap", "--app", "piv", "--to", "-"],
        &["check", "--app", "piv", "--card", NO_CARD],
        &["upload", "--app", "piv", "--card", NO_CARD],
        &[
            "rotate",
            "--app",
            "piv",
            "--date",
            "2027-01-01",
            "--card",
            NO_CARD,
        ],
    ] {
        let err = refused(&[verb, &["-n", &long][..]].concat());
        assert!(err.contains("--name is 41 characters"), "{verb:?}:\n{err}");
        let err = refused(
            &[
                verb,
                &["-n", "Alice", "--crl-url", "http://example.org/a.crl?x"][..],
            ]
            .concat(),
        );
        assert!(err.contains("query or a fragment"), "{verb:?}:\n{err}");
    }

    // OpenPGP alone takes the name, and a name at the bound is PIV's
    let out = run(&["publish", "--app", "pgp", "-n", &long, "--to", "-"]);
    assert!(stderr(&out).contains("BIP-39"), "{}", stderr(&out));
    let out = run(&[
        "publish",
        "--app",
        "piv",
        "-n",
        &"\u{e9}".repeat(40),
        "--to",
        "-",
    ]);
    assert!(stderr(&out).contains("BIP-39"), "{}", stderr(&out));
}

/// A malformed email is an error with the address named, never a panic.
#[test]
fn malformed_email_is_an_error_not_a_panic() {
    let out = seeded(&[
        "publish",
        "--app",
        "pgp",
        "-n",
        "Alice",
        "-m",
        "not<an@address",
    ]);
    let err = stderr(&out);

    assert!(!out.status.success());
    assert!(!err.contains("panicked"), "a bad email crashed the binary:\n{err}");
    assert!(err.contains("not<an@address"), "the offending address is not named:\n{err}");
}

/// Errors surface through the exit status, and success is exit zero.
#[test]
fn exit_status_reflects_the_outcome() {
    // An identity's certificates need its name...
    let out = seeded(&["publish", "--app", "piv", "--to", "-"]);
    assert!(!out.status.success(), "publish without a name exited zero");
    assert!(stderr(&out).contains("--name"), "{}", stderr(&out));

    // ... while a complete offline invocation succeeds
    let out = seeded(&[&["publish", "--app", "piv", "--to", "-"][..], &WHO].concat());
    assert!(out.status.success(), "offline publish failed:\n{}", stderr(&out));
}

/// `generate` refuses to run without a controlling terminal instead of spilling the
/// ceremony into a redirected stdout, and a piped session cannot replace its seed.
#[test]
#[cfg(unix)]
fn generate_refuses_without_a_terminal() {
    let out = bin().arg("generate").output().unwrap();
    let (out_text, err) = (stdout(&out), stderr(&out));

    assert!(!out.status.success(), "generate ran without a terminal");
    assert!(err.contains("terminal"), "the refusal does not explain itself:\n{err}");
    assert!(out_text.is_empty(), "the ceremony leaked onto stdout:\n{out_text}");

    let out = repl("generate\nquit\n", &["-s", TEST_PHRASE]);
    carried_on(&out, 1);
    assert!(stderr(&out).contains("cannot replace"), "{}", stderr(&out));
}

/// The command line's own defaults are frozen with the scheme.
///
/// The shortest command a user can type -- the phrase, a name and an address, nothing else
/// -- runs through the phrase step, each applet's default algorithm and the default dates at
/// once, so these two values pin all three as a user gets them. Like the vectors in the
/// library suites, they do not change within a major version.
#[test]
fn shortest_commands_are_frozen() {
    use sequoia_openpgp::parse::Parse;
    use sha2::{Digest, Sha256};
    use x509_cert::der::{DecodePem, Encode};

    let out = seeded(&[&["publish", "--app", "pgp", "--to", "-"][..], &WHO].concat());
    assert!(out.status.success(), "pgp publish failed: {:?}", out);
    let cert = sequoia_openpgp::Cert::from_bytes(&out.stdout).unwrap();
    assert_eq!(
        cert.fingerprint().to_hex(),
        "38BAAB2F9DE7D459C34A80B3AF859A5F33253C3A",
        "the default OpenPGP certificate moved"
    );

    let root = x509_cert::Certificate::from_pem(root_pem(bin(), &["-n", "Alice"])).unwrap();
    let digest = hex(&Sha256::digest(root.to_der().unwrap()));
    assert_eq!(
        digest, "562b7918ec4d66bf8ed60aaab91018ab18193f0add68d5b495fa7405c137f9bf",
        "the default PIV root certificate moved"
    );
}

#[test]
fn man_page_generation() {
    let mut cmd = command();
    cmd.build();

    let man = clap_mangen::Man::new(cmd);
    let mut output = Vec::new();
    man.render(&mut output).unwrap();

    assert!(!output.is_empty());
}

/// The packaging helper writes a page per verb and the completions.
#[test]
fn the_build_helper_writes_pages_and_completions() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_mind-the-build"))
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "mind-the-build failed: {:?}", out);

    let man = dir.path().join("share/man/man1");
    for page in [
        "mind-the-gap.1",
        "mind-the-gap-upload.1",
        "mind-the-gap-run.1",
    ] {
        assert!(man.join(page).exists(), "no man page {page}");
    }
    assert!(!man.join("mind-the-gap-help.1").exists(), "help got a page of its own");
    // A session's verb alone has none; what the command line runs has one
    assert!(!man.join("mind-the-gap-quit.1").exists(), "quit got a page of its own");
    assert!(man.join("mind-the-gap-set.1").exists(), "set has no page");
    assert!(
        dir.path()
            .join("share/bash-completion/completions/mind-the-gap.bash")
            .exists()
    );

    // Each shell's script completes `run` with the recipes of the ceremony file; the
    // live-system check completes them in each shell
    let script = |path: &str| std::fs::read_to_string(dir.path().join(path)).unwrap();
    let bash = script("share/bash-completion/completions/mind-the-gap.bash");
    assert!(bash.contains("_mind__the__gap__recipes()"), "no recipes in bash");
    assert!(
        bash.trim_end().ends_with(
            "complete -F _mind__the__gap__with__recipes -o bashdefault -o default mind-the-gap\nfi"
        ),
        "bash does not complete with the recipes"
    );
    let zsh = script("share/zsh/vendor-completions/_mind-the-gap");
    assert!(zsh.contains(":_mind-the-gap_recipes'"), "zsh does not complete the recipe");
    assert!(zsh.contains("_mind-the-gap_recipes() {"), "no recipes in zsh");
    let fish = script("share/fish/vendor_completions.d/mind-the-gap.fish");
    assert!(fish.contains("-a \"(__fish_mind_the_gap_recipes)\""), "no recipes in fish");
    for script in [&bash, &zsh, &fish] {
        assert!(script.contains("MIND_THE_CEREMONY"), "a script ignores MIND_THE_CEREMONY");
        assert!(script.contains("/etc/mind-the-gap/ceremony"), "a script ignores the image's");
        // A `ceremony` default in a config file, as `run` reads it
        assert!(script.contains("MIND_THE_CONFIG"), "a script ignores MIND_THE_CONFIG");
        assert!(script.contains("/etc/mind-the-gap/config.toml"), "a script ignores the image's");
    }
}

/// The book's option reference is the command line rendered, so it says what the binary does:
/// the committed chapter has to be what the command renders now.
#[test]
fn the_option_reference_is_current() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/options-reference.md");
    let committed = std::fs::read_to_string(&path).unwrap();
    assert!(
        committed == mind_the_gap::cli::reference(),
        "{} is out of date with the command line; write it again with\n    {}",
        path.display(),
        mind_the_gap::cli::REGENERATE
    );
}

/// Each shell the package installs completions for gets a script that offers the verbs, not
/// merely one that generates without an error.
#[test]
fn shell_completions_offer_the_verbs() {
    use clap_complete::Shell;

    for shell in [Shell::Bash, Shell::Fish, Shell::Zsh] {
        let mut output = Vec::new();
        clap_complete::generate(shell, &mut command(), "mind-the-gap", &mut output);
        let script = String::from_utf8(output).unwrap();

        for verb in ["init", "upload", "publish", "ungap", "run", "generate"] {
            assert!(script.contains(verb), "{shell} completions do not offer {verb}");
        }
    }
}

/// `--version` names the derivation scheme next to the release, which a record kept with a
/// phrase needs as much: the scheme decides the keys. `-V` stays the short form.
#[test]
fn the_long_version_names_the_scheme() {
    let long = stdout(&bin().arg("--version").output().unwrap());
    let short = stdout(&bin().arg("-V").output().unwrap());
    let release = format!("mind-the-gap {}", env!("CARGO_PKG_VERSION"));
    assert!(long.starts_with(&format!("{release} (scheme mtg1")), "{long}");
    assert_eq!(short.trim_end(), release);
}

/// A verb's help lists its own options first, then the groups, then what writes, then the
/// process options, and the seeds last; `quit`, which runs in a session alone, is left out
/// of the command line's help, where `set` and `unset` stay.
#[test]
fn the_help_puts_a_verbs_own_options_first() {
    let out = bin().args(["pin", "--help"]).output().unwrap();
    let text = stdout(&out);
    let at = |what: &str| {
        text.find(what)
            .unwrap_or_else(|| panic!("no {what} in:\n{text}"))
    };
    assert!(at("--reset") < at("\nCard:"), "{text}");
    assert!(at("\nCard:") < at("\nWriting:"), "{text}");
    assert!(at("\nWriting:") < at("--dry-run"), "{text}");
    assert!(at("--dry-run") < at("\nProcess:"), "{text}");
    assert!(at("\nProcess:") < at("--log-level"), "{text}");
    assert!(at("--log-level") < at("\nSeeds:"), "{text}");

    // The one --to says nothing one verb does not mean
    for verb in ["trust", "revoke", "ungap"] {
        let out = bin().args([verb, "--help"]).output().unwrap();
        assert!(!stdout(&out).contains("wkd"), "{verb}'s --to speaks of WKD");
    }

    let text = stdout(&bin().arg("--help").output().unwrap());
    assert!(text.contains("  set "), "{text}");
    assert!(text.contains("  unset "), "{text}");
    assert!(!text.contains("  quit "), "quit is offered on the command line:\n{text}");
    assert!(text.contains("~/.config/mind-the-gap/config.toml"), "{text}");
}
