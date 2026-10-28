//! The interactive session as a pipe drives it: lines, errors, secrets kept off them.

use crate::{NO_CARD, TEST_PHRASE, carried_on, repl, stderr, stdout};

/// An immediately closed stdin is an ordinary, successful end of session.
#[test]
fn repl_handles_immediate_eof() {
    let out = repl("", &[]);
    assert!(out.status.success(), "empty session exited nonzero: {:?}", out);
}

/// A bad line is reported and the session continues; `quit` ends it, and nothing after
/// `quit` runs.
#[test]
fn repl_recovers_from_errors_and_quits() {
    let dir = tempfile::tempdir().unwrap();
    let [after_error, after_quit] = ["a.pem", "b.pem"].map(|name| dir.path().join(name));
    let script = format!(
        "bogus command
publish --app piv --part identity -n Jane --to {}
quit
publish --app piv --part identity -n Jane --to {}
",
        after_error.display(),
        after_quit.display()
    );

    let out = repl(&script, &["-s", TEST_PHRASE]);
    carried_on(&out, 1);
    assert!(after_error.exists(), "the command after the bad line did not run");
    assert!(!after_quit.exists(), "a line after quit ran");
}

/// A piped session never prompts: a seed-needing line without a seed is an error, the
/// session survives it, and the next line still runs.
#[test]
fn piped_session_never_prompts_for_seed() {
    let out = repl("publish -n Jane -m jane@example.com\nset\nquit\n", &[]);
    let err = stderr(&out);

    carried_on(&out, 1);
    assert!(err.contains("No seed phrase given"), "the missing seed is not reported:\n{err}");
    assert!(stdout(&out).contains("no defaults set"), "the line after it did not run");
}

/// Seeds and passwords cannot be named on a session line; asking for a seed can.
#[test]
fn repl_rejects_secret_arguments() {
    for line in [
        "check --seed foo",
        "check --seed=foo",
        "check --password=x",
        "check --password x",
        "check -p x",
        "check -sabandon",
        "upload --card-seed='abandon art'",
        "upload --key-seed=abandon",
        "rotate --from-key-seed=abandon --date 2027-01-01",
        "rotate --from-key-password=x --date 2027-01-01",
        "set --key-password=x",
        // A phrase after a bare seed flag, with a space where `=` belongs
        "upload --card-seed abandon abandon art",
        "upload --key-seed zoo wrong",
    ] {
        let out = repl(&format!("{line}\nquit\n"), &[]);
        let err = stderr(&out);

        carried_on(&out, 1);
        assert!(err.contains("fixed for the session"), "no rejection for {line:?}:\n{err}");
        for word in ["abandon", "zoo"] {
            assert!(!err.contains(word), "{line:?} was echoed:\n{err}");
        }
    }

    // A bare seed flag asks for that seed, which a piped session cannot, but it is no secret
    let out = repl(&format!("upload --key-seed --card {NO_CARD}\nquit\n"), &["-s", TEST_PHRASE]);
    let err = stderr(&out);
    assert!(!err.contains("fixed for the session"), "a bare --key-seed was refused:\n{err}");
    assert!(err.contains("No key seed phrase given"), "the bare seed was not asked for:\n{err}");
}

/// A line that looks like a seed phrase is neither stored nor echoed back.
#[test]
fn a_phrase_typed_at_the_prompt_is_not_echoed() {
    let out = repl("abandon ability able about above\nquit\n", &[]);
    let err = stderr(&out);

    carried_on(&out, 1);
    assert!(err.contains("looks like a seed phrase"), "the line was not recognised:\n{err}");
    assert!(!err.contains("ability"), "the phrase was echoed:\n{err}");
}

/// A half-quoted line is rejected without killing the session, like any other bad line.
#[test]
fn repl_survives_unbalanced_quotes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("root.pem");
    let script = format!(
        "publish --to x \"half quoted
publish --app piv --part identity -n Jane --to {}
quit
",
        path.display()
    );

    let out = repl(&script, &["-s", TEST_PHRASE]);
    let err = stderr(&out);

    carried_on(&out, 1);
    assert!(err.contains("Unbalanced quotes"), "the bad line is not called out:\n{err}");
    assert!(path.exists(), "the command after the bad line did not run");
}

/// Process options are fixed when the program starts, not per line.
#[test]
fn process_options_are_fixed_per_session() {
    for line in [
        "set --plumbing",
        "set --log-level debug",
        "set --config x.toml",
    ] {
        let out = repl(&format!("{line}\nquit\n"), &[]);
        let err = stderr(&out);
        assert!(err.contains("fixed when the program starts"), "{line:?} was taken:\n{err}");
    }
}

/// The session's help is the session's: a line has no program name, so neither has the usage
/// it shows, and the options a line cannot change are left out of it, though a line naming
/// one is still refused with the reason. `quit` is listed here, where it runs. Help is what
/// the line asked for, so it is no failed line, and it is shown once.
#[test]
fn the_session_help_fits_the_session() {
    let out = repl("help upload\nhelp\nupload --help\n", &[]);
    let text = stdout(&out);
    assert!(out.status.success(), "help failed a line:\n{}", stderr(&out));
    assert!(text.contains("Usage: upload [OPTIONS]"), "{text}");
    assert!(!text.contains("Usage: mtg"), "the help names a program:\n{text}");
    assert!(!text.contains("mind-the-gap upload"), "the help names a program:\n{text}");
    for hidden in [
        "--log-level",
        "--plumbing",
        "--config",
        "--seed",
        "--key-password",
    ] {
        assert!(!text.contains(hidden), "the session's help shows {hidden}:\n{text}");
    }
    assert!(text.contains("  quit "), "quit is not listed:\n{text}");
    assert_eq!(text.matches("Usage: upload [OPTIONS]").count(), 2, "{text}");
}

/// The session's tab key completes what the session's own help offers: the verbs, a verb's
/// options, the values of an option that takes one of a few, and the names `set` and `unset`
/// take. Never the seed or a password flag, which a line cannot carry, and never a value of an
/// option that takes a secret; a seed flag a line gives bare, to be asked, is offered.
#[test]
fn tab_completes_from_the_session_command() {
    use mind_the_gap::cli::complete;

    let completions = |line: &str| complete(line, line.len());
    assert_eq!(completions("che"), (0, vec!["check ".into()]));
    assert_eq!(completions("help up"), (5, vec!["upload ".into()]));
    let (_, verbs) = completions("");
    for verb in ["generate ", "upload ", "set ", "quit ", "help "] {
        assert!(verbs.contains(&verb.to_string()), "{verb} is not offered: {verbs:?}");
    }

    assert_eq!(completions("upload --po"), (7, vec!["--policy ".into()]));
    assert_eq!(completions("upload --policy st").1, ["strict "]);
    assert_eq!(completions("upload --policy=st").1, ["--policy=strict "]);
    assert_eq!(completions("upload -c 1 --app p").1, ["piv ", "pgp "]);
    assert_eq!(completions("publish --key si").1, ["signature"]);
    assert_eq!(completions("publish --key signature,de").1, ["signature,decryption"]);

    assert_eq!(completions("set pol"), (4, vec!["policy=".into()]));
    assert_eq!(completions("set policy=re").1, ["policy=relaxed "]);
    assert_eq!(completions("set pgp.algo").1, ["pgp.algorithm="]);
    assert_eq!(completions("set pgp.algorithm=rsa4").1, ["pgp.algorithm=rsa4096 "]);
    assert_eq!(completions("set legacy=t").1, ["legacy=true "]);
    assert_eq!(completions("set --sa").1, ["--save "]);
    assert_eq!(completions("unset sub").1, ["subkey "]);

    // What a line cannot carry is never offered, nor a secret's value
    let (_, flags) = completions("check --");
    for hidden in [
        "--seed ",
        "--password ",
        "--card-password ",
        "--key-password ",
        "--log-level ",
        "--plumbing ",
        "--config ",
    ] {
        assert!(!flags.contains(&hidden.to_string()), "{hidden} is offered: {flags:?}");
    }
    // A bare seed flag asks for that seed, which a line may
    for offered in ["--pin ", "--card-seed ", "--key-seed "] {
        assert!(flags.contains(&offered.to_string()), "{offered} is not offered: {flags:?}");
    }
    assert_eq!(completions("rotate --from").1, ["--from-key-seed "]);
    assert!(completions("rotate --from-key-p").1.is_empty());
    assert!(completions("check --pin 12").1.is_empty());
    assert!(completions("set pin").1.is_empty());
    assert!(completions("set seed=").1.is_empty());
}

/// Whitespace of more than one byte, a no-break space typed with AltGr or an ideographic
/// space, separates words like any other, and a cursor inside a character completes nothing:
/// the tab key never panics on a line, which would end the session and print the line.
#[test]
fn tab_completes_past_wide_whitespace() {
    use mind_the_gap::cli::complete;

    for space in ['\u{a0}', '\u{3000}'] {
        let line = format!("check{space}--po");
        let (start, candidates) = complete(&line, line.len());
        assert_eq!(&line[start..], "--po", "{space:?}");
        assert_eq!(candidates, ["--policy "], "{space:?}");

        let line = format!("publish{space}--key{space}sig");
        assert_eq!(complete(&line, line.len()).1, ["signature"], "{space:?}");
        // The cursor one byte into the space
        assert!(complete(&line, "publish".len() + 1).1.is_empty(), "{space:?}");
    }
}
