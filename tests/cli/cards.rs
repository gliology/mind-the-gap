//! The verbs that write cards, stopped before any card: init, pin, rotate and check.

use crate::{NO_CARD, TEST_PHRASE, WHO, bin, carried_on, repl, seeded, stderr, stdout};

/// The legacy scheme is for cards provisioned under it; `init` only ever installs the current
/// one, as its admin pin would be one no later legacy verb derives.
#[test]
fn init_refuses_the_legacy_scheme() {
    let out = seeded(&[
        "init", "--app", "pgp", "--legacy", "--yes", "--card", NO_CARD,
    ]);
    assert!(!out.status.success(), "init --legacy ran");
    assert!(stderr(&out).contains("current scheme"), "{}", stderr(&out));
}

/// A dry run of `pin` writes no pin, so it asks for none.
#[test]
fn a_pin_dry_run_needs_no_pins() {
    for args in [&["pin", "--reset"][..], &["pin"][..]] {
        let out = seeded(&[args, &["--dry-run", "--card", NO_CARD]].concat());
        let err = stderr(&out);
        assert!(!err.contains("pin given"), "{args:?} --dry-run asked for a pin:\n{err}");
    }
}

/// A PIV pin is held to 6 to 8 ASCII characters before a card is looked for.
#[test]
fn piv_pins_are_validated_before_the_card() {
    for pin in ["123", "123456789", "pïnpïn"] {
        let out = bin()
            .args([
                "pin",
                "--app",
                "piv",
                "--card",
                NO_CARD,
                "--current-pin",
                "123456",
                "-i",
                pin,
            ])
            .output()
            .unwrap();
        let err = stderr(&out);
        assert!(!out.status.success(), "pin accepted {pin:?}");
        assert!(err.contains("6 and 8"), "unexpected pin error for {pin:?}:\n{err}");

        let out = seeded(&["init", "--app", "piv", "--card", NO_CARD, "-i", pin]);
        let err = stderr(&out);
        assert!(!out.status.success(), "init accepted {pin:?}");
        assert!(err.contains("6 and 8"), "unexpected init pin error for {pin:?}:\n{err}");
    }
}

/// A one-shot pin change never prompts: a missing pin is an error naming the ways out, and
/// changing a pin with the current one needs no seed.
#[test]
fn pin_change_without_pins_names_the_ways_out() {
    let cases: [(&[&str], &str); 2] = [
        (&["pin", "--card", NO_CARD], "--pin (or MIND_THE_PIN)"),
        (&["pin", "--card", NO_CARD, "-i", "654321"], "--current-pin (or MIND_THE_CURRENT_PIN)"),
    ];
    for (args, way) in cases {
        let out = bin().args(args).output().unwrap();
        let err = stderr(&out);

        assert!(!out.status.success(), "{args:?} exited zero");
        assert!(err.contains(way), "{args:?} does not name {way}:\n{err}");
        assert!(err.contains("interactive session"), "{args:?} omits the session:\n{err}");
        assert!(!err.contains("No seed phrase"), "{args:?} demanded a seed:\n{err}");
    }

    let out = bin()
        .args([
            "pin",
            "--card",
            NO_CARD,
            "--current-pin",
            "123456",
            "-i",
            "654321",
        ])
        .output()
        .unwrap();
    let err = stderr(&out);
    assert!(!out.status.success(), "pin found a card that cannot exist");
    assert!(!err.contains("No seed phrase"), "a pin change demanded a seed:\n{err}");

    // A reset takes the card seed, which a one-shot invocation does not ask for
    let out = bin()
        .args(["pin", "--reset", "--card", NO_CARD, "-i", "654321"])
        .output()
        .unwrap();
    assert!(stderr(&out).contains("No seed phrase"), "pin --reset ran without the card seed");
}

/// A piped session has no terminal to ask a new pin on, and goes on after refusing.
#[test]
fn piped_pin_change_never_prompts() {
    let out = repl(&format!("pin --card {NO_CARD}\nset\nquit\n"), &["-s", TEST_PHRASE]);
    let err = stderr(&out);

    carried_on(&out, 1);
    assert!(err.contains("No new pin given"), "the pin change did not refuse:\n{err}");
    assert!(stdout(&out).contains("no defaults set"), "the line after pin did not run");
}

/// Initializing without a pin warns about the factory pin before anything else happens.
#[test]
fn factory_pin_warns() {
    let out = seeded(&["init", "--card", NO_CARD]);
    let err = stderr(&out);

    // The run still dies at the missing card, but the warning must be on record by then
    assert!(!out.status.success(), "init without a card exited zero");
    assert!(err.contains("factory user pin"), "init does not warn about the factory pin:\n{err}");
}

/// A rotation needs somewhere to go: a new generation or another key seed.
#[test]
fn rotation_needs_a_new_generation() {
    let out = seeded(&["rotate", "--card", NO_CARD, "-n", "Alice"]);
    let err = stderr(&out);

    assert!(!out.status.success(), "rotate without --date exited zero");
    assert!(err.contains("--date"), "the way out is not named:\n{err}");
    assert!(err.contains("--from-key-seed"), "the other way out is not named:\n{err}");
}

/// `check` shows the record a phrase is checked against before it looks for a card.
#[test]
fn check_shows_the_record_first() {
    let out = seeded(&[&["check", "--card", NO_CARD][..], &WHO].concat());
    let text = stdout(&out);

    assert!(!out.status.success(), "check found a card that cannot exist");
    assert!(text.contains("Seed id: "), "no seed id:\n{text}");
    assert!(
        text.contains("OpenPGP identity: 38BAAB2F9DE7D459C34A80B3AF859A5F33253C3A"),
        "no OpenPGP identity:\n{text}"
    );
    assert!(text.contains("PIV root authority: "), "no PIV identity:\n{text}");

    // A password moves the seed id, which is what the record is for
    let other = bin()
        .args([
            "-s",
            TEST_PHRASE,
            "-p",
            "hunter2",
            "check",
            "--card",
            NO_CARD,
        ])
        .args(WHO)
        .output()
        .unwrap();
    let id = |text: &str| {
        text.lines()
            .find(|line| line.starts_with("Seed id"))
            .map(String::from)
    };
    assert_ne!(id(&text), id(&stdout(&other)), "the password left the seed id alone");
}

/// A pin one applet cannot take holds back neither the record nor the other applet's
/// comparison, unless that applet was named.
#[test]
fn check_holds_a_pin_to_the_applet_it_fits() {
    // Nine characters: an OpenPGP pin, too long for PIV
    let out = seeded(
        &[
            &["check", "--card", NO_CARD, "--pin", "123456789"][..],
            &WHO,
        ]
        .concat(),
    );
    let (text, err) = (stdout(&out), stderr(&out));
    assert!(text.contains("PIV root authority: "), "no PIV identity:\n{text}");
    assert!(text.contains("OpenPGP identity: "), "no OpenPGP identity:\n{text}");
    assert!(err.contains("PIV is compared without it"), "no warning:\n{err}");

    let out = seeded(
        &[
            &[
                "check",
                "--app",
                "piv",
                "--card",
                NO_CARD,
                "--pin",
                "123456789",
            ][..],
            &WHO,
        ]
        .concat(),
    );
    let err = stderr(&out);
    assert!(!out.status.success(), "a named applet took a pin it cannot");
    assert!(err.contains("PIV pin needs to be between 6 and 8"), "{err}");
}

/// A name or a list URL PIV's certificates cannot carry holds back neither the record nor the
/// OpenPGP comparison where PIV was not named: `check` leaves PIV out with a warning, as it
/// does a pin; named, PIV refuses them before any seed is stretched
#[test]
fn check_holds_an_identity_to_the_applet_it_fits() {
    let long = "A".repeat(41);
    for (unfit, told) in [
        (&["-n", &long][..], "--name is 41 characters"),
        (
            &["-n", "Alice", "--crl-url", "http://example.org/alice"][..],
            "does not end in a list's name",
        ),
    ] {
        let out = seeded(
            &[
                &["check", "--card", NO_CARD][..],
                unfit,
                &["-m", "alice@example.com"],
            ]
            .concat(),
        );
        let (text, err) = (stdout(&out), stderr(&out));
        assert!(text.contains("OpenPGP identity: "), "no OpenPGP identity:\n{text}");
        assert!(!text.contains("PIV root authority: "), "a PIV identity:\n{text}");
        assert!(err.contains("No PIV identity: "), "no warning:\n{err}");
        assert!(err.contains(told), "{told} untold:\n{err}");
        assert!(!out.status.success(), "check found a card that cannot exist");

        let out = bin()
            .args([
                "-s",
                "not a phrase",
                "check",
                "--app",
                "piv",
                "--card",
                NO_CARD,
            ])
            .args(unfit)
            .output()
            .unwrap();
        let err = stderr(&out);
        assert!(!out.status.success(), "a named PIV took what it cannot carry");
        assert!(err.contains(told), "{told} untold:\n{err}");
        assert!(!err.contains("BIP-39"), "the seed was reached first:\n{err}");
    }
}
