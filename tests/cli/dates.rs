//! Dates: generations, validity and the days a key can be created on.

use crate::{WHO, bin, repl, root_pem, seeded, stderr, stdout};

/// A date is midnight UTC wherever the command runs: the timezone of the machine it is typed
/// on must not reach a derivation input. Kiritimati is as far ahead of UTC as any zone gets,
/// and the far western end is spelled the POSIX way, which needs no zone database, so the
/// test cannot pass vacuously on a machine without one.
#[test]
fn dates_ignore_the_timezone() {
    use x509_cert::der::DecodePem;

    let root = |tz: &str| {
        let mut cmd = bin();
        cmd.env("TZ", tz);
        root_pem(cmd, &["-n", "Alice", "--identity-date", "2026-01-01"])
    };

    let utc = root("UTC");
    for tz in ["Pacific/Kiritimati", "<-12>12"] {
        assert_eq!(root(tz), utc, "TZ={tz} moved the date");
    }

    let root = x509_cert::Certificate::from_pem(utc).unwrap();
    let not_before = root
        .tbs_certificate()
        .validity()
        .not_before
        .to_unix_duration();
    assert_eq!(not_before.as_secs(), 1_767_225_600, "--identity-date is not midnight UTC");
}

/// A day is also a creation time, which OpenPGP keeps as unsigned 32-bit seconds: a day
/// outside them would derive under its label but read back as another generation.
#[test]
fn dates_outside_the_creation_times_are_refused() {
    for option in ["--date", "--identity-date"] {
        for day in [
            "1969-12-31",
            "0001-01-01",
            "-0001-01-01",
            "2106-02-08",
            "+10000-01-01",
        ] {
            // Joined, so that a leading minus reaches the date parser rather than clap's
            let given = format!("{option}={day}");
            let out =
                seeded(&[&["publish", "--app", "piv", &given, "--to", "-"][..], &WHO].concat());
            assert!(!out.status.success(), "{option} {day} was accepted");
            assert!(stderr(&out).contains("outside the days"), "{option} {day}:\n{}", stderr(&out));
        }
    }
    for day in ["1970-01-01", "2106-02-07"] {
        let out = seeded(
            &[
                &[
                    "publish",
                    "--app",
                    "pgp",
                    "--identity-date",
                    day,
                    "--to",
                    "-",
                ][..],
                &WHO,
            ]
            .concat(),
        );
        assert!(out.status.success(), "--identity-date {day} was refused:\n{}", stderr(&out));
    }
}

/// A validity counts from the generation's day; without one the keys date from the epoch,
/// and a validity would publish certificates that expired in 1971.
#[test]
fn a_validity_needs_a_date() {
    for app in ["piv", "pgp"] {
        let out = seeded(
            &[
                &["publish", "--app", app, "--validity", "1y", "--to", "-"][..],
                &WHO,
            ]
            .concat(),
        );
        assert!(!out.status.success(), "{app}: a validity without a date was taken");
        assert!(stderr(&out).contains("--identity-date"), "{app}: {}", stderr(&out));

        let out = seeded(
            &[
                &[
                    "publish",
                    "--app",
                    app,
                    "--validity",
                    "1y",
                    "--identity-date",
                    "2026-01-01",
                    "--to",
                    "-",
                ][..],
                &WHO,
            ]
            .concat(),
        );
        assert!(out.status.success(), "{app}: refused with a date:\n{}", stderr(&out));
    }
}

/// A validity counts calendar days, weeks, months and years from the generation's midnight:
/// two years from New Year end on New Year two years on, and a month from the 31st ends on
/// the last day of a shorter month. OpenPGP's subkeys expire on the same day as PIV's
/// certificates.
#[test]
fn a_validity_counts_on_the_calendar() {
    use sequoia_openpgp::parse::Parse;
    use x509_cert::der::DecodePem;

    let not_after = |date: &str, validity: &str| {
        let out = seeded(
            &[
                &[
                    "publish",
                    "--app",
                    "piv",
                    "--part",
                    "keys",
                    "--key",
                    "signature",
                    "--date",
                    date,
                    "--validity",
                    validity,
                    "--to",
                    "-",
                ][..],
                &WHO,
            ]
            .concat(),
        );
        assert!(out.status.success(), "{validity} from {date}:\n{}", stderr(&out));
        x509_cert::Certificate::from_pem(out.stdout)
            .unwrap()
            .tbs_certificate()
            .validity()
            .not_after
            .to_unix_duration()
            .as_secs()
    };
    // 2028-01-01T00:00:00Z, a calendar year being no 365.25 days
    assert_eq!(not_after("2026-01-01", "2y"), 1_830_297_600);
    assert_eq!(not_after("2026-01-01", "24mo"), 1_830_297_600);
    assert_eq!(not_after("2026-01-01", "730d"), 1_830_297_600);
    // 2026-01-15T00:00:00Z
    assert_eq!(not_after("2026-01-01", "2w"), 1_768_435_200);
    // 2026-02-28T00:00:00Z, the last day of February
    assert_eq!(not_after("2026-01-31", "1mo"), 1_772_236_800);
    // 2029-02-28T00:00:00Z, a year from a leap day
    assert_eq!(not_after("2028-02-29", "1y"), 1_866_931_200);

    let out = seeded(
        &[
            &[
                "publish",
                "--app",
                "pgp",
                "--date",
                "2026-01-01",
                "--validity",
                "2y",
                "--to",
                "-",
            ][..],
            &WHO,
        ]
        .concat(),
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let cert = sequoia_openpgp::Cert::from_bytes(&out.stdout).unwrap();
    let policy = sequoia_openpgp::policy::StandardPolicy::new();
    let created = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_767_225_600);
    let valid = cert.with_policy(&policy, created).unwrap();
    assert_eq!(valid.keys().subkeys().count(), 3, "not the three subkeys");
    for key in valid.keys().subkeys() {
        let expires = key.key_expiration_time().unwrap();
        assert_eq!(
            expires,
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_830_297_600),
            "an OpenPGP subkey does not expire with the PIV certificates"
        );
    }
}

/// A validity ends no later than the last day OpenPGP can tell, 2106-02-07: past it a subkey's
/// expiry would wrap round to a day long gone, so a longer one is refused with the limit named
/// and the way to have no end at all, for both applets alike.
#[test]
fn a_validity_ends_by_the_last_day_a_key_can_tell() {
    // 2026-01-01 plus 80 years is 2106-01-01, inside; plus 81 is 2107-01-01, outside
    let publish = |app: &str, validity: &str| {
        seeded(
            &[
                &[
                    "publish",
                    "--app",
                    app,
                    "--date",
                    "2026-01-01",
                    "--validity",
                    validity,
                    "--to",
                    "-",
                ][..],
                &WHO,
            ]
            .concat(),
        )
    };
    for app in ["piv", "pgp"] {
        let out = publish(app, "80y");
        assert!(out.status.success(), "{app}: 80y was refused:\n{}", stderr(&out));
        for validity in ["81y", "137y", "7974y", "1100mo"] {
            let out = publish(app, validity);
            let err = stderr(&out);
            assert!(!out.status.success(), "{app}: {validity} was taken");
            assert!(err.contains("ends after 2106-02-07"), "{app} {validity}:\n{err}");
            assert!(err.contains("leave --validity out"), "{app} {validity}:\n{err}");
        }
    }
}

/// A validity takes calendar units alone: minutes, hours and seconds are refused with the
/// units named, `24m` most of all, which once read as 24 minutes; no short flag stands for it,
/// and a config file, the environment and `set` take it through the same parser.
#[test]
fn a_validity_takes_calendar_units_alone() {
    for validity in ["24m", "1h", "90s", "2", "0d", "1.5y", "2 years"] {
        let out = seeded(
            &[
                &[
                    "publish",
                    "--app",
                    "piv",
                    "--date",
                    "2026-01-01",
                    "--validity",
                    validity,
                    "--to",
                    "-",
                ][..],
                &WHO,
            ]
            .concat(),
        );
        let err = stderr(&out);
        assert!(!out.status.success(), "--validity {validity} was taken");
        assert!(err.contains("730d, 2w, 6mo or 2y"), "{validity}: the units are not named:\n{err}");
    }
    let out = seeded(&["publish", "--app", "piv", "--validity", "24m"]);
    assert!(stderr(&out).contains("months are `mo`"), "{}", stderr(&out));

    let out = seeded(
        &[
            &["publish", "--app", "piv", "-v", "2y", "--to", "-"][..],
            &WHO,
        ]
        .concat(),
    );
    assert!(!out.status.success(), "-v still stands for --validity");

    let mut cmd = bin();
    cmd.env("MIND_THE_VALIDITY", "1h");
    let out = cmd.args(["publish"]).output().unwrap();
    assert!(stderr(&out).contains("730d, 2w, 6mo or 2y"), "{}", stderr(&out));

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "validity = \"24m\"\n").unwrap();
    let out = bin()
        .args(["--config", config.to_str().unwrap(), "publish"])
        .output()
        .unwrap();
    let err = stderr(&out);
    assert!(err.contains("config.toml") && err.contains("months are `mo`"), "{err}");

    let out = repl("set validity=1h\nset validity=6mo\nset\n", &[]);
    assert!(stderr(&out).contains("730d, 2w, 6mo or 2y"), "{}", stderr(&out));
    assert!(stdout(&out).contains("validity = 6mo"), "{}", stdout(&out));
}

/// A generation's date moves its keys, and starts its certificates; the identity stays.
#[test]
fn the_date_is_a_generation() {
    use x509_cert::der::DecodePem;

    let keys = |args: &[&str]| {
        let out = seeded(
            &[
                &[
                    "publish",
                    "--app",
                    "piv",
                    "--part",
                    "keys",
                    "--key",
                    "signature",
                    "--to",
                    "-",
                ][..],
                &WHO,
                args,
            ]
            .concat(),
        );
        assert!(out.status.success(), "publish failed:\n{}", stderr(&out));
        x509_cert::Certificate::from_pem(out.stdout).unwrap()
    };
    let undated = keys(&[]);
    let dated = keys(&["--date", "2026-01-01"]);
    assert_ne!(
        undated.tbs_certificate().subject_public_key_info(),
        dated.tbs_certificate().subject_public_key_info(),
        "the date did not move the key"
    );
    assert_eq!(
        dated
            .tbs_certificate()
            .validity()
            .not_before
            .to_unix_duration()
            .as_secs(),
        1_767_225_600,
        "the generation's certificate does not start at its date"
    );
    assert_eq!(
        root_pem(bin(), &["-n", "Alice"]),
        root_pem(bin(), &["-n", "Alice", "-d", "2026-01-01"])
    );
}

/// No key can be older than the identity that certifies it: without a `--date` the keys are
/// of the identity's own generation, and a date before the identity is refused
#[test]
fn keys_default_to_the_identity_generation() {
    let publish = |extra: &[&str]| {
        seeded(&[&["publish", "--app", "pgp", "--to", "-"][..], &WHO, extra].concat())
    };
    let defaulted = publish(&["--identity-date", "2026-01-01"]);
    assert!(defaulted.status.success(), "{}", stderr(&defaulted));
    let explicit = publish(&["--identity-date", "2026-01-01", "--date", "2026-01-01"]);
    assert!(explicit.status.success(), "{}", stderr(&explicit));
    assert_eq!(defaulted.stdout, explicit.stdout, "the identity date is not the generation");

    let older = publish(&["--identity-date", "2026-01-01", "--date", "2025-12-31"]);
    assert!(!older.status.success(), "keys older than their identity were certified");
    assert!(stderr(&older).contains("no key can be older"), "{}", stderr(&older));
}
