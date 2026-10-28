//! Ceremonies: recipes run in order, dry runs, records and what a ceremony file may hold.

use crate::{NO_CARD, bin, root_subject, seeded, stderr, stdout};

use std::path::Path;

/// Write a ceremony file into `dir`
fn ceremony(dir: &Path, text: &str) -> std::path::PathBuf {
    let path = dir.join("ceremony");
    std::fs::write(&path, text).unwrap();
    path
}

/// Recipes run after the recipes they depend on, each once, the first one by default; a
/// ceremony's `set` lasts as long as the ceremony.
#[test]
fn ceremonies_run_dependencies_first_and_once() {
    let dir = tempfile::tempdir().unwrap();
    let out_dir = dir.path().join("out");
    let file = ceremony(
        dir.path(),
        &format!(
            "# The identity's public material
all: name first second
    publish --app piv --part identity --to {out}/all.pem

name:
    set name=Jane

first: name
    publish --app piv --part identity --to {out}/first.pem

second: name first
    publish --app piv --part identity --to {out}/second.pem
",
            out = out_dir.display()
        ),
    );

    let out = seeded(&["run", "--ceremony", file.to_str().unwrap()]);
    let err = stderr(&out);
    assert!(out.status.success(), "the ceremony failed:\n{err}");
    for name in ["first", "second", "all"] {
        let pem = std::fs::read(out_dir.join(format!("{name}.pem"))).unwrap();
        assert_eq!(
            root_subject(&pem),
            "CN=Jane PIV Root CA p256",
            "{name} missed the ceremony's set"
        );
    }
    let order: Vec<_> = err
        .lines()
        .filter(|line| line.starts_with("==> "))
        .collect();
    assert_eq!(order.len(), 4, "a recipe ran more than once:\n{err}");
    assert!(order[0].contains("name: set name=Jane"), "{order:?}");
    assert!(order[1].contains("first: publish"), "{order:?}");
    assert!(order[2].contains("second: publish"), "{order:?}");
    assert!(order[3].contains("all: publish"), "{order:?}");

    // A recipe named on its own runs with its dependencies only
    std::fs::remove_dir_all(&out_dir).unwrap();
    let out = seeded(&["run", "--ceremony", file.to_str().unwrap(), "first"]);
    assert!(out.status.success(), "the named recipe failed:\n{}", stderr(&out));
    assert!(out_dir.join("first.pem").exists());
    assert!(!out_dir.join("second.pem").exists(), "a recipe outside the dependencies ran");
}

/// A failing step stops the ceremony: nothing after it runs, and the exit says so.
#[test]
fn a_failing_step_stops_the_ceremony() {
    let dir = tempfile::tempdir().unwrap();
    let after = dir.path().join("after.pem");
    let file = ceremony(
        dir.path(),
        &format!(
            "card:
    upload --card {NO_CARD} -n Jane
    publish --app piv --part identity -n Jane --to {}
",
            after.display()
        ),
    );

    let out = seeded(&["run", "--ceremony", file.to_str().unwrap()]);
    let err = stderr(&out);
    assert!(!out.status.success(), "a failed ceremony exited zero");
    assert!(err.contains("Step 1 of the ceremony failed"), "the failing step is not named:\n{err}");
    assert!(!after.exists(), "a step after the failure ran");
}

/// A dry run hands `--dry-run` to the steps that write, and skips what leaves the gap;
/// a record of it keeps the steps, never a secret.
#[test]
fn a_dry_run_writes_nothing_and_a_record_keeps_no_secret() {
    let dir = tempfile::tempdir().unwrap();
    let [revocation, published] = ["rev.asc", "pub.asc"].map(|name| dir.path().join(name));
    let record = dir.path().join("record");
    let file = ceremony(
        dir.path(),
        &format!(
            "retire:
    revoke --app pgp --kind subkeys -n Jane --to {}
    publish --app pgp -n Jane -m jane@example.com --to {}
",
            revocation.display(),
            published.display()
        ),
    );

    let out = seeded(&[
        "run",
        "--ceremony",
        file.to_str().unwrap(),
        "--dry-run",
        "--record",
        record.to_str().unwrap(),
    ]);
    let err = stderr(&out);
    assert!(out.status.success(), "the dry run failed:\n{err}");
    assert!(stdout(&out).contains("Would write the OpenPGP revocation"), "no dry run:\n{err}");
    assert!(err.contains("not run in a dry run"), "the outbound step was not skipped:\n{err}");
    assert!(!revocation.exists() && !published.exists(), "a dry run wrote a file");

    let transcripts: Vec<_> = std::fs::read_dir(&record).unwrap().collect();
    assert_eq!(transcripts.len(), 1, "not one transcript");
    let transcript = std::fs::read_to_string(transcripts[0].as_ref().unwrap().path()).unwrap();
    // The tool's version line, as `--version` gives it, scheme and all
    let version = stdout(&bin().arg("--version").output().unwrap());
    assert_eq!(transcript.lines().next(), Some(version.trim_end()), "{transcript}");
    assert!(transcript.contains("recipe retire"), "the recipe is not named:\n{transcript}");
    assert!(transcript.contains("revoke --app pgp"), "the step is missing:\n{transcript}");
    assert!(transcript.contains("ceremony finished"), "the end is missing:\n{transcript}");
    assert!(!transcript.contains("abandon"), "the seed reached the transcript:\n{transcript}");
}

/// `run --check` checks the whole file and lists the recipe's steps, running none: it needs
/// no seed, and a secret in a recipe that is not asked for still fails it.
#[test]
fn a_ceremony_is_checked_without_running() {
    let dir = tempfile::tempdir().unwrap();
    let good = "card: init keys\n\ninit:\n    init --yes\n\nkeys: init\n    upload --yes\n";
    let file = ceremony(dir.path(), good);
    let out = bin()
        .args(["run", "--check", "--ceremony", file.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "a sound ceremony failed its check:\n{}", stderr(&out));
    assert_eq!(
        stdout(&out),
        "Recipes: card (init keys), init, keys (init)\n[1/2] init: init --yes\n[2/2] keys: \
         upload --yes\n"
    );

    // A recipe the file lacks is answered with the ones it has
    let out = bin()
        .args([
            "run",
            "--check",
            "--ceremony",
            file.to_str().unwrap(),
            "nosuch",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "a missing recipe was checked");
    assert!(
        stderr(&out).contains("no recipe `nosuch`; it has card, init, keys"),
        "{}",
        stderr(&out)
    );

    let file = ceremony(dir.path(), &format!("{good}\nother:\n    check --pin 123456\n"));
    let out = bin()
        .args(["run", "--check", "--ceremony", file.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success(), "a pin in another recipe passed the check");
    assert!(stderr(&out).contains("recipe `other`"), "{}", stderr(&out));
}

/// A ceremony file holds no secret, not even a pin, and runs no other ceremony.
#[test]
fn ceremony_files_hold_no_secrets() {
    let dir = tempfile::tempdir().unwrap();
    for (step, complaint) in [
        (format!("init --card {NO_CARD} --pin 123456"), "A pin"),
        (format!("init --card {NO_CARD} -i123456"), "A pin"),
        ("check --seed abandon".to_string(), "The seed"),
        ("run other".to_string(), "cannot run another ceremony"),
        ("set --save name=Jane".to_string(), "saves defaults"),
        ("unset --save name".to_string(), "saves defaults"),
    ] {
        let file = ceremony(dir.path(), &format!("only:\n    {step}\n"));
        let record = dir.path().join("record");
        let out = seeded(&[
            "run",
            "--ceremony",
            file.to_str().unwrap(),
            "--record",
            record.to_str().unwrap(),
        ]);
        let err = stderr(&out);
        assert!(!out.status.success(), "{step:?} ran");
        assert!(err.contains(complaint), "{step:?} refused for another reason:\n{err}");
        // Refused before it is shown or recorded, so the secret is on neither
        for secret in ["123456", "abandon"] {
            assert!(!err.contains(secret), "{step:?} was echoed:\n{err}");
        }
        assert!(!record.exists(), "{step:?} started a transcript");
    }

    let file = ceremony(dir.path(), "a: b\n    set name=x\nb: a\n    set name=y\n");
    let out = seeded(&["run", "--ceremony", file.to_str().unwrap()]);
    assert!(stderr(&out).contains("depends on itself"), "a cycle ran:\n{}", stderr(&out));
}
