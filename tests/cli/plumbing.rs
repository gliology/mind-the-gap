//! Plumbing: one JSON object per command, no prompt and no QR code.

use crate::{NO_CARD, TEST_PHRASE, WHO, bin, repl, stderr, stdout};

/// Plumbing never waits on a key: material without `--to` would go to the QR viewer, which
/// does, so it is refused.
#[test]
fn plumbing_shows_no_qr_codes() {
    for verb in ["publish", "ungap"] {
        let out = bin()
            .args(["--plumbing", "-s", TEST_PHRASE, verb, "--app", "pgp"])
            .args(WHO)
            .output()
            .unwrap();
        assert!(!out.status.success(), "{verb} without --to succeeded in plumbing mode");
        assert!(stdout(&out).contains("shows no QR codes"), "{verb}: {}", stdout(&out));
    }
}

/// Plumbing: one JSON object per command on stdout, the human output on stderr.
#[test]
fn plumbing_reports_one_object_per_command() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cert.asc");
    let out = bin()
        .args(["--plumbing", "-s", TEST_PHRASE, "publish", "--app", "pgp"])
        .args(WHO)
        .args(["--to", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "plumbing publish failed:\n{}", stderr(&out));
    assert_eq!(stdout(&out), "{\"command\":\"publish\",\"ok\":true}\n");
    assert!(stderr(&out).contains("OpenPGP certificate"), "the log left stderr");

    // Secrets never go to stdout, which plumbing keeps for the reports anyway
    let out = bin()
        .args(["--plumbing", "-s", TEST_PHRASE, "ungap"])
        .args(WHO)
        .args(["--to", "-"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "ungap wrote secrets to stdout");
    let report = stdout(&out);
    assert!(report.starts_with("{\"command\":\"ungap\",\"ok\":false,\"error\":"), "{report}");
    assert!(report.contains("keeps stdout for its reports"), "{report}");
    assert!(!report.contains("PRIVATE KEY"), "the secret reached the report");

    // Nor does public material: stdout is the reports' alone
    let out = bin()
        .args(["--plumbing", "-s", TEST_PHRASE, "publish", "--app", "pgp"])
        .args(WHO)
        .args(["--to", "-"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "plumbing wrote a certificate to stdout");
    assert!(!stdout(&out).contains("BEGIN PGP"), "the certificate reached the reports");
}

/// A piped plumbing session reports every line, refused ones included, and stops at the
/// first error, as a script would want.
#[test]
fn plumbing_sessions_stop_at_the_first_error() {
    let dir = tempfile::tempdir().unwrap();
    let [first, last] = ["first.pem", "last.pem"].map(|name| dir.path().join(name));
    let script = format!(
        "publish --app piv --part identity -n Jane --to {}
bogus
publish --app piv --part identity -n Jane --to {}
",
        first.display(),
        last.display()
    );

    let out = repl(&script, &["--plumbing", "-s", TEST_PHRASE]);
    let reports: Vec<_> = stdout(&out).lines().map(String::from).collect();
    assert!(!out.status.success(), "a failed plumbing session exited zero");
    assert_eq!(reports.len(), 2, "not one report per line run: {reports:?}");
    assert_eq!(reports[0], "{\"command\":\"publish\",\"ok\":true}");
    assert!(reports[1].starts_with("{\"command\":\"bogus\",\"ok\":false"), "{reports:?}");
    assert!(first.exists() && !last.exists(), "the session did not stop at the error");
}

/// Plumbing reports what `check` found as data, the record even where no card is there to
/// compare, so a script reads the seed id and the identity's fingerprints off the report
#[test]
fn plumbing_check_reports_the_record() {
    let out = bin()
        .args(["--plumbing", "-s", TEST_PHRASE, "check", "--card", NO_CARD])
        .args(WHO)
        .output()
        .unwrap();
    let report = stdout(&out);
    assert!(report.starts_with("{\"command\":\"check\",\"ok\":false,"), "{report}");
    for field in ["\"seed_id\":\"", "\"piv_root\":\"", "\"pgp_identity\":\""] {
        assert!(report.contains(field), "{field} is missing from {report}");
    }
}
