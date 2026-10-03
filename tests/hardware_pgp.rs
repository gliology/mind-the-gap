//! On-card tests for the OpenPGP backend.
//!
//! The counterpart to `tests/hardware.rs`, gated on the same two features -- see the feature
//! comments in `Cargo.toml` for why the second one exists.
//!
//! **Running this wipes the card's OpenPGP applet.** `upload` factory-resets it. Note that it
//! resets *only* that applet: a card provisioned by `tests/hardware.rs` keeps its PIV keys, so
//! the two suites can share a token, just not at the same time.
//!
//! ```text
//! MTG_HARDWARE_TEST_CARD=0006:20381784 \
//!   cargo test --features destructive-hardware-tests --test hardware_pgp -- --nocapture
//! ```
//!
//! Unlike the PIV suite this one needs **no touches**: the OpenPGP applet is provisioned
//! through the admin pin, and a YubiKey ships with its touch policies off.
//!
//! The card is addressed by its OpenPGP *application identifier* (`0006:20381784`), not the
//! bare serial the PIV suite wants -- that is what `openpgp-card` matches on. `mind-the-gap
//! pgp status` prints it.

#![cfg(all(
    feature = "destructive-hardware-tests",
    not(feature = "no-destructive-hardware-tests")
))]

use mind_the_gap::pgp::{CertificateKind, SeededSmartcard, SubkeyRole};
use mind_the_gap::seed::Seed256;

use sequoia_openpgp::cert::Cert;
use sequoia_openpgp::policy::StandardPolicy;

use card_backend_pcsc::PcscBackend;
use openpgp_card::Card;
use openpgp_card::ocard::KeyType;

use zeroize::Zeroizing;

use std::time::{Duration, SystemTime};

/// Seed for the provisioned test identity. Deliberately different from the PIV suite's, so a
/// crossed wire between the two backends cannot pass by coincidence.
const TEST_SEED: Seed256 = [0xa7u8; 32];

const TEST_PIN: &str = "471120";
const TEST_NAME: &str = "Hardware Test";
const TEST_EMAIL: &str = "hardware-test@example.com";

/// Application identifier of the card under test.
///
/// Required, and required to be explicit, for the same reason as the PIV suite's serial: the
/// feature flag says "run destructive tests", this says "against *that* card".
fn target() -> String {
    match std::env::var("MTG_HARDWARE_TEST_CARD") {
        Ok(ident) if !ident.trim().is_empty() => ident.trim().to_string(),
        _ => panic!(
            "MTG_HARDWARE_TEST_CARD is not set.\n\
             \n\
             This test factory-resets the OpenPGP applet of the card it runs against, so it\n\
             will not pick one for you. Print the identifier with `mind-the-gap pgp status`\n\
             and pass it explicitly:\n\
             \n\
             \tMTG_HARDWARE_TEST_CARD=<ident> cargo test --features destructive-hardware-tests\n"
        ),
    }
}

fn subject() -> SeededSmartcard {
    SeededSmartcard::new(&TEST_SEED, None, TEST_NAME.into())
        .add_email(TEST_EMAIL)
        .unwrap()
        .with_pin(Zeroizing::new(TEST_PIN.to_string()))
        .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        .with_subkey_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
}

/// Open the card under test directly, bypassing the crate.
///
/// The assertions below have to be independent of the code they are checking, so they read the
/// card through `openpgp-card` rather than through `SeededSmartcard::check`.
fn open() -> Card<openpgp_card::state::Open> {
    let ident = target();
    let backends: Vec<PcscBackend> = PcscBackend::cards(None)
        .expect("cannot enumerate PC/SC cards")
        .filter_map(Result::ok)
        .collect();

    for backend in backends {
        let mut card = Card::new(backend).expect("cannot open card");
        let matches = {
            let tx = card.transaction().expect("cannot start card transaction");
            tx.application_identifier()
                .expect("cannot read application identifier")
                .ident()
                .eq_ignore_ascii_case(&ident)
        };
        if matches {
            return card;
        }
    }

    panic!("no OpenPGP card with identifier '{ident}'; `mind-the-gap pgp status` lists them")
}

/// Fingerprints of the three subkeys, in `SubkeyRole::ALL` order.
fn derived_fingerprints(cert: &Cert) -> Vec<(KeyType, [u8; 20])> {
    let policy = StandardPolicy::new();
    let valid = cert
        .with_policy(&policy, None)
        .expect("derived certificate is not valid under the standard policy");

    SubkeyRole::ALL
        .iter()
        .map(|role| {
            let kind = role.key_type();
            let subkey = valid
                .keys()
                .subkeys()
                .find(|key| key.key_flags().is_some_and(|flags| role.matches(&flags)))
                .unwrap_or_else(|| panic!("derived certificate has no {kind:?} subkey"));

            let fingerprint: [u8; 20] = subkey
                .key()
                .fingerprint()
                .as_bytes()
                .try_into()
                .expect("fingerprint is not 20 bytes");

            (kind, fingerprint)
        })
        .collect()
}

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

#[test]
fn provision_and_verify_card() {
    let subject = subject();
    let ident = target();

    // -- Provision -----------------------------------------------------------------------
    eprintln!("[1/5] deriving the certificate offline");
    let offline = subject
        .certify(CertificateKind::Full)
        .expect("offline certify failed");

    eprintln!("[2/5] uploading to card {ident} (no touch needed)");
    let uploaded = subject
        .upload(Some(ident.clone()))
        .expect("upload to card failed");

    assert_eq!(
        uploaded.fingerprint(),
        offline.fingerprint(),
        "upload and certify produced different primary keys",
    );

    // -- The crate's own check agrees ----------------------------------------------------
    eprintln!("[3/5] running check");
    subject
        .check(Some(ident.clone()))
        .expect("check disagreed with the card");

    // -- Independent verification --------------------------------------------------------
    //
    // `check` is the thing under test, so read the card directly rather than taking its word.
    eprintln!("[4/5] asserting card contents independently");
    let expected = derived_fingerprints(&offline);

    let mut card = open();
    let mut transaction = card.transaction().expect("cannot start card transaction");

    for (kind, want) in &expected {
        let on_card = transaction
            .fingerprint(*kind)
            .unwrap_or_else(|e| panic!("cannot read {kind:?} fingerprint: {e}"))
            .unwrap_or_else(|| panic!("no {kind:?} key on card"));

        assert_eq!(on_card.as_bytes(), want, "{kind:?} key on card is not the derived one",);
    }

    let cardholder = transaction
        .cardholder_name()
        .expect("cannot read cardholder name");
    assert_eq!(cardholder.trim(), TEST_NAME, "cardholder name was not set from the identity",);

    // The user pin we asked for has to be the one in force, and the factory default must not
    // be. Checked in this order so a card that accepts everything still fails.
    transaction
        .verify_user_pin(secrecy::SecretString::new(TEST_PIN.to_string()))
        .expect("card rejected the pin we provisioned it with");

    drop(transaction);
    drop(card);

    eprintln!("[5/5] gpg sees the card");
    gpg_sees_the_keys(&expected);
}

/// Confirm gpg itself finds the three keys, and clean up the scdaemon that costs.
///
/// Uses a throwaway GNUPGHOME so the caller's keyring and agent are untouched, and forces
/// scdaemon through PC/SC -- its internal CCID driver claims the USB interface directly and
/// fails with "No such device" whenever pcscd already holds the reader.
#[cfg(has_gpg)]
fn gpg_sees_the_keys(expected: &[(KeyType, [u8; 20])]) {
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

    let output = std::process::Command::new("gpg")
        .env("GNUPGHOME", &home)
        .arg("--card-status")
        .output()
        .expect("cannot run gpg");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "gpg --card-status failed:\n{}\n{}",
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
}

#[cfg(not(has_gpg))]
fn gpg_sees_the_keys(_expected: &[(KeyType, [u8; 20])]) {
    eprintln!("      skipped: gpg not found in PATH");
}
