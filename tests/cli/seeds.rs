//! The seeds and what they derive: a key seed apart, the password, the algorithm and how strong
//! a phrase is for it.

use crate::{OTHER_PHRASE, TEST_PHRASE, WHO, bin, root_pem, seeded, stderr};

/// A key seed apart from the seed derives another identity, and the seed still the card's.
#[test]
fn a_key_seed_apart_derives_another_identity() {
    let own = root_pem(bin(), &["-n", "Alice"]);
    let mut cmd = bin();
    cmd.env("MIND_THE_KEY_SEED", OTHER_PHRASE);
    let team = root_pem(cmd, &["-n", "Alice"]);
    assert_ne!(own, team, "the key seed changed nothing");

    let mut cmd = bin();
    cmd.env("MIND_THE_KEY_SEED", TEST_PHRASE);
    assert_eq!(own, root_pem(cmd, &["-n", "Alice"]), "the same phrase as key seed differs");
}

/// The derivation password changes every derived key.
#[test]
fn password_changes_derivation() {
    let plain = root_pem(bin(), &["-n", "Alice"]);
    let mut cmd = bin();
    cmd.args(["-p", "hunter2"]);
    assert_ne!(plain, root_pem(cmd, &["-n", "Alice"]), "the password changed nothing");
}

/// `--algorithm` changes the derived keys, from the line and from the environment.
#[test]
fn algorithm_selects_the_keys() {
    let default = root_pem(bin(), &["-n", "Alice"]);
    let p256 = root_pem(bin(), &["-n", "Alice", "--algorithm", "p256"]);
    let ed25519 = root_pem(bin(), &["-n", "Alice", "--algorithm", "curve25519"]);
    let mut cmd = bin();
    cmd.env("MIND_THE_ALGORITHM", "curve25519");
    let from_env = root_pem(cmd, &["-n", "Alice"]);

    assert_eq!(default, p256, "PIV does not default to P-256");
    assert_ne!(p256, ed25519, "--algorithm curve25519 changed nothing");
    assert_eq!(ed25519, from_env, "MIND_THE_ALGORITHM is not honoured");

    let pgp = |args: &[&str]| {
        let out = seeded(&[&["publish", "--app", "pgp", "--to", "-"][..], &WHO, args].concat());
        assert!(out.status.success(), "pgp publish failed:\n{}", stderr(&out));
        out.stdout
    };
    assert_eq!(pgp(&[]), pgp(&["--algorithm", "curve25519"]), "OpenPGP does not default to 25519");
    assert_ne!(pgp(&[]), pgp(&["--algorithm", "p256"]), "--algorithm p256 changed nothing");

    // The legacy scheme predates the algorithm segment and refuses the other algorithm
    let out = seeded(
        &[
            &["publish", "--app", "pgp", "--legacy", "--algorithm", "p256"][..],
            &WHO,
        ]
        .concat(),
    );
    let err = stderr(&out);
    assert!(!out.status.success(), "--legacy accepted --algorithm p256");
    assert!(err.contains("--legacy"), "the refusal does not name --legacy:\n{err}");

    // An empty subkey id is no subkey id to the legacy scheme, so it would quietly address
    // the card without one
    let out = seeded(
        &[
            &["publish", "--app", "pgp", "--legacy", "-k", "", "--to", "-"][..],
            &WHO,
        ]
        .concat(),
    );
    assert!(!out.status.success(), "--legacy accepted an empty subkey id");
    assert!(stderr(&out).contains("empty subkey id"), "unexpected refusal:\n{}", stderr(&out));
}

/// Asking for more strength than the phrase carries warns, and only then: RSA-4096 rates
/// about 152 bits, which a 24 word phrase covers and a 12 word one does not.
#[test]
fn weak_phrase_warns_for_strong_algorithms() {
    const SHORT_PHRASE: &str = "abandon abandon abandon abandon abandon abandon \
                                abandon abandon abandon abandon abandon about";
    let run = |phrase: &str, algorithm: &str| {
        let out = bin()
            .args([
                "-s", phrase, "publish", "--app", "piv", "--part", "identity", "--to", "-",
            ])
            .args(["-n", "Alice", "--algorithm", algorithm])
            .output()
            .unwrap();
        assert!(out.status.success(), "publish failed: {:?}", out);
        stderr(&out)
    };

    let weak = run(SHORT_PHRASE, "rsa4096");
    assert!(weak.contains("rsa4096 keys aim at about 152 bits"), "no warning:\n{weak}");
    assert!(weak.contains("128 bits of entropy"), "the warning lacks the entropy:\n{weak}");

    for (phrase, algorithm) in [(TEST_PHRASE, "rsa4096"), (SHORT_PHRASE, "rsa3072")] {
        let quiet = run(phrase, algorithm);
        assert!(!quiet.contains("aim at about"), "{algorithm} warned needlessly:\n{quiet}");
    }
}
