use mind_the_gap::seed::{argon2id_256, Seed256, Seed256Derive};

use base64::prelude::BASE64_STANDARD_NO_PAD;
use base64::Engine;

const SEED: Seed256 = [42u8; 32];
const DEFAULT_INPUT: &[u8] = b"Mind the gap, bro!";

#[test]
fn derive_is_deterministic() {
    assert_eq!(SEED.derive(Some(b"path")), SEED.derive(Some(b"path")));
}

#[test]
fn derive_differs_by_path() {
    assert_ne!(SEED.derive(Some(b"path-a")), SEED.derive(Some(b"path-b")));
}

#[test]
fn derive_none_path_differs_from_some() {
    // None (no path) and Some with a non-empty path produce different results
    assert_ne!(SEED.derive(None), SEED.derive(Some(b"nonempty")));
}

#[test]
fn derive_chains() {
    // derive(a).derive(b) is distinct from derive(b) alone
    assert_ne!(
        SEED.derive(Some(b"a")).derive(Some(b"b")),
        SEED.derive(Some(b"b"))
    );
}

#[test]
fn base64_round_trips() {
    let path = Some(b"test".as_slice());
    let derived = SEED.derive(path);
    let encoded = SEED.base64(path);
    let decoded = BASE64_STANDARD_NO_PAD.decode(&encoded).unwrap();
    assert_eq!(decoded.as_slice(), derived.as_ref());
}

#[test]
fn argon_with_salt() {
    let without_salt = argon2id_256(DEFAULT_INPUT, None);
    let with_salt = argon2id_256(DEFAULT_INPUT, Some(b"test"));
    // Adding a salt changes the output
    assert_ne!(without_salt, with_salt);
    // And the result is deterministic
    assert_eq!(with_salt, argon2id_256(DEFAULT_INPUT, Some(b"test")));
}
