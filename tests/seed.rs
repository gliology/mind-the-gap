use mind_the_gap::seed::{
    Algorithm, Seed256, Seed256Derive, algorithm_label, argon2id_256, derive_p384_scalar, label,
};

use base64::Engine;
use base64::prelude::BASE64_STANDARD_NO_PAD;

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
    assert_ne!(SEED.derive(Some(b"a")).derive(Some(b"b")), SEED.derive(Some(b"b")));
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

/// The algorithm is a label segment of its own, behind a second colon.
#[test]
fn algorithm_label_has_the_segment_on_its_own() {
    assert_eq!(algorithm_label("signature", "p256"), b"key:signature:p256");
    assert_eq!(algorithm_label("key-management", "x25519"), b"key:key-management:x25519");

    // An algorithm-qualified key is a different key from the bare name, and from each other
    let seed: Seed256 = [7u8; 32];
    let bare = seed.derive(Some(&label("key", "signature")));
    let p256 = seed.algorithm_key("signature", Algorithm::P256.signing_segment());
    let ed25519 = seed.algorithm_key("signature", Algorithm::Curve25519.signing_segment());
    assert_ne!(*bare, *p256);
    assert_ne!(*bare, *ed25519);
    assert_ne!(*p256, *ed25519);
}

/// Key agreement keys get their own segment name on Curve25519, signing keys theirs; P-256
/// serves both roles under one name.
#[test]
fn curve_segments_name_the_algorithm() {
    assert_eq!(Algorithm::P256.signing_segment(), "p256");
    assert_eq!(Algorithm::P256.agreement_segment(), "p256");
    assert_eq!(Algorithm::P384.signing_segment(), "p384");
    assert_eq!(Algorithm::P384.agreement_segment(), "p384");
    assert_eq!(Algorithm::Curve25519.signing_segment(), "ed25519");
    assert_eq!(Algorithm::Curve25519.agreement_segment(), "x25519");
}

/// A P-384 scalar is 48 bytes, reproducible, and laid out exactly as the derivation chapter
/// documents: the labelled argon2id output, then 16 bytes of its `key:p384-extend` child.
#[test]
fn p384_scalar_is_the_documented_construction() {
    let path = algorithm_label("signature", "p384");
    let scalar = derive_p384_scalar(&SEED, Some(&path)).unwrap();

    assert_eq!(scalar.len(), 48);
    assert_eq!(*scalar, *derive_p384_scalar(&SEED, Some(&path)).unwrap());

    let first = SEED.derive(Some(&path));
    let second = first.key("p384-extend");
    assert_eq!(&scalar[..32], &first[..]);
    assert_eq!(&scalar[32..], &second[..16]);

    // A valid key, and a different one under a different label
    assert!(p384::SecretKey::from_slice(&scalar).is_ok());
    let other =
        derive_p384_scalar(&SEED, Some(&algorithm_label("authentication", "p384"))).unwrap();
    assert_ne!(*scalar, *other);
}
