//! The phrase: parsing, the password and the seed it yields.

use crate::hex::hex;

use mind_the_gap::mnemonic::MnemonicSeed;

fn phrase() -> &'static str {
    "abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon art"
}

fn seed(password: Option<&str>) -> String {
    let mut ms = MnemonicSeed::from_phrase(phrase()).unwrap();
    if let Some(password) = password {
        ms = ms.with_password(password);
    }
    hex(&**ms.seed())
}

#[test]
fn from_phrase_roundtrips() {
    let ms = MnemonicSeed::from_phrase(phrase()).unwrap();
    // Normalise whitespace: the crate may canonicalise spacing
    assert_eq!(
        ms.phrase().split_whitespace().collect::<Vec<_>>(),
        phrase().split_whitespace().collect::<Vec<_>>()
    );
}

/// The step from the phrase to the root seed is frozen with the rest of `mtg1`.
///
/// Every key descends from this seed, so a change here -- to the argon2 input, to where the
/// password goes, to how the phrase is parsed -- would move every key on every card while
/// the vectors of both backends, which start from a seed, kept passing.
///
/// The password is taken in NFKD, as the BIP-39 seed function takes its passphrase, so the
/// vector with a precomposed `ä` is also the vector of its decomposed spelling.
#[test]
fn seed_is_frozen() {
    for (password, expected) in [
        (None, "d3a32efe4a87fd72a92f7058d998d2d0127baf225514f2d70f69f9abf6b83d42"),
        (
            Some("correct horse battery staple"),
            "16fe6cfe8f739bef3ed4983045f818d656842bcb49777ee9482c1d0142376ec3",
        ),
        (
            Some("p\u{e4}ssw\u{f6}rd \u{6771}\u{4eac}"),
            "19a87dfba9f91b7e4564384e9eee53c778f0e99b38527e0de410c389de144b42",
        ),
    ] {
        assert_eq!(seed(password), expected, "seed moved for password {password:?}");
    }
}

/// One password however it was typed: precomposed and decomposed spellings, and the
/// compatibility forms NFKD folds, derive the same seed.
#[test]
fn password_is_normalised() {
    let composed = seed(Some("p\u{e4}ssw\u{f6}rd \u{6771}\u{4eac}"));
    assert_eq!(composed, seed(Some("pa\u{308}sswo\u{308}rd \u{6771}\u{4eac}")));
    // A full-width letter folds to its ASCII form under NFKD
    assert_eq!(seed(Some("\u{ff58}")), seed(Some("x")));
}

#[test]
fn password_changes_seed() {
    assert_ne!(seed(None), seed(Some("x")));
}
