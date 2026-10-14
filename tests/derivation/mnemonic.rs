//! The phrase: parsing, the password and the seed it yields.

use mind_the_gap::mnemonic::MnemonicSeed;

fn phrase() -> &'static str {
    "abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon art"
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn seed(password: Option<&str>) -> String {
    let mut ms = MnemonicSeed::from_phrase(phrase()).unwrap();
    if let Some(password) = password {
        ms = ms.with_password(password);
    }
    hex(&*ms.seed())
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
/// The password is taken as exactly the UTF-8 bytes it was typed as, with no Unicode
/// normalisation: unlike the BIP-39 seed function, which normalises to NFKD first, `ä` typed
/// as one code point and as `a` with a combining diaeresis are two different passwords.
/// That is today's behaviour and frozen as such, since normalising now would move the keys
/// of everyone whose password is not plain ASCII.
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
            "ba01eae36961d954157bae7b71b234ab466f900a35ab38f5a16c49c009bca5bd",
        ),
    ] {
        assert_eq!(seed(password), expected, "seed moved for password {password:?}");
    }
}

/// The other half of the no-normalisation promise: the decomposed spelling of the same
/// password derives a different seed.
#[test]
fn password_is_not_normalised() {
    assert_ne!(
        seed(Some("p\u{e4}ssw\u{f6}rd \u{6771}\u{4eac}")),
        seed(Some("pa\u{308}sswo\u{308}rd \u{6771}\u{4eac}")),
    );
}

#[test]
fn password_changes_seed() {
    assert_ne!(seed(None), seed(Some("x")));
}
