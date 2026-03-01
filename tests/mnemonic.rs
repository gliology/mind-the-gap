use mind_the_gap::mnemonic::MnemonicSeed;
use mind_the_gap::seed::Seed256Derive;

fn phrase() -> &'static str {
    "abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon art"
}

#[test]
fn from_phrase_roundtrips() {
    let ms = MnemonicSeed::from_phrase(phrase()).unwrap();
    // Normalise whitespace: the crate may canonicalise spacing
    assert_eq!(ms.phrase().split_whitespace().collect::<Vec<_>>(),
               phrase().split_whitespace().collect::<Vec<_>>());
}

#[test]
fn seed_is_deterministic() {
    let ms1 = MnemonicSeed::from_phrase(phrase()).unwrap();
    let ms2 = MnemonicSeed::from_phrase(phrase()).unwrap();
    assert_eq!(ms1.seed(), ms2.seed());
}

#[test]
fn password_changes_seed() {
    let ms = MnemonicSeed::from_phrase(phrase()).unwrap();
    let ms_with_pw = MnemonicSeed::from_phrase(phrase()).unwrap().with_password("x");
    assert_ne!(ms.seed(), ms_with_pw.seed());
}

#[test]
fn password_is_deterministic() {
    let ms1 = MnemonicSeed::from_phrase(phrase()).unwrap().with_password("password");
    let ms2 = MnemonicSeed::from_phrase(phrase()).unwrap().with_password("password");
    assert_eq!(ms1.seed(), ms2.seed());
}

#[test]
fn derive_stable() {
    let ms = MnemonicSeed::from_phrase(phrase()).unwrap();
    let path = Some(b"test".as_slice());
    assert_eq!(ms.derive(path), ms.seed().derive(path));
}
