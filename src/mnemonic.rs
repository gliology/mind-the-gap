//! BIP39 mnemonic handling: from the phrase, plus an optional password, to the root seed.
//!
//! [`MnemonicSeed`] wraps `bip39::Mnemonic` to add the password and the argon2id step that
//! produces the root [`SecretSeed`]; everything it hands out is [`Zeroizing`], so no plain
//! copy of the phrase or the seed escapes it.

use crate::seed::{SecretSeed, Seed256Derive, argon2id_256};

use std::str::FromStr;

use anyhow::{Error, anyhow};

use bip39::{ErrorKind, Language, Mnemonic};

use unicode_normalization::UnicodeNormalization;

use zeroize::Zeroizing;

/// Simple wrapper to add password and derivation support to mnemonics
///
/// Deliberately not `Debug`: the mnemonic and password would both end up in the output, and a
/// stray `{:?}` must not be able to print them.
#[derive(Clone)]
pub struct MnemonicSeed {
    mnemonic: Mnemonic,
    password: Zeroizing<String>,
}

impl MnemonicSeed {
    /// Generate a fresh 24 word mnemonic straight from the operating system's entropy source.
    ///
    /// `getrandom` on purpose, rather than a userspace generator: the kernel CSPRNG is
    /// the sole source, with nothing reseeded or buffered in between. This mints new
    /// key material, so it stays an explicit call: only the `generate` ceremony and the
    /// interactive session reach it, never a command that merely lacked its seed.
    pub fn generate() -> Result<Self, Error> {
        let mut entropy = Zeroizing::new([0u8; 32]);
        getrandom::fill(entropy.as_mut())
            .map_err(|err| anyhow!("Operating system entropy source failed: {err}"))?;

        Ok(MnemonicSeed {
            mnemonic: Mnemonic::from_entropy(entropy.as_ref(), Language::English)?,
            password: String::new().into(),
        })
    }

    /// Create seed from mnemonic
    ///
    /// The errors name what is wrong and where, counting words from one, and never repeat
    /// a word: the phrase is the secret, and an error message ends up in scrollback.
    pub fn from_phrase(phrase: &str) -> Result<Self, Error> {
        let mnemonic =
            Mnemonic::from_phrase(phrase, Language::English).map_err(|err| match err {
                ErrorKind::InvalidWord(index) => {
                    anyhow!("Word {} of the phrase is not on the BIP-39 list", index + 1)
                }
                ErrorKind::InvalidChecksum => {
                    anyhow!("The phrase fails its checksum: a word is mistyped or out of order")
                }
                ErrorKind::InvalidWordLength(count) => {
                    anyhow!("A phrase has 12, 15, 18, 21 or 24 words, this one has {count}")
                }
                other => anyhow!("Not a valid phrase: {other}"),
            })?;
        Ok(MnemonicSeed { mnemonic, password: String::new().into() })
    }

    /// Protect seed with password
    ///
    /// The password is taken in Unicode NFKD, as BIP-39 takes its passphrase: `ä` typed as
    /// one code point or as `a` with a combining diaeresis, as keyboards and systems differ
    /// on, is the same password and derives the same keys.
    pub fn with_password(mut self, password: &str) -> Self {
        // Sized up front, so that no reallocation leaves a partial copy behind unwiped
        let length = password.nfkd().map(char::len_utf8).sum();
        self.password = Zeroizing::new(String::with_capacity(length));
        self.password.extend(password.nfkd());
        self
    }

    /// Return mnemonic phrase
    pub fn phrase(&self) -> Zeroizing<String> {
        Zeroizing::new(String::from(self.mnemonic.phrase()))
    }

    /// Return the individual words of the phrase
    pub fn words(&self) -> Zeroizing<Vec<String>> {
        Zeroizing::new(
            self.mnemonic
                .phrase()
                .split_whitespace()
                .map(String::from)
                .collect(),
        )
    }

    /// Entropy the phrase carries, in bits: 128 for 12 words up to 256 for 24
    ///
    /// The password is deliberately not counted, since nothing here can tell how much of
    /// it is guessable.
    pub fn entropy_bits(&self) -> u32 {
        u32::try_from(self.mnemonic.entropy().len() * 8).expect("at most 256 bits")
    }

    /// Process and return seed
    pub fn seed(&self) -> SecretSeed {
        argon2id_256(self.mnemonic.entropy(), Some(self.password.as_bytes()))
    }

    /// Process, derive and return seed
    pub fn derive(&self, path: Option<&[u8]>) -> SecretSeed {
        self.seed().derive(path)
    }
}

/// Support parsing from string e.g. in clap
impl FromStr for MnemonicSeed {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        MnemonicSeed::from_phrase(s)
    }
}

/// Whether a line looks like (part of) a seed phrase: three or more words, all from the
/// BIP-39 list
///
/// For the session, which must neither store nor echo a phrase typed at its prompt; a
/// command line never consists of list words alone.
pub fn looks_like_phrase(tokens: &[String]) -> bool {
    let words = Language::English.wordmap();
    tokens.len() >= 3 && tokens.iter().all(|token| words.get_bits(token).is_some())
}
