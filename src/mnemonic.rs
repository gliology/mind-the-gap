//! BIP39 mnemonic handling: from the phrase, plus an optional password, to the root seed.
//!
//! [`MnemonicSeed`] wraps `bip39::Mnemonic` to add the password and the argon2id step that
//! produces the root [`Seed256`]; everything it hands out is [`Zeroizing`], so no plain
//! copy of the phrase or the seed escapes it.

use crate::seed::{Seed256, Seed256Derive, argon2id_256};

use std::str::FromStr;

use anyhow::{Error, anyhow};

use bip39::{Language, Mnemonic};

use rand_core::{OsRng, TryRngCore};

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
    /// `OsRng` on purpose, rather than a userspace generator: the kernel CSPRNG is the sole
    /// source, with nothing reseeded or buffered in between. This mints new key material, so
    /// it stays an explicit call -- commands that need a seed prompt for one instead of
    /// quietly calling this.
    pub fn generate() -> Result<Self, Error> {
        let mut entropy = Zeroizing::new([0u8; 32]);
        OsRng
            .try_fill_bytes(entropy.as_mut())
            .map_err(|err| anyhow!("Operating system entropy source failed: {err}"))?;

        Ok(MnemonicSeed {
            mnemonic: Mnemonic::from_entropy(entropy.as_ref(), Language::English)?,
            password: String::new().into(),
        })
    }

    /// Create seed from mnemonic
    pub fn from_phrase(phrase: &str) -> Result<Self, Error> {
        Ok(MnemonicSeed {
            mnemonic: Mnemonic::from_phrase(phrase, Language::English)?,
            password: String::new().into(),
        })
    }

    /// Protect seed with password
    pub fn with_password(mut self, password: &str) -> Self {
        self.password = String::from(password).into();
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

    /// Process and return seed
    pub fn seed(&self) -> Zeroizing<Seed256> {
        argon2id_256(self.mnemonic.entropy(), Some(self.password.as_bytes()))
    }

    /// Process, derive and return seed
    pub fn derive(&self, path: Option<&[u8]>) -> Zeroizing<Seed256> {
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
