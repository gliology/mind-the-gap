use crate::seed::{argon2id_256, Seed256, Seed256Derive};

use std::str::FromStr;

use anyhow::Error;

use bip39::{Language, Mnemonic, MnemonicType};

use zeroize::Zeroizing;

/// Simple wrapper to add password and derivation support to mnemonics
#[derive(Clone, Debug)]
pub struct MnemonicSeed {
    mnemonic: Mnemonic,
    password: Zeroizing<String>,
    source: MnemonicSource,
}

/// Enum to track source of mnemonic seed
#[derive(Copy, Clone, Debug)]
pub enum MnemonicSource {
    Random,
    Phrase,
}

impl MnemonicSeed {
    /// Create new random seed
    pub fn new() -> Self {
        MnemonicSeed {
            mnemonic: Mnemonic::new(MnemonicType::Words24, Language::English),
            password: String::new().into(),
            source: MnemonicSource::Random,
        }
    }

    /// Create seed from mnemonic
    pub fn from_phrase(phrase: &str) -> Result<Self, Error> {
        Ok(MnemonicSeed {
            mnemonic: Mnemonic::from_phrase(phrase, Language::English)?,
            password: String::new().into(),
            source: MnemonicSource::Phrase,
        })
    }

    /// Protect seed with password
    pub fn with_password(mut self, password: &str) -> Self {
        self.password = String::from(password).into();
        self
    }

    /// Return mnemnonic phrase
    pub fn phrase(&self) -> String {
        String::from(self.mnemonic.phrase())
    }

    /// Process and return seed
    pub fn seed(&self) -> Seed256 {
        argon2id_256(self.mnemonic.entropy(), Some(self.password.as_bytes()))
    }

    /// Process, derive and return seed
    pub fn derive(&self, path: Option<&[u8]>) -> Seed256 {
        self.seed().derive(path)
    }

    /// Return source of the mnemonic
    pub fn source(&self) -> MnemonicSource {
        self.source
    }
}

/// Support parsing from string e.g. in clap
impl FromStr for MnemonicSeed {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        MnemonicSeed::from_phrase(s)
    }
}
