use crate::{SEED256_DERIVATION_ID, Seed256};

use anyhow::Error;

use bip39::{Language, Mnemonic, MnemonicType};

use sha2::Sha256;
use hmac::Hmac;
use pbkdf2::pbkdf2;

use zeroize::Zeroize;

/// Simple helper to generate a fixed length blake2b output
fn blake2b_256(input: &[u8]) -> [u8; 32] {
    let mut res = [0u8; 32];
    res.copy_from_slice(blake2_rfc::blake2b::blake2b(32, &[], input).as_bytes());
    res
}

/// Simple wrapper to add password and derivation support to mnemonics
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct MnemonicSeed {
    mnemonic: Mnemonic,
    password: String,
}

impl MnemonicSeed {
    /// Create new random seed
    pub fn new() -> Self {
        MnemonicSeed {
            mnemonic: Mnemonic::new(MnemonicType::Words24, Language::English),
            password: String::new(),
        }
    }

    /// Create seed from mnemonic
    pub fn from_phrase(phrase: &str) -> Result<Self, Error> {
        Ok(MnemonicSeed {
            mnemonic: Mnemonic::from_phrase(phrase, Language::English)?,
            password: String::new(),
        })
    }

    /// Protect seed with password
    pub fn with_password(mut self, password: &str) -> Self {
        self.password = String::from(password);
        self
    }

    /// Return mnemnonic phrase
    pub fn phrase(&self) -> String {
        String::from(self.mnemonic.phrase())
    }
}

impl Seed256 for MnemonicSeed {
    /// Process and return seed
    fn seed(&self, path: Option<&str>) -> [u8; 32] {
        // Run seed through pbkdf2 and optionally apply password
        let mut salt = String::with_capacity(8 + self.password.len());
        salt.push_str("mnemonic");
        salt.push_str(&self.password);

        let mut seed = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(self.mnemonic.entropy(), salt.as_bytes(), 2048, &mut seed);

        salt.zeroize();

        // Apply optional hard derivation
        if let Some(path) = path {
            blake2b_256(&[
                SEED256_DERIVATION_ID,
                &seed,
                &blake2b_256(path.as_bytes())
            ].concat())
        } else {
            seed
        }
    }
}
