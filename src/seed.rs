use argon2::{Algorithm, Argon2, Params, Version};

use base64::prelude::BASE64_STANDARD_NO_PAD;
use base64::Engine;

/// Type alias for derivation path with empty default that just used derivation id
pub type MaybePath<'a> = Option<&'a [u8]>;

/// Type alias for raw seeds
pub type Seed256 = [u8; 32];

/// Constant to be used in all 256bit seed derivations
const DERIVATION_CONTEXT: &[u8] = b"MINDTHEGAP256HDKD";

/// Simple wrapper around argon2 crate to hash byte inputs
pub fn argon2id_256(input: &[u8], salt: Option<&[u8]>) -> Seed256 {
    // Default setting for memory-constrained environments
    let params = Params::new(64 * 1024, 3, 1, None).unwrap();

    // Prepare salt value
    let salt = &[DERIVATION_CONTEXT, salt.unwrap_or(b"")].concat();

    // Use latest hybrid variant
    let mut hash = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(input, salt, &mut hash)
        .expect("Parameters are valid");
    hash
}

/// Simple wrapper around base64 crate to turn bytes into ascii strings
pub(crate) fn base64_encode(input: &[u8]) -> String {
    BASE64_STANDARD_NO_PAD.encode(input)
}

// Abstract derivation step ...
pub trait Seed256Derive {
    fn derive(&self, path: Option<&[u8]>) -> Seed256;
}

// ... and implement it using argon2
impl Seed256Derive for Seed256 {
    fn derive(&self, path: Option<&[u8]>) -> Seed256 {
        argon2id_256(self, path)
    }
}
