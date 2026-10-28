//! The base layer: argon2id, the seed tree, the phrase and RSA key generation.

mod argon;
#[path = "../common/hex.rs"]
mod hex;
mod mnemonic;
mod rsa_keys;
mod seed;

/// The input the argon2id vector starts from
const DEFAULT_INPUT: &[u8] = b"Mind the gap, bro!";
