//! The base layer: argon2id, the seed tree, the phrase and RSA key generation.

mod argon;
mod mnemonic;
mod rsa_keys;
mod seed;

/// The input both the argon2id vector and the seed tests start from
const DEFAULT_INPUT: &[u8] = b"Mind the gap, bro!";
