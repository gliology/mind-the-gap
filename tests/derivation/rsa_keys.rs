//! RSA keys from two primes read off a SHAKE256 stream.

use crate::hex::hex;

use mind_the_gap::rsa::{PUBLIC_EXPONENT, derive_key};
use mind_the_gap::seed::Seed256;

use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use sha2::{Digest, Sha256};

const SEED: Seed256 = [1; 32];

/// SHA-256 of the big-endian modulus for [`SEED`], per size
///
/// Computed independently from the description in `src/rsa.rs` with nothing but Python's
/// standard library (`hashlib.shake_256` and Miller-Rabin), so these pin the procedure
/// rather than this crate's arithmetic.
const MODULI: [(u32, &str); 3] = [
    (2048, "6790659ecced64f17a887deb100961d4c1359818f199e177a826e29d6ea3bc7e"),
    (3072, "38e7eb329f99abededdfa93f17214a76c1e085f2bfb0e017e5565428a693819b"),
    (4096, "481549a77b330ea3aa9ecbf84f5b6a4193970c47ffcd7dbee2a3a56a51d62e04"),
];

/// The derivation is frozen: the same seed gives the same modulus, forever.
#[test]
fn rsa_derivation_is_frozen() {
    for (bits, expected) in MODULI {
        let key = derive_key(&SEED, bits).unwrap();
        let n = key.n().to_be_bytes();
        assert_eq!(n.len(), bits as usize / 8);
        assert_eq!(hex(&Sha256::digest(&n)), expected, "RSA-{bits} modulus moved");
    }
}

/// Every derived key meets the FIPS 186-5 shape the procedure promises.
#[test]
fn rsa_keys_have_the_promised_shape() {
    let key = derive_key(&SEED, 2048).unwrap();
    let e = key.e().to_be_bytes();
    assert_eq!(u32::from_be_bytes(e[e.len() - 4..].try_into().unwrap()), PUBLIC_EXPONENT);

    let [p, q] = key.primes() else {
        panic!("two primes expected")
    };
    assert_eq!(p.bits(), 1024);
    assert_eq!(q.bits(), 1024);
    // Both have their two top bits set, which is what puts n at exactly 2048 bits
    assert!(p.to_be_bytes()[0] >= 0xc0 && q.to_be_bytes()[0] >= 0xc0);
    key.validate().unwrap();
}

/// Different seeds and different sizes give unrelated keys.
#[test]
fn rsa_keys_are_separated() {
    let a = derive_key(&SEED, 2048).unwrap();
    let b = derive_key(&[2; 32], 2048).unwrap();
    assert_ne!(a.n(), b.n());
}

/// Only the three sizes the cards take are derived.
#[test]
fn rsa_sizes_are_limited() {
    assert!(derive_key(&SEED, 1024).is_err());
    assert!(derive_key(&SEED, 2047).is_err());
}
