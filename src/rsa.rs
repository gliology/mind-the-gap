//! Deterministic RSA keys: two primes drawn from a SHAKE256 stream over a derived seed.
//!
//! An RSA key cannot be a 256-bit string the way an elliptic curve key is, so the derived
//! seed is stretched instead. [`derive_key`] reads candidates from
//! `SHAKE256(RSA_STREAM_CONTEXT || bits || seed)` and keeps the first two that pass the
//! checks of FIPS 186-5 appendix A.1.3, the generation of probable primes. The seed caps the
//! strength at 256 bits, comfortably above any modulus here (about 112 bits for RSA-2048,
//! 128 for 3072, 152 for 4096).
//!
//! Like the rest of the derivation, this procedure is a frozen constant of `mtg1`: every
//! byte read from the stream and every acceptance rule decides which key comes out, so the
//! golden vectors pin it. Nothing else is frozen: primality is a property of the number,
//! not of the test, so any correct primality test agrees with the one used here and the
//! key can be recomputed without this crate's dependencies.

use anyhow::{Result, bail};

use crypto_bigint::{BoxedUint, Limb, NonZero};
use crypto_primes::{Flavor, is_prime};

use rsa::RsaPrivateKey;
use rsa::traits::PublicKeyParts;

use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use zeroize::Zeroizing;

use crate::seed::Seed256;

/// Domain separation for the prime stream, in the spirit of the argon2 context
const RSA_STREAM_CONTEXT: &[u8] = b"MINDTHEGAPRSA";

/// The public exponent of every derived key: the only one the Yubico clients import
pub const PUBLIC_EXPONENT: u32 = 65537;

/// Odd primes below 1000, multiplied into words for cheap trial division
///
/// Pure speed: a candidate with a small factor is composite, so rejecting it early changes
/// no outcome, it only spares the full primality test.
const SMALL_PRIME_PRODUCTS: &[u64] = &small_prime_products();

const fn small_prime_products() -> [u64; 32] {
    let mut products = [1u64; 32];
    let mut slot = 0;
    let mut n = 3u64;
    while n < 1000 {
        let mut d = 3;
        let mut prime = true;
        while d * d <= n {
            if n.is_multiple_of(d) {
                prime = false;
                break;
            }
            d += 2;
        }
        if prime {
            if products[slot].checked_mul(n).is_none() {
                slot += 1;
            }
            products[slot] *= n;
        }
        n += 2;
    }
    products
}

/// Whether `candidate` has an odd prime factor below 1000
fn has_small_factor(candidate: &BoxedUint) -> bool {
    SMALL_PRIME_PRODUCTS
        .iter()
        .filter(|&&product| product > 1)
        .any(|&product| {
            let product = NonZero::new(Limb(product)).expect("products are non-zero");
            let rest = candidate.rem_limb(product).0;
            // A common factor with the product means a small prime divides the candidate
            gcd(rest, product.get().0) != 1
        })
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// Derive the RSA key of `bits` modulus bits that `seed` stands for
///
/// The frozen procedure, for a modulus of `bits` bits:
///
/// 1. The stream is SHAKE256 over `RSA_STREAM_CONTEXT`, `bits` as a big-endian `u16`, and
///    the 32 seed bytes, read front to back without gaps.
/// 2. A candidate is the next `bits / 16` bytes, big-endian, with its two top bits and its
///    lowest bit set. The top bits put every candidate above `√2 · 2^(bits/2 - 1)`, so the
///    modulus has exactly `bits` bits; the low bit makes it odd.
/// 3. `p` is the first candidate that is prime and for which `p - 1` is not a multiple of
///    65537 (the public exponent, itself prime, so this is `gcd(p - 1, e) = 1`).
/// 4. `q` is the first later candidate with the same properties that also lies more than
///    `2^(bits/2 - 100)` away from `p`.
/// 5. FIPS 186-5 gives up after `5 · bits` candidates for `p` and `10 · bits` for `q`; so
///    does this, as an error that no real seed is expected to reach.
///
/// The key is `(p, q)` in that order with `e = 65537`; the private exponent is whatever the
/// `rsa` crate computes from them, which changes nothing that is published: public keys and
/// fingerprints carry only `n` and `e`, and PKCS#1 v1.5 signatures are the same under any
/// valid `d`.
pub fn derive_key(seed: &Seed256, bits: u32) -> Result<RsaPrivateKey> {
    if !matches!(bits, 2048 | 3072 | 4096) {
        bail!("RSA keys are derived with 2048, 3072 or 4096 bits, not {bits}");
    }

    let bits_u16 = u16::try_from(bits).expect("checked above");
    let mut stream = Shake256::default();
    stream.update(RSA_STREAM_CONTEXT);
    stream.update(&bits_u16.to_be_bytes());
    stream.update(seed);
    let mut stream = stream.finalize_xof();

    let half = bits / 2;
    let p = next_prime(&mut stream, half, 5 * bits, |_| true)
        .ok_or_else(|| anyhow::anyhow!("No RSA prime p within {} candidates", 5 * bits))?;

    let min_distance = BoxedUint::one_with_precision(half)
        .shl_vartime(half - 100)
        .expect("the shift stays below the precision");
    let q = next_prime(&mut stream, half, 10 * bits, |q| {
        let distance = if q.cmp_vartime(&p).is_gt() {
            q.wrapping_sub(&p)
        } else {
            p.wrapping_sub(q)
        };
        distance.cmp_vartime(&min_distance).is_gt()
    })
    .ok_or_else(|| anyhow::anyhow!("No RSA prime q within {} candidates", 10 * bits))?;

    let key = RsaPrivateKey::from_p_q(p, q, BoxedUint::from(PUBLIC_EXPONENT))?;
    if key.as_public_key().n().bits() != bits {
        bail!("Derived an RSA modulus of the wrong size");
    }
    Ok(key)
}

/// Read candidates of `bits` bits from `stream` until one is a suitable prime
fn next_prime(
    stream: &mut impl XofReader,
    bits: u32,
    attempts: u32,
    accept: impl Fn(&BoxedUint) -> bool,
) -> Option<BoxedUint> {
    let exponent = NonZero::new(Limb(PUBLIC_EXPONENT.into())).expect("65537 is non-zero");
    let mut bytes = Zeroizing::new(vec![0u8; bits as usize / 8]);

    for _ in 0..attempts {
        stream.read(&mut bytes);
        bytes[0] |= 0xc0;
        *bytes.last_mut().expect("candidates are not empty") |= 1;

        let candidate = BoxedUint::from_be_slice(&bytes, bits).expect("bytes fit the precision");
        if has_small_factor(&candidate) {
            continue;
        }
        // The candidate is odd, so `candidate - 1` leaves remainder `r - 1` where `r` is the
        // candidate's own, and is a multiple of 65537 exactly when `r` is 1
        if candidate.rem_limb(exponent) == Limb::ONE {
            continue;
        }
        if is_prime(Flavor::Any, &candidate) && accept(&candidate) {
            return Some(candidate);
        }
    }

    None
}
