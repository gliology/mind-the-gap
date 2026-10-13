//! The derivation layer: argon2id and the labelled seed tree.
//!
//! Every derivation funnels through [`argon2id_256`]; the [`Seed256Derive`] trait spells the
//! step out as a label grammar (`app:`, `sub:`, `key:`, `id:`, `pin:`) whose prefixes keep
//! outputs of different kinds apart by construction. Results come back wrapped in
//! [`Zeroizing`] so every copy wipes itself. The tree and its rationale are documented in
//! the derivation chapter, <https://gliology.github.io/mind-the-gap/derivation.html>.

use argon2::{Argon2, Params, Version};

use anyhow::{Result, bail};

use base64::Engine;
use base64::prelude::BASE64_STANDARD_NO_PAD;

use zeroize::Zeroizing;

/// Type alias for raw seeds
pub type Seed256 = [u8; 32];

/// Constant to be used in all 256bit seed derivations
const DERIVATION_CONTEXT: &[u8] = b"MINDTHEGAP256HDKD";

/// Simple wrapper around argon2 crate to hash byte inputs
///
/// Two deliberate, load-bearing choices live here. There is no random salt: determinism
/// is the product, the same seed must yield the same keys forever, and uniqueness comes
/// from the 256-bit entropy input instead. And the optional user secret arrives in the
/// *salt* position, appended to the context, not mixed into the password input: argon2
/// folds password and salt into its initial state symmetrically, the 17-byte context
/// clears the 8-byte salt minimum, and moving it would silently re-derive every key.
///
/// The parameters are frozen constants of the scheme named by [`SCHEME_VERSION`], the
/// same way the label grammar is: changing any of them moves every key and therefore
/// ships as a new major, never as a tuning tweak.
pub fn argon2id_256(input: &[u8], salt: Option<&[u8]>) -> Zeroizing<Seed256> {
    // Chosen for memory-constrained environments; comfortably above the OWASP floor,
    // and part of the frozen mtg1 scheme (see above)
    let params = Params::new(64 * 1024, 3, 1, None).unwrap();

    // Prepare salt value
    let salt = &[DERIVATION_CONTEXT, salt.unwrap_or(b"")].concat();

    // Use latest hybrid variant
    let mut hash = Zeroizing::new([0u8; 32]);
    Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(input, salt, hash.as_mut())
        .expect("Parameters are valid");
    hash
}

/// Simple wrapper around base64 crate to turn bytes into ascii strings
fn base64_encode(input: &[u8]) -> String {
    BASE64_STANDARD_NO_PAD.encode(input)
}

/// Version tag stamped on the identifiers this crate publishes
///
/// Deliberately *not* part of any derivation label. Relabelling already moves every key, so a
/// version in the path would separate nothing that the scheme change had not separated
/// already, and it would cost an argon2 pass to carry. What it is for is the other direction:
/// an identifier that names its own scheme can be read off a card, or out of a certificate,
/// and tell you which version produced it.
///
/// The frozen OpenPGP scheme is `mtg0` by convention only. It stamps nothing, because it
/// predates the marker and its output is fixed.
///
/// The crate's major version tracks this constant: 0.x derived under `mtg0`, 1.x derives
/// under `mtg1`. Changing the scheme moves every key, so it always ships as a new major.
pub const SCHEME_VERSION: &str = "mtg1";

/// Stamp the scheme version on a published identifier
pub fn stamp(value: &str) -> String {
    format!("{SCHEME_VERSION}:{value}")
}

/// Subtree holding everything derived for one application
pub const PREFIX_APP: &str = "app";

/// Subtree scoped to a user-supplied subkey id
///
/// Its own prefix because the id is the only part of a label a user controls. Sharing a
/// namespace with the fixed labels would let an id collide with one of them, and at the level
/// the subkey id sits at, that neighbour is the primary key.
pub const PREFIX_SUB: &str = "sub";

/// 256 bits of raw key material
pub const PREFIX_KEY: &str = "key";

/// Identifier material, truncated by the caller to the width its format allows
pub const PREFIX_ID: &str = "id";

/// An ASCII pin
pub const PREFIX_PIN: &str = "pin";

/// Compose a derivation label from its prefix and a lowercase hyphenated name
///
/// For the fixed labels this crate defines. The grammar is asserted rather than enforced,
/// since every caller passes a literal -- a violation is a bug here, not bad input.
pub fn label(prefix: &str, name: &str) -> Vec<u8> {
    debug_assert!(
        !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
        "derivation labels are lowercase and hyphenated: {name:?}",
    );
    format!("{prefix}:{name}").into_bytes()
}

/// Compose the label for key material bound to one algorithm: `key:<name>:<segment>`
///
/// The algorithm is a segment of its own rather than part of the name so that one name can
/// never hand the same bytes to two algorithms: `key:signature:p256` and
/// `key:signature:ed25519` are different keys, and a card switched from one algorithm to the
/// other shares no secret with its former self.
pub fn algorithm_label(name: &str, segment: &str) -> Vec<u8> {
    debug_assert!(
        !segment.is_empty()
            && segment
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
        "derivation labels are lowercase and hyphenated: {segment:?}",
    );
    let mut label = label(PREFIX_KEY, name);
    label.push(b':');
    label.extend_from_slice(segment.as_bytes());
    label
}

/// Compose the label for the subtree scoped to a user-supplied subkey id
///
/// Deliberately not [`label`]: the id is arbitrary text a user chose, so it is neither checked
/// against the label grammar nor required to be valid UTF-8 beyond what the CLI already
/// accepts. The prefix is what matters: no fixed label begins with it, so an id can never
/// collide with one however exotic it is.
///
/// No id at all derives under the bare prefix, with no separator; a supplied id, the
/// empty string included, derives under `sub:<id>`. The two must not coincide: they
/// produce different certificates, and keys that differ from certificates that agree
/// is exactly the confusion the label grammar exists to rule out. `--shared` keys and
/// a card without a subkey id both take the `None` side, so they keep agreeing.
pub fn sub_label(id: Option<&str>) -> Vec<u8> {
    match id {
        Some(id) => [PREFIX_SUB.as_bytes(), b":", id.as_bytes()].concat(),
        None => PREFIX_SUB.as_bytes().to_vec(),
    }
}

/// Abstract derivation step
///
/// Every label is `<prefix>:<name>`, and the prefix says what comes out: `key` is raw key
/// material, `id` is an identifier, `pin` is something a person types. `app` and `sub` name
/// subtrees rather than outputs. Keeping the shape in the label means two derivations can
/// never agree by accident just because their names happen to match across use cases.
pub trait Seed256Derive {
    /// Derive a child seed under the given path
    fn derive(&self, path: Option<&[u8]>) -> Zeroizing<Seed256>;

    /// Derive a child seed and encode it as base64
    fn base64(&self, path: Option<&[u8]>) -> Zeroizing<String> {
        Zeroizing::new(base64_encode(&self.derive(path)[..]))
    }

    /// Derive an application subtree, which is itself only ever used to derive further
    fn app(&self, name: &str) -> Zeroizing<Seed256> {
        self.derive(Some(&label(PREFIX_APP, name)))
    }

    /// Derive the subtree scoped to a user-supplied subkey id
    fn sub(&self, id: Option<&str>) -> Zeroizing<Seed256> {
        self.derive(Some(&sub_label(id)))
    }

    /// Derive 256 bits of raw key material
    fn key(&self, name: &str) -> Zeroizing<Seed256> {
        self.derive(Some(&label(PREFIX_KEY, name)))
    }

    /// Derive 256 bits of key material for one algorithm, see [`algorithm_label`]
    fn algorithm_key(&self, name: &str, segment: &str) -> Zeroizing<Seed256> {
        self.derive(Some(&algorithm_label(name, segment)))
    }

    /// Derive identifier material, truncated to the width the format allows
    ///
    /// Separate from [`Seed256Derive::key`] so that an identifier, which is published, can
    /// never be the same bytes as a key that merely shares its name.
    fn id(&self, name: &str, bytes: usize) -> Vec<u8> {
        self.derive(Some(&label(PREFIX_ID, name)))[..bytes].to_vec()
    }

    /// Derive an ASCII pin
    fn pin(&self, name: &str) -> Zeroizing<String> {
        Zeroizing::new(base64_encode(&self.derive(Some(&label(PREFIX_PIN, name)))[..]))
    }
}

// ... and implement it using argon2
impl Seed256Derive for Seed256 {
    fn derive(&self, path: Option<&[u8]>) -> Zeroizing<Seed256> {
        argon2id_256(self, path)
    }
}

/// The algorithm a backend derives its asymmetric keys with
///
/// Scheme vocabulary rather than a backend detail: the algorithm is a segment of every key
/// label (see [`algorithm_label`]), so both backends have to spell it the same way. The
/// segments are the RFC names, `x25519` rather than OpenPGP's `cv25519`; an RSA key signs
/// and decrypts with the same key, so its segment is the same in either role.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    /// NIST P-256: ECDSA signatures, ECDH key agreement
    P256,
    /// NIST P-384: ECDSA signatures, ECDH key agreement (PIV only)
    P384,
    /// Curve25519: Ed25519 signatures, X25519 key agreement
    Curve25519,
    /// RSA with a 2048-bit modulus: PKCS#1 v1.5 signatures and decryption
    Rsa2048,
    /// RSA with a 3072-bit modulus
    Rsa3072,
    /// RSA with a 4096-bit modulus
    Rsa4096,
}

impl Algorithm {
    /// Label segment of a signing key in this algorithm
    pub fn signing_segment(self) -> &'static str {
        match self {
            Algorithm::P256 => "p256",
            Algorithm::P384 => "p384",
            Algorithm::Curve25519 => "ed25519",
            _ => self.name(),
        }
    }

    /// Label segment of a key agreement (or, for RSA, decryption) key in this algorithm
    pub fn agreement_segment(self) -> &'static str {
        match self {
            Algorithm::P256 => "p256",
            Algorithm::P384 => "p384",
            Algorithm::Curve25519 => "x25519",
            _ => self.name(),
        }
    }

    /// The name the command line knows this algorithm by
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::P256 => "p256",
            Algorithm::P384 => "p384",
            Algorithm::Curve25519 => "curve25519",
            Algorithm::Rsa2048 => "rsa2048",
            Algorithm::Rsa3072 => "rsa3072",
            Algorithm::Rsa4096 => "rsa4096",
        }
    }

    /// Modulus size of an RSA algorithm, `None` for the elliptic curves
    pub fn rsa_bits(self) -> Option<u32> {
        match self {
            Algorithm::Rsa2048 => Some(2048),
            Algorithm::Rsa3072 => Some(3072),
            Algorithm::Rsa4096 => Some(4096),
            Algorithm::P256 | Algorithm::P384 | Algorithm::Curve25519 => None,
        }
    }

    /// Security strength in bits: the curves as NIST SP 800-57 part 1 rates them, the RSA
    /// moduli as SP 800-56B rev. 2 table 2 does
    ///
    /// The bar the phrase's entropy is held against: a key cannot be stronger than the
    /// secret it is derived from, so a phrase below this level makes the larger key size
    /// pointless rather than unsafe.
    pub fn strength_bits(self) -> u32 {
        match self {
            Algorithm::P256 | Algorithm::Curve25519 => 128,
            Algorithm::P384 => 192,
            Algorithm::Rsa2048 => 112,
            Algorithm::Rsa3072 => 128,
            Algorithm::Rsa4096 => 152,
        }
    }
}

/// Maximum number of re-derivations while searching for a valid P-256 or P-384 scalar, or
/// for a triple DES key that is not weak.
///
/// A rejection happens with probability of roughly 2^-32 per draw on P-256, 2^-190 on P-384
/// and 2^-50 for triple DES, so in practice the first candidate is always accepted; the
/// bound merely keeps the functions total.
const MAX_SCALAR_TRIES: usize = 8;

/// Derive a *valid* P-256 secret scalar, re-deriving deterministically on rejection.
///
/// A uniform 256-bit string is only a valid NIST P-256 private key when it lies in
/// `[1, n-1]`; `SecretKey::from_bytes` performs exactly that range and zero check. Ed25519
/// and X25519 need nothing of the kind, any 32 bytes are a key, which is why this lives
/// here for P-256 alone.
pub fn derive_p256_scalar(parent: &Seed256, path: Option<&[u8]>) -> Result<Zeroizing<Seed256>> {
    let mut candidate = parent.derive(path);

    for _ in 0..MAX_SCALAR_TRIES {
        // `into()` hands p256 a transient `FieldBytes` copy that is beyond our wiping
        if p256::SecretKey::from_bytes(&(*candidate).into()).is_ok() {
            return Ok(candidate);
        }

        log::warn!("Derived scalar outside the P-256 group order, re-deriving");
        candidate = candidate.key("p256-retry");
    }

    bail!("Failed to derive a valid P-256 scalar")
}

/// Width of a P-384 secret scalar in bytes
pub const P384_SCALAR_BYTES: usize = 48;

/// Derive a *valid* P-384 secret scalar, re-deriving deterministically on rejection.
///
/// One argon2id output is 256 bits and a P-384 scalar needs 384, so the candidate is the
/// first output `a`, followed by the first 16 bytes of a second output derived from `a`
/// under the fixed label `key:p384-extend`. `a` is a 256-bit secret in its own right, so the
/// extension adds width rather than entropy; what matters is that both halves are a
/// deterministic function of the seed and the label. A candidate outside `[1, n-1]` is
/// rejected like on P-256 and `a` moves on under `key:p384-retry`. The construction is
/// part of the `mtg1` scheme, see the derivation chapter.
pub fn derive_p384_scalar(parent: &Seed256, path: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>> {
    let mut first = parent.derive(path);

    for _ in 0..MAX_SCALAR_TRIES {
        let second = first.key("p384-extend");

        let mut candidate = Zeroizing::new(Vec::with_capacity(P384_SCALAR_BYTES));
        candidate.extend_from_slice(&first[..]);
        candidate.extend_from_slice(&second[..P384_SCALAR_BYTES - first.len()]);

        if p384::SecretKey::from_slice(&candidate).is_ok() {
            return Ok(candidate);
        }

        log::warn!("Derived scalar outside the P-384 group order, re-deriving");
        first = first.key("p384-retry");
    }

    bail!("Failed to derive a valid P-384 scalar")
}

/// Width of a triple DES key in bytes: three DES keys of eight bytes each
pub const TDES_KEY_BYTES: usize = 24;

/// The four weak and twelve semi-weak DES keys (FIPS 74, section 3.6), in odd parity
const DES_WEAK_KEYS: [[u8; 8]; 16] = [
    [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
    [0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE],
    [0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1],
    [0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E],
    [0x01, 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E],
    [0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E, 0x01],
    [0x01, 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1],
    [0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1, 0x01],
    [0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE],
    [0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01],
    [0x1F, 0xE0, 0x1F, 0xE0, 0x0E, 0xF1, 0x0E, 0xF1],
    [0xE0, 0x1F, 0xE0, 0x1F, 0xF1, 0x0E, 0xF1, 0x0E],
    [0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E, 0xFE],
    [0xFE, 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E],
    [0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1, 0xFE],
    [0xFE, 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1],
];

/// Whether a triple DES key is weak: one of its three DES keys is weak or semi-weak, or two
/// of them coincide, which collapses the cipher to single DES
///
/// DES ignores the low bit of every byte (it is a parity bit), so the comparison does too.
/// Neither `yubikey` nor the cards are relied on for this: the crate's parser accepts any 24
/// bytes, and what a card refuses varies by firmware.
pub fn is_weak_tdes_key(key: &[u8; TDES_KEY_BYTES]) -> bool {
    let strip = |chunk: &[u8]| -> [u8; 8] {
        let mut out = [0u8; 8];
        for (out, byte) in out.iter_mut().zip(chunk) {
            *out = byte & 0xfe;
        }
        out
    };

    let parts = [strip(&key[..8]), strip(&key[8..16]), strip(&key[16..])];
    let weak = parts
        .iter()
        .any(|part| DES_WEAK_KEYS.iter().any(|weak| strip(weak) == *part));

    weak || parts[0] == parts[1] || parts[1] == parts[2] || parts[0] == parts[2]
}

/// Derive a triple DES key that is not weak, re-deriving deterministically on rejection.
///
/// The key is the first 24 bytes of the labelled argon2id output; should those be weak (see
/// [`is_weak_tdes_key`]), the output moves on under `key:tdes-retry` and the next 24 bytes
/// are tried. A rejection has a probability of about 2^-50, so the bound only keeps the
/// function total.
pub fn derive_tdes_key(
    parent: &Seed256,
    path: Option<&[u8]>,
) -> Result<Zeroizing<[u8; TDES_KEY_BYTES]>> {
    let mut candidate = parent.derive(path);

    for _ in 0..MAX_SCALAR_TRIES {
        let mut key = Zeroizing::new([0u8; TDES_KEY_BYTES]);
        key.copy_from_slice(&candidate[..TDES_KEY_BYTES]);

        if !is_weak_tdes_key(&key) {
            return Ok(key);
        }

        log::warn!("Derived a weak triple DES key, re-deriving");
        candidate = candidate.key("tdes-retry");
    }

    bail!("Failed to derive a triple DES key that is not weak")
}
