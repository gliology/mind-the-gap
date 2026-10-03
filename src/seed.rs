//! The derivation layer: argon2id and the labelled seed tree.
//!
//! Every derivation funnels through [`argon2id_256`]; the [`Seed256Derive`] trait spells the
//! step out as a label grammar (`app:`, `sub:`, `key:`, `id:`, `pin:`) whose prefixes keep
//! outputs of different kinds apart by construction. Results come back wrapped in
//! [`Zeroizing`] so every copy wipes itself. The tree and its rationale are documented in
//! the derivation chapter, <https://gliology.github.io/mind-the-gap/derivation.html>.

use argon2::{Algorithm, Argon2, Params, Version};

use base64::Engine;
use base64::prelude::BASE64_STANDARD_NO_PAD;

use zeroize::Zeroizing;

/// Type alias for raw seeds
pub type Seed256 = [u8; 32];

/// Constant to be used in all 256bit seed derivations
const DERIVATION_CONTEXT: &[u8] = b"MINDTHEGAP256HDKD";

/// Simple wrapper around argon2 crate to hash byte inputs
pub fn argon2id_256(input: &[u8], salt: Option<&[u8]>) -> Zeroizing<Seed256> {
    // Default setting for memory-constrained environments
    let params = Params::new(64 * 1024, 3, 1, None).unwrap();

    // Prepare salt value
    let salt = &[DERIVATION_CONTEXT, salt.unwrap_or(b"")].concat();

    // Use latest hybrid variant
    let mut hash = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
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

/// Compose the label for the subtree scoped to a user-supplied subkey id
///
/// Deliberately not [`label`]: the id is arbitrary text a user chose, so it is neither checked
/// against the label grammar nor required to be valid UTF-8 beyond what the CLI already
/// accepts. The prefix is what matters -- no fixed label begins with it, so an id can never
/// collide with one however exotic it is. `None` and `""` mean the same thing, which is what
/// makes a card with no subkey id and a `--shared` key agree.
pub fn sub_label(id: Option<&str>) -> Vec<u8> {
    [PREFIX_SUB.as_bytes(), b":", id.unwrap_or("").as_bytes()].concat()
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
