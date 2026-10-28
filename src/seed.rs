//! The derivation layer: argon2id and the labelled seed tree.
//!
//! Every derivation funnels through [`argon2id_256`]; the [`Seed256Derive`] trait spells the
//! step out as a label grammar (`app:`, `sub:`, `date:`, `key:`, `id:`, `pin:`) whose prefixes
//! keep outputs of different kinds apart by construction. Results come back wrapped in
//! [`Zeroizing`] so every copy wipes itself.
//!
//! Two seeds feed the tree, and one phrase may well be both: the *card seed* derives what
//! administers a card (credentials and identifiers, each bound to the card's serial), the
//! *key seed* an identity and its usable keys, along a [`KeyPath`]. The tree and its rationale
//! are documented in the derivation chapter,
//! <https://gliology.github.io/mind-the-gap/derivation.html>.

use argon2::{Argon2, Params, Version};

use anyhow::{Result, bail};

use chrono::NaiveDate;

use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::prelude::BASE64_STANDARD_NO_PAD;

use zeroize::Zeroizing;

/// Type alias for raw seeds
pub type Seed256 = [u8; 32];

/// A derived seed, wiped when dropped and kept on the heap
///
/// On the heap the 32 bytes stay where they were written: a seed handed on, returned or
/// stored in a struct moves only its pointer, where an array would be copied, and each copy
/// would be a stack slot nothing wipes.
pub type SecretSeed = Box<Zeroizing<Seed256>>;

/// A seed copied straight onto the heap, where the copy is wiped like any derived seed
fn secret_copy(seed: &Seed256) -> SecretSeed {
    let mut copy: SecretSeed = Box::new(Zeroizing::new([0u8; 32]));
    copy.copy_from_slice(seed);
    copy
}

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
pub fn argon2id_256(input: &[u8], salt: Option<&[u8]>) -> SecretSeed {
    // Chosen for memory-constrained environments; comfortably above the OWASP floor,
    // and part of the frozen mtg1 scheme (see above)
    let params = Params::new(64 * 1024, 3, 1, None).unwrap();

    // At the root the salt carries the seed's password, so the joined copy is wiped too
    let salt = Zeroizing::new([DERIVATION_CONTEXT, salt.unwrap_or(b"")].concat());

    let mut hash: SecretSeed = Box::new(Zeroizing::new([0u8; 32]));
    Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(input, &salt, &mut hash[..])
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

/// Subtree of one key generation, named by the day it was created
pub const PREFIX_DATE: &str = "date";

/// 256 bits of raw key material
pub const PREFIX_KEY: &str = "key";

/// Identifier material, truncated by the caller to the width its format allows
pub const PREFIX_ID: &str = "id";

/// A credential: a pin, a puk or a management key, always bound to one card
pub const PREFIX_PIN: &str = "pin";

/// Whether `segment` fits the label grammar: lowercase letters, digits and hyphens
fn is_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Compose a derivation label from its prefix and a lowercase hyphenated name
///
/// For the fixed labels this crate defines. The grammar is asserted rather than enforced,
/// since every caller passes a literal -- a violation is a bug here, not bad input.
pub fn label(prefix: &str, name: &str) -> Vec<u8> {
    debug_assert!(is_segment(name), "derivation labels are lowercase and hyphenated: {name:?}");
    format!("{prefix}:{name}").into_bytes()
}

/// Compose a label of several segments after its prefix: `<prefix>:<a>:<b>:...`
///
/// Every segment follows the grammar of [`label`]; a card serial is spelled into it by
/// [`CardSerial`], which is how a label that names a card stays inside the grammar.
pub fn segments_label(prefix: &str, segments: &[&str]) -> Vec<u8> {
    debug_assert!(
        !segments.is_empty() && segments.iter().all(|segment| is_segment(segment)),
        "derivation labels are lowercase and hyphenated: {segments:?}",
    );
    let mut label = prefix.to_string();
    for segment in segments {
        label.push(':');
        label.push_str(segment);
    }
    label.into_bytes()
}

/// Compose the label for key material bound to one algorithm: `key:<name>:<segment>`
///
/// The algorithm is a segment of its own rather than part of the name so that one name can
/// never hand the same bytes to two algorithms: `key:signature:p256` and
/// `key:signature:ed25519` are different keys, and a card switched from one algorithm to the
/// other shares no secret with its former self.
pub fn algorithm_label(name: &str, segment: &str) -> Vec<u8> {
    segments_label(PREFIX_KEY, &[name, segment])
}

/// Compose the label of a credential bound to one card: `pin:<name>:<kind>:<serial>`
///
/// The kind says what the derived bytes become (`aes256`, `tdes`, `ascii`), so one name can
/// never hand the same bytes to two encodings; the serial makes the credential the card's
/// own, so one card's credential opens no other card.
pub fn credential_label(name: &str, kind: &str, serial: &CardSerial) -> Vec<u8> {
    segments_label(PREFIX_PIN, &[name, kind, serial.segment()])
}

/// Compose the label of an identifier bound to one card: `id:<name>:<serial>`
pub fn card_id_label(name: &str, serial: &CardSerial) -> Vec<u8> {
    segments_label(PREFIX_ID, &[name, serial.segment()])
}

/// Compose the label for the subtree scoped to a user-supplied subkey id, `sub:<id>`
///
/// Deliberately not [`label`]: the id is arbitrary text a user chose, so it is neither checked
/// against the label grammar nor required to be valid UTF-8 beyond what the CLI already
/// accepts. The prefix is what matters: no fixed label begins with it, so an id can never
/// collide with one however exotic it is. The empty id is an id like any other; no id at all
/// is no step, see [`KeyPath`].
pub fn sub_label(id: &str) -> Vec<u8> {
    [PREFIX_SUB.as_bytes(), b":", id.as_bytes()].concat()
}

/// Compose the label for the subtree of one key generation, `date:<YYYY-MM-DD>`
pub fn date_label(date: NaiveDate) -> Vec<u8> {
    format!("{PREFIX_DATE}:{}", date.format("%Y-%m-%d")).into_bytes()
}

/// A card's hardware serial, spelled as the last segment of the labels bound to that card
///
/// The serial is the card's own: what a PIV card reports for itself (a YubiKey's serial
/// number, the trussed app's), or the manufacturer and serial of an OpenPGP card's
/// application identifier. Spelled in decimal for PIV and as `mmmm-ssssssss` in lowercase hex
/// for OpenPGP, so that both stay inside the label grammar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CardSerial(String);

impl CardSerial {
    /// A PIV card's serial number
    pub fn piv(serial: u32) -> Self {
        CardSerial(serial.to_string())
    }

    /// An OpenPGP card's manufacturer and serial, from its application identifier
    pub fn pgp(manufacturer: u16, serial: u32) -> Self {
        CardSerial(format!("{manufacturer:04x}-{serial:08x}"))
    }

    /// The label segment
    pub fn segment(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CardSerial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The two seeds a command derives from, each present only when the command needs it
///
/// One phrase is usually both. They part where administering cards and holding an identity
/// are different people or different risks: a team's administrator issues every member's card
/// from the card seed, while the team's signing keys come from the team's own key seed.
#[derive(Clone, Copy, Default)]
pub struct Seeds<'a> {
    /// What administers a card: its credentials and identifiers
    pub card: Option<&'a Seed256>,
    /// What an identity and its usable keys derive from
    pub key: Option<&'a Seed256>,
}

impl<'a> Seeds<'a> {
    /// One seed in both roles
    pub fn one(seed: &'a Seed256) -> Self {
        Seeds { card: Some(seed), key: Some(seed) }
    }
}

/// Where usable keys sit under a key seed's application subtree
///
/// Two optional steps, each skipped when not given: `sub:<id>` for a device or application,
/// then `date:<YYYY-MM-DD>` for a key generation. A key bound to one device takes both; the
/// keys an identity shares across its devices (the decryption key) take the date alone, so
/// every card of the identity carries the same one and rotation still moves it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyPath {
    /// The device or application the keys are bound to
    pub subkey: Option<String>,
    /// The key generation, which is also when its keys and certificates were created
    pub date: Option<NaiveDate>,
}

impl KeyPath {
    /// The seed a device's own keys derive from: `[sub:<id>] / [date:<iso>]`
    pub fn device(&self, app: &Seed256) -> SecretSeed {
        let seed = match &self.subkey {
            Some(id) => app.sub(id),
            None => secret_copy(app),
        };
        match self.date {
            Some(date) => seed.date(date),
            None => seed,
        }
    }

    /// The seed an identity's shared keys derive from: `[date:<iso>]`
    pub fn shared(&self, app: &Seed256) -> SecretSeed {
        match self.date {
            Some(date) => app.date(date),
            None => secret_copy(app),
        }
    }

    /// When the keys of this generation were created: midnight UTC of its date, or one
    /// second after the unix epoch without one, so that an undated generation reproduces
    pub fn creation_time(&self) -> SystemTime {
        match self.date {
            Some(date) => midnight(date),
            None => epoch_creation(),
        }
    }
}

/// The creation time of everything derived without a date: one second after the unix epoch,
/// since OpenPGP reads a zero creation time as none at all
pub fn epoch_creation() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1)
}

/// Midnight UTC of a day, as a system time; never local time, so that derivation inputs do
/// not depend on the time zone of the machine they are typed on
pub fn midnight(date: NaiveDate) -> SystemTime {
    let seconds = date
        .and_hms_opt(0, 0, 0)
        .expect("midnight exists")
        .and_utc()
        .timestamp();
    // Dates before 1970 cannot be key generations: OpenPGP stores creation times unsigned
    SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(seconds).unwrap_or(0))
}

/// The day a generation was created on, read back from a creation time
///
/// The inverse of [`KeyPath::creation_time`]: `None` for the undated epoch time, the day for a
/// time at its midnight UTC, and an error for anything else, which no generation produces.
pub fn generation_of(time: SystemTime) -> Option<Option<NaiveDate>> {
    if time == epoch_creation() {
        return Some(None);
    }
    let seconds = time.duration_since(SystemTime::UNIX_EPOCH).ok()?.as_secs();
    let date = chrono::DateTime::from_timestamp(i64::try_from(seconds).ok()?, 0)?;
    (seconds % 86_400 == 0).then(|| Some(date.date_naive()))
}

/// Derivation name of the seed's own identifier, see [`Seed256Derive::seed_id`]
const NAME_SEED_ID: &str = "seed";

/// Abstract derivation step
///
/// Every label is `<prefix>:<name>`, and the prefix says what comes out: `key` is raw key
/// material, `id` is an identifier, `pin` is a credential that opens one card. `app`, `sub`
/// and `date` name subtrees rather than outputs. Keeping the shape in the label means two
/// derivations can never agree by accident just because their names happen to match across
/// use cases.
pub trait Seed256Derive {
    /// Derive a child seed under the given path
    fn derive(&self, path: Option<&[u8]>) -> SecretSeed;

    /// Derive a child seed and encode it as base64
    fn base64(&self, path: Option<&[u8]>) -> Zeroizing<String> {
        Zeroizing::new(base64_encode(&self.derive(path)[..]))
    }

    /// Derive an application subtree, which is itself only ever used to derive further
    fn app(&self, name: &str) -> SecretSeed {
        self.derive(Some(&label(PREFIX_APP, name)))
    }

    /// Derive the subtree scoped to a user-supplied subkey id
    fn sub(&self, id: &str) -> SecretSeed {
        self.derive(Some(&sub_label(id)))
    }

    /// Derive the subtree of one key generation
    fn date(&self, date: NaiveDate) -> SecretSeed {
        self.derive(Some(&date_label(date)))
    }

    /// Derive the raw bytes of a credential bound to one card, see [`credential_label`]
    fn credential(&self, name: &str, kind: &str, serial: &CardSerial) -> SecretSeed {
        self.derive(Some(&credential_label(name, kind, serial)))
    }

    /// Derive an identifier bound to one card, truncated to the width the format allows
    fn card_id(&self, name: &str, serial: &CardSerial, bytes: usize) -> Vec<u8> {
        self.derive(Some(&card_id_label(name, serial)))[..bytes].to_vec()
    }

    /// The seed's own identifier, `id:seed` in hex, for telling whether a phrase and its
    /// password were entered as they were written down
    ///
    /// A password has no checksum, so a typo in it silently derives other keys; this short,
    /// public value is what a record kept with the phrase can be compared with first. Eight
    /// bytes say nothing about the seed that the derived public keys do not.
    fn seed_id(&self) -> String {
        self.derive(Some(&label(PREFIX_ID, NAME_SEED_ID)))[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// Derive 256 bits of raw key material
    fn key(&self, name: &str) -> SecretSeed {
        self.derive(Some(&label(PREFIX_KEY, name)))
    }

    /// Derive 256 bits of key material for one algorithm, see [`algorithm_label`]
    fn algorithm_key(&self, name: &str, segment: &str) -> SecretSeed {
        self.derive(Some(&algorithm_label(name, segment)))
    }

    /// Derive identifier material, truncated to the width the format allows
    ///
    /// Separate from [`Seed256Derive::key`] so that an identifier, which is published, can
    /// never be the same bytes as a key that merely shares its name.
    fn id(&self, name: &str, bytes: usize) -> Vec<u8> {
        self.derive(Some(&label(PREFIX_ID, name)))[..bytes].to_vec()
    }

    /// Derive an ASCII credential bound to one card, `pin:<name>:ascii:<serial>`, in base64
    /// and at most `length` characters long
    fn ascii_credential(
        &self,
        name: &str,
        serial: &CardSerial,
        length: usize,
    ) -> Zeroizing<String> {
        let mut text = Zeroizing::new(base64_encode(&self.credential(name, "ascii", serial)[..]));
        text.truncate(length);
        text
    }
}

// ... and implement it using argon2
impl Seed256Derive for Seed256 {
    fn derive(&self, path: Option<&[u8]>) -> SecretSeed {
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

impl std::fmt::Display for Algorithm {
    // The command-line spelling, so a message names the value the user would type
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = clap::ValueEnum::to_possible_value(self).expect("no variant is skipped");
        f.write_str(value.get_name())
    }
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
/// `[1, n-1]`; `SecretKey::from_slice` performs exactly that range and zero check. Ed25519
/// and X25519 need nothing of the kind, any 32 bytes are a key, which is why this lives
/// here for P-256 alone.
pub fn derive_p256_scalar(parent: &Seed256, path: Option<&[u8]>) -> Result<SecretSeed> {
    let mut candidate = parent.derive(path);

    for _ in 0..MAX_SCALAR_TRIES {
        // From the slice, which p256 reads in place rather than as a copy of its own
        if p256::SecretKey::from_slice(&candidate[..]).is_ok() {
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
