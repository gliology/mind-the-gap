//! Slot keys, the management key and the card identifiers, derived from the seeds.
//!
//! Part of the frozen `mtg1` derivation: the golden vectors in `tests/piv/golden.rs` pin every
//! label used here.

use super::{SeededSmartcard, SlotRole};
use crate::backend::cached;
use crate::role::KeyRole;
use crate::seed::{self, Algorithm, CardSerial, SecretSeed, Seed256, Seed256Derive};

use anyhow::{Result, anyhow, bail};

use yubikey::piv::{self, AlgorithmId, RsaKeyData, SlotId};
use yubikey::{CardId, MgmAlgorithmId, MgmKey, PinPolicy, TouchPolicy, YubiKey};

use p256::ecdsa::SigningKey;

use rsa::RsaPrivateKey;
use rsa::traits::PrivateKeyParts;

use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use der::asn1::BitString;

use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use zeroize::Zeroizing;

/// Derivation name for the card management key in slot 9B, `pin:management:<kind>:<serial>`
const NAME_MANAGEMENT: &str = "management";

/// Credential kinds of the management key, one per algorithm the card may take
const KIND_AES256: &str = "aes256";
const KIND_TDES: &str = "tdes";

/// Derivation name for the puk, `pin:puk:ascii:<serial>`
const NAME_PUK: &str = "puk";

/// The longest puk a PIV card takes, in bytes
pub(super) const PUK_LENGTH: usize = 8;

/// Derivation name for the key management key, live in slot 9D or kept in a retired slot
pub(super) const NAME_KEY_MANAGEMENT: &str = "key-management";

/// Derivation name for the card identifier printed in the slot 9E subject
const NAME_CARD_ID: &str = "card";

/// Derivation name for the CHUID Card UUID
const NAME_CHUID_ID: &str = "chuid";

/// Derivation name for the CCC card identifier
const NAME_CCC_ID: &str = "ccc";

/// A slot's private key: what the card imports, and the algorithm it is for
pub(super) struct SlotKey {
    pub(super) algorithm: AlgorithmId,
    pub(super) secret: SlotSecret,
}

/// The secret half of a slot key, in the shape its algorithm family imports
pub(super) enum SlotSecret {
    /// The raw bytes an elliptic curve key is: 48 for a P-384 scalar, 32 for a P-256
    /// scalar, an Ed25519 seed or an X25519 key
    Bytes(Zeroizing<Vec<u8>>),
    /// An RSA key, of which the card takes the primes and their CRT exponents
    Rsa(Box<RsaPrivateKey>),
}

impl SlotKey {
    /// Derive a key for the card algorithm `algorithm` under `parent` and `label`
    ///
    /// Every key of the chain derives here, the authorities' as well as the slots', so that a
    /// key that signs its own certificate is the one the card holds.
    pub(super) fn derive(parent: &Seed256, label: &[u8], algorithm: AlgorithmId) -> Result<Self> {
        let rsa_bits = match algorithm {
            AlgorithmId::Rsa1024 => Some(1024),
            AlgorithmId::Rsa2048 => Some(2048),
            AlgorithmId::Rsa3072 => Some(3072),
            AlgorithmId::Rsa4096 => Some(4096),
            _ => None,
        };
        let secret = match (algorithm, rsa_bits) {
            (_, Some(bits)) => SlotSecret::Rsa(Box::new(crate::rsa::derive_key(
                &parent.derive(Some(label)),
                bits,
            )?)),
            (AlgorithmId::EccP256, _) => SlotSecret::Bytes(Zeroizing::new(
                seed::derive_p256_scalar(parent, Some(label))?.to_vec(),
            )),
            (AlgorithmId::EccP384, _) => {
                SlotSecret::Bytes(seed::derive_p384_scalar(parent, Some(label))?)
            }
            // Ed25519 takes any 32 bytes as its seed, X25519 clamps on use; the card does
            // the same with the very same bytes, so neither needs rejection sampling
            _ => SlotSecret::Bytes(Zeroizing::new(parent.derive(Some(label)).to_vec())),
        };

        Ok(SlotKey { algorithm, secret })
    }

    /// The raw bytes of an elliptic curve key
    pub(super) fn bytes(&self) -> Result<&Zeroizing<Vec<u8>>> {
        match &self.secret {
            SlotSecret::Bytes(bytes) => Ok(bytes),
            SlotSecret::Rsa(_) => bail!("{:?} keys are not raw bytes", self.algorithm),
        }
    }

    /// The public half, encoded exactly as the card reports it through `GET METADATA`
    ///
    /// That equality is what `upload` and `check` compare on, byte for byte. The X25519
    /// encoding is spelled out because `x25519-dalek` has no SPKI support: RFC 8410 gives
    /// the algorithm no parameters and the raw 32-byte point as the subject key.
    pub(super) fn spki(&self) -> Result<SubjectPublicKeyInfoOwned> {
        if let SlotSecret::Rsa(key) = &self.secret {
            return Ok(SubjectPublicKeyInfoOwned::from_key(key.as_public_key())?);
        }
        Ok(match self.algorithm {
            AlgorithmId::EccP256 => {
                let key = SigningKey::from_slice(self.bytes()?)
                    .map_err(|err| anyhow!("Invalid P-256 scalar: {err}"))?;
                SubjectPublicKeyInfoOwned::from_key(key.verifying_key())?
            }
            AlgorithmId::EccP384 => {
                let key = p384::ecdsa::SigningKey::from_slice(self.bytes()?)
                    .map_err(|err| anyhow!("Invalid P-384 scalar: {err}"))?;
                SubjectPublicKeyInfoOwned::from_key(key.verifying_key())?
            }
            AlgorithmId::Ed25519 => SubjectPublicKeyInfoOwned::from_key(
                &ed25519_dalek::SigningKey::from_bytes(&*self.seed()?).verifying_key(),
            )?,
            AlgorithmId::X25519 => SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifierOwned { oid: piv::OID_X25519, parameters: None },
                subject_public_key: BitString::from_bytes(
                    X25519PublicKey::from(&StaticSecret::from(**self.seed()?)).as_bytes(),
                )?,
            },
            other => bail!("{other:?} is not a slot key algorithm this backend derives"),
        })
    }

    /// The bytes as the 32-byte seed the Curve25519 keys take
    pub(super) fn seed(&self) -> Result<SecretSeed> {
        let bytes = self.bytes()?;
        let mut seed: SecretSeed = Box::new(Zeroizing::new([0u8; 32]));
        if bytes.len() != seed.len() {
            bail!("{:?} key is {} bytes, not 32", self.algorithm, bytes.len());
        }
        seed.copy_from_slice(bytes);
        Ok(seed)
    }

    /// Import this key into `slot`, with the card's own import for its algorithm family
    pub(super) fn import(
        &self,
        token: &mut YubiKey,
        slot: SlotId,
        touch_policy: TouchPolicy,
        pin_policy: PinPolicy,
    ) -> Result<()> {
        match (&self.secret, self.algorithm) {
            (SlotSecret::Rsa(key), _) => {
                let [p, q] = key.primes() else {
                    bail!("An RSA key without two primes")
                };
                let (p, q) = (Zeroizing::new(p.to_be_bytes()), Zeroizing::new(q.to_be_bytes()));
                piv::import_rsa_key(
                    token,
                    slot,
                    self.algorithm,
                    RsaKeyData::new(&p, &q)?,
                    touch_policy,
                    pin_policy,
                )?
            }
            (SlotSecret::Bytes(bytes), AlgorithmId::EccP256 | AlgorithmId::EccP384) => {
                piv::import_ecc_key(token, slot, self.algorithm, bytes, touch_policy, pin_policy)?
            }
            // Clamped as RFC 7748 has every X25519 implementation do before use: the same key
            // with the same public half, which a card that uses the bytes as they come
            // (CanoKey) would otherwise turn into another, all-zero one
            (SlotSecret::Bytes(bytes), AlgorithmId::X25519) => {
                let mut clamped = bytes.clone();
                clamped[0] &= 0b1111_1000;
                clamped[31] &= 0b0111_1111;
                clamped[31] |= 0b0100_0000;
                piv::import_cv_key(token, slot, self.algorithm, &clamped, touch_policy, pin_policy)?
            }
            (SlotSecret::Bytes(bytes), _) => {
                piv::import_cv_key(token, slot, self.algorithm, bytes, touch_policy, pin_policy)?
            }
        }

        Ok(())
    }
}

impl SeededSmartcard {
    /// The private key of one usable key, the same wherever it is kept
    ///
    /// A device's keys derive from its own seed, the decryption key from the seed every card
    /// of the identity shares; the slot the key ends up in plays no part, so a key kept in a
    /// retired slot derives exactly as it did in 9D.
    pub(super) fn role_key(&self, role: KeyRole) -> Result<&SlotKey> {
        let index = KeyRole::ALL
            .iter()
            .position(|r| *r == role)
            .expect("every role is among all of them");
        cached(&self.derived.roles[index], || {
            let seed = self.seeds.key()?.seed_for(role);
            let slot_role = SlotRole::from(role);
            let label = seed::algorithm_label(
                slot_role.name(),
                slot_role.algorithm_segment(self.algorithm),
            );
            SlotKey::derive(seed, &label, slot_role.card_algorithm(self.algorithm))
        })
    }

    /// Management key of the card with this serial, in `algorithm`
    ///
    /// Each algorithm derives under its own credential kind, so the two keys share no bytes:
    /// the 3DES key is not a truncation of the AES-256 one.
    pub(super) fn management_key(
        &self,
        algorithm: MgmAlgorithmId,
        serial: &CardSerial,
    ) -> Result<MgmKey> {
        let root = self.seeds.card()?;
        // Lent by reference, so the one copy of ours is wiped where it drops; the `MgmKey`
        // keeps an unwiped copy of its own until yubikey.rs wipes it on drop, so callers
        // keep it short-lived
        Ok(match algorithm {
            MgmAlgorithmId::Aes256 => {
                let key = root.credential(NAME_MANAGEMENT, KIND_AES256, serial);
                MgmKey::from_bytes(&key[..], Some(algorithm))?
            }
            MgmAlgorithmId::ThreeDes => {
                let label = seed::credential_label(NAME_MANAGEMENT, KIND_TDES, serial);
                MgmKey::from_bytes(seed::derive_tdes_key(root, Some(&label))?, Some(algorithm))?
            }
            other => bail!(
                "The card's management key is {other:?}, which this tool never installs: \
                 it was not initialized by mind-the-gap"
            ),
        })
    }

    /// The puk of the card with this serial, eight ASCII characters
    ///
    /// Derived rather than blocked, so that the card seed unblocks a forgotten pin without
    /// wiping the keys; the card counts its tries like any puk's.
    pub(super) fn puk(&self, serial: &CardSerial) -> Result<Zeroizing<String>> {
        Ok(self
            .seeds
            .card()?
            .ascii_credential(NAME_PUK, serial, PUK_LENGTH))
    }

    /// The card authentication key of the card with this serial, for `algorithm`
    ///
    /// The card's own key, from the card seed and bound to the serial: it says which card this
    /// is, never who holds it, so it is no key of the identity's.
    pub(super) fn card_authentication_key(
        &self,
        algorithm: Algorithm,
        serial: &CardSerial,
    ) -> Result<SlotKey> {
        let label = super::ownership::card_authentication_label(algorithm, serial);
        let algorithm = SlotRole::CardAuthentication.card_algorithm(algorithm);
        SlotKey::derive(self.seeds.card()?, &label, algorithm)
    }

    /// The Card UUID the CHUID of the card with this serial carries
    ///
    /// SP 800-73-4 wants a valid UUID there, so the derived bytes carry RFC 4122's version 4
    /// and variant bits, as a random UUID does, which leaves 122 of them derived.
    pub(super) fn chuid_guid(&self, serial: &CardSerial) -> Result<Vec<u8>> {
        let mut guid = self.seeds.card()?.card_id(NAME_CHUID_ID, serial, 16);
        guid[6] = (guid[6] & 0x0f) | 0x40;
        guid[8] = (guid[8] & 0x3f) | 0x80;
        Ok(guid)
    }

    /// The card identifier the CCC of the card with this serial carries
    pub(super) fn ccc_id(&self, serial: &CardSerial) -> Result<Vec<u8>> {
        Ok(self
            .seeds
            .card()?
            .card_id(NAME_CCC_ID, serial, CardId::BYTE_SIZE))
    }

    /// Card identifier used in the slot 9E subject
    pub(super) fn card_id(&self, serial: &CardSerial) -> Result<String> {
        let derived: String = self
            .seeds
            .card()?
            .card_id(NAME_CARD_ID, serial, 4)
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect();

        Ok(seed::stamp(&derived))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::{KeyPath, Seeds};

    use sha2::{Digest, Sha256};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn card() -> SeededSmartcard {
        SeededSmartcard::new(Seeds::one(&[1u8; 32]), KeyPath::default(), "Alice".into())
    }

    /// The card credentials are frozen with the keys, in both management key algorithms.
    ///
    /// They are what `check`, `upload` and `pin --reset` authenticate with, so a credential
    /// that moved would lock this tool out of every card it initialized while the chain
    /// vectors, which never see it, kept passing. Pinned by digest, which says as much as the
    /// credential itself would without putting key material in the source.
    #[test]
    fn card_credentials_are_frozen() {
        for (serial, aes, tdes, puk_digest) in [
            (
                12345678,
                "eb3aa0eeb1c50a330727424f90d254300c7e639176ad12fa19f4f101cbc9f51a",
                "dd9fcc4c3d0d20935861288b57afcbed8c6a3cb85bcf8aa6a4ef120ce6484c9c",
                "899f6f310bd5fd0f91f06991500519d8f90c63d78f63169f6920ac79cebca536",
            ),
            (
                87654321,
                "a4b6cca026e29fe4d0c244320a12baf196ae24f26d6ca9fd01633ac5bf336f9f",
                "1c64034bf0a6e8d80b13c9a3ed8683df4b3154b46c6226f88890c1aa9b2b9573",
                "8f6177c306ce55a252836765b408a6b230611538fd5f98ceca73723ec5ab126f",
            ),
        ] {
            let serial = CardSerial::piv(serial);
            let digest = |algorithm| {
                hex(&Sha256::digest(card().management_key(algorithm, &serial).unwrap().as_ref()))
            };
            assert_eq!(digest(MgmAlgorithmId::Aes256), aes, "AES-256 key moved for {serial}");
            assert_eq!(digest(MgmAlgorithmId::ThreeDes), tdes, "3DES key moved for {serial}");
            let puk = card().puk(&serial).unwrap();
            assert_eq!(puk.len(), PUK_LENGTH);
            assert_eq!(hex(&Sha256::digest(puk.as_bytes())), puk_digest, "puk moved for {serial}");
        }
    }

    /// The CHUID and CCC identifiers are frozen too, at the widths `init` writes them in.
    ///
    /// Middleware caches a card by them, so an identifier that moved would make a
    /// re-initialized card look like a stranger. Published on the card, so pinned as is.
    #[test]
    fn card_identifiers_are_frozen() {
        for (serial, chuid, ccc) in [
            (12345678, "5cc4a86390f64577b7970a3c491bf2e8", "0c1905a11faa6fb5236d098b943e"),
            (87654321, "f6e1e7cddbbb452aaef343236f66abfe", "bc75160cc177aedc6d0da3d28666"),
        ] {
            let serial = CardSerial::piv(serial);
            assert_eq!(
                hex(&card().chuid_guid(&serial).unwrap()),
                chuid,
                "CHUID moved for {serial}"
            );
            assert_eq!(hex(&card().ccc_id(&serial).unwrap()), ccc, "CCC moved for {serial}");
        }
    }
}
