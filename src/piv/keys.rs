//! Slot keys, the management key and the card identifiers, derived from the seeds.
//!
//! Part of the frozen `mtg1` derivation: the golden vectors in `tests/piv/golden.rs` pin every
//! label used here.

use super::{
    SeededSmartcard, SharedSlot, SlotRole, slots::FIRST_RETIRED_SLOT, slots::slot_name,
    slots::slot_role,
};
use crate::seed::{self, Algorithm, Seed256, Seed256Derive};

use anyhow::{Result, anyhow, bail};

use yubikey::piv::{self, AlgorithmId, RetiredSlotId, RsaKeyData, SlotId};
use yubikey::{MgmAlgorithmId, MgmKey, PinPolicy, TouchPolicy, YubiKey};

use p256::ecdsa::SigningKey;

use rsa::RsaPrivateKey;
use rsa::traits::PrivateKeyParts;

use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use der::asn1::BitString;

use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use zeroize::Zeroizing;

/// Derivation name for the card management key in slot 9B
pub(super) const NAME_MANAGEMENT: &str = "management";

/// Algorithm segment of the triple DES management key, `key:management:tdes`
///
/// The AES-256 key predates the segment and keeps its bare `key:management` label, frozen
/// with the rest of `mtg1`; the 3DES key is a later, additive label.
pub(super) const SEGMENT_TDES: &str = "tdes";

/// Derivation name for the key management key, live in slot 9D and archived in a retired slot
pub(super) const NAME_KEY_MANAGEMENT: &str = "key-management";

/// Derivation name for the card identifier printed in the slot 9E subject
const NAME_CARD_ID: &str = "card";

/// Derivation name for the CHUID Card UUID
pub(super) const NAME_CHUID_ID: &str = "chuid";

/// Derivation name for the CCC card identifier
pub(super) const NAME_CCC_ID: &str = "ccc";

/// A slot's private key: what the card imports, and the algorithm it is for
pub(super) struct SlotKey {
    algorithm: AlgorithmId,
    secret: SlotSecret,
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
    /// Derive the key for `role` under `parent` and `label`
    fn derive(
        parent: &Seed256,
        label: &[u8],
        role: SlotRole,
        algorithm: Algorithm,
    ) -> Result<Self> {
        let rsa_bits = algorithm.rsa_bits();
        let algorithm = role.card_algorithm(algorithm);
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
    fn bytes(&self) -> Result<&Zeroizing<Vec<u8>>> {
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
                    X25519PublicKey::from(&StaticSecret::from(*self.seed()?)).as_bytes(),
                )?,
            },
            other => bail!("{other:?} is not a slot key algorithm this backend derives"),
        })
    }

    /// The bytes as the 32-byte seed the Curve25519 keys take
    fn seed(&self) -> Result<Zeroizing<Seed256>> {
        let bytes = self.bytes()?;
        let mut seed = Zeroizing::new([0u8; 32]);
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
            (SlotSecret::Bytes(bytes), _) => {
                piv::import_cv_key(token, slot, self.algorithm, bytes, touch_policy, pin_policy)?
            }
        }

        Ok(())
    }
}

impl SeededSmartcard {
    /// Where a slot's key comes from: the seed it derives under and the label it uses
    ///
    /// A retired slot holds a *previous* generation's key management key, so it derives from
    /// that generation's subseed under the very same label the live 9D key uses. Deriving it
    /// by role rather than by slot is what lets an archived key be re-derived at all.
    fn key_source(&self, slot: SlotId) -> Result<(Zeroizing<Seed256>, Vec<u8>)> {
        let segment = slot_role(slot).algorithm_segment(self.algorithm);

        if let SlotId::Retired(retired) = slot {
            let index = usize::from(u8::from(retired).saturating_sub(FIRST_RETIRED_SLOT));
            let generation = self
                .retired
                .get(index)
                .ok_or_else(|| anyhow!("No retired generation for {slot:?}"))?;

            return Ok((
                self.root.sub(Some(generation)),
                seed::algorithm_label(NAME_KEY_MANAGEMENT, segment),
            ));
        }

        // A deliberate copy of the slot's parent seed, wiped when the caller is done with it
        Ok((Zeroizing::new(*self.seed_for(slot)), seed::algorithm_label(slot_name(slot), segment)))
    }

    /// The private key a slot holds, derived the same way whether it is certified or imported
    pub(super) fn slot_key(&self, slot: SlotId) -> Result<SlotKey> {
        let (seed, label) = self.key_source(slot)?;
        SlotKey::derive(&seed, &label, slot_role(slot), self.algorithm)
    }

    /// Slot each archived generation is written to, newest first from 0x82
    pub(super) fn retired_slots(&self) -> Result<Vec<(SlotId, &str)>> {
        // An archived generation re-derives as that generation's *per-card* key management
        // key. Under --shared key-management there is no such key: the fleet-wide key is
        // derived without any subkey id and never rotates with it, so the archive would hold
        // a key no card ever carried -- and check could not catch it, because it compares
        // against the same wrong derivation.
        if !self.retired.is_empty() && self.shared.contains(&SharedSlot::KeyManagement) {
            bail!(
                "--retire archives per-card key management generations, which --shared \
                 key-management does not produce: the shared key never rotates with the \
                 subkey id, so there is no generation to archive. Drop one of the two flags."
            );
        }

        self.retired
            .iter()
            .enumerate()
            .map(|(index, generation)| {
                let offset = u8::try_from(index)
                    .ok()
                    .and_then(|i| FIRST_RETIRED_SLOT.checked_add(i));
                let slot = offset
                    .and_then(|byte| RetiredSlotId::try_from(byte).ok())
                    .ok_or_else(|| anyhow!("Only 20 generations fit in the retired slots"))?;

                Ok((SlotId::Retired(slot), generation.as_str()))
            })
            .collect()
    }

    /// Seed a slot key is derived from, which is the shared one only when asked for
    fn seed_for(&self, slot: SlotId) -> &Seed256 {
        if self.shared.iter().any(|entry| SlotId::from(*entry) == slot) {
            &self.shared_seed
        } else {
            &self.subseed
        }
    }

    /// Management key derived from the subkey generation seed, in `algorithm`
    ///
    /// Each algorithm derives under its own label, so the two keys share no bytes: the
    /// 3DES key is not a truncation of the AES-256 one.
    pub(super) fn management_key(&self, algorithm: MgmAlgorithmId) -> Result<MgmKey> {
        // Moved in by value so our copy is wiped when `from_bytes` drops it; the `MgmKey`
        // itself keeps an unwiped internal cipher-key copy, so callers keep it short-lived
        Ok(match algorithm {
            MgmAlgorithmId::Aes256 => {
                MgmKey::from_bytes(self.subseed.key(NAME_MANAGEMENT), Some(algorithm))?
            }
            MgmAlgorithmId::ThreeDes => {
                let label = seed::algorithm_label(NAME_MANAGEMENT, SEGMENT_TDES);
                MgmKey::from_bytes(
                    seed::derive_tdes_key(&self.subseed, Some(&label))?,
                    Some(algorithm),
                )?
            }
            other => bail!(
                "The card's management key is {other:?}, which this tool never installs: \
                 it was not provisioned by mind-the-gap"
            ),
        })
    }

    /// Card identifier used in the slot 9E subject.
    ///
    /// Derived from the subkey generation seed rather than read off the card, so that
    /// `certify` (which runs without hardware) and `upload` agree and `check` can compare.
    pub(super) fn card_id(&self) -> String {
        let derived: String = self
            .subseed
            .id(NAME_CARD_ID, 4)
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect();

        seed::stamp(&derived)
    }
}
