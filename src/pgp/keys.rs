//! The key set and its signatures, derived from the seeds.
//!
//! Part of the frozen `mtg1` derivation: the golden vectors in `tests/pgp/golden.rs` pin every
//! label, creation time and signature made here.

use super::signer::DerivedSigner;
use super::{KeyRole, KeySecret, P384_REFUSED, Scheme, SeededSmartcard};
use crate::backend::cached;
use crate::common;
use crate::revocation::Reason;
use crate::seed::{self, Algorithm, CardSerial, Seed256, Seed256Derive};

use std::time::SystemTime;

use anyhow::{Result, anyhow, bail};

use zeroize::Zeroizing;

use openpgp::Packet;
use openpgp::cert::{Cert, CertRevocationBuilder, SubkeyRevocationBuilder};
use openpgp::crypto::mpi::{MPI, ProtectedMPI, SecretKeyMaterial};
use openpgp::crypto::{Password, mpi};
use openpgp::packet::key::Key4;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::{Key, key};
use openpgp::policy::StandardPolicy;
use openpgp::types::{
    Curve as PgpCurve, Features, HashAlgorithm, PublicKeyAlgorithm, ReasonForRevocation,
    SignatureType, SymmetricAlgorithm,
};
use sequoia_openpgp as openpgp;

use rsa::traits::PrivateKeyParts;

pub(super) type SecretPrimaryKey = Key<key::SecretParts, key::PrimaryRole>;
pub(super) type SecretSubKey = Key<key::SecretParts, key::SubordinateRole>;

/// Map a numeric reason code onto the OpenPGP set, which numbers the shared reasons the same
fn reason(code: u8) -> ReasonForRevocation {
    match Reason::of(code) {
        Some(Reason::Unspecified) => ReasonForRevocation::Unspecified,
        Some(Reason::Superseded) => ReasonForRevocation::KeySuperseded,
        Some(Reason::Compromised) => ReasonForRevocation::KeyCompromised,
        Some(Reason::Retired) => ReasonForRevocation::KeyRetired,
        None => match code {
            32 => ReasonForRevocation::UIDRetired,
            100..=110 => ReasonForRevocation::Private(code),
            _ => ReasonForRevocation::Unknown(code),
        },
    }
}

/// Derivation name of the primary key under the current scheme
pub(super) const NAME_PRIMARY: &str = "primary";

/// Derivation name of the admin pin, `pin:admin:ascii:<serial>`
const NAME_ADMIN: &str = "admin";

/// The longest admin pin the derivation hands out: 43 characters of base64, the whole 256
/// bits, which every OpenPGP card this tool knows takes
const ADMIN_PIN_LENGTH: usize = 43;

/// Derivation name of the card identifier `init` writes into the private-use data object,
/// `id:card:<serial>`, under the card seed like the PIV CHUID's Card UUID
pub(super) const NAME_CARD_ID: &str = "card";

impl SeededSmartcard {
    /// Label a subkey is derived under
    ///
    /// The legacy labels are the OpenPGP key flag values themselves, which ties the derivation
    /// to how those flags happen to be bundled -- 0x0C is transport(0x04)|storage(0x08), so
    /// splitting them later would silently move the key.
    pub(super) fn label_for(&self, role: KeyRole) -> Vec<u8> {
        match self.scheme {
            Scheme::Legacy => role.code().to_le_bytes().to_vec(),
            Scheme::Current => {
                seed::algorithm_label(role.name(), role.algorithm_segment(self.algorithm))
            }
        }
    }

    /// Derive the secret of one key for the configured algorithm
    ///
    /// The raw secret is exactly what the card imports: a valid P-256 scalar, an Ed25519
    /// seed, or a clamped X25519 scalar (Curve25519 paper, section 3: clear bits 0, 1, 2 of
    /// the first byte, clear bit 7 and set bit 6 of the last). For RSA it is the seed the
    /// primes are searched from, see [`crate::rsa::derive_key`], and the key comes with it.
    fn derive_secret(&self, parent: &Seed256, label: &[u8], agreement: bool) -> Result<KeySecret> {
        let raw = match self.algorithm {
            Algorithm::P256 => seed::derive_p256_scalar(parent, Some(label))?,
            Algorithm::P384 => bail!(P384_REFUSED),
            Algorithm::Curve25519 => {
                let mut bytes = parent.derive(Some(label));
                if agreement {
                    bytes[0] &= 0b1111_1000;
                    bytes[31] &= !0b1000_0000;
                    bytes[31] |= 0b0100_0000;
                }
                bytes
            }
            Algorithm::Rsa2048 | Algorithm::Rsa3072 | Algorithm::Rsa4096 => {
                parent.derive(Some(label))
            }
        };
        let rsa = match self.algorithm.rsa_bits() {
            Some(bits) => Some(Box::new(crate::rsa::derive_key(&raw, bits)?)),
            None => None,
        };
        Ok(KeySecret { raw, rsa })
    }

    /// The primary key's secret, under the application subtree
    ///
    /// The legacy scheme labels it with the byte 0x01, below the root it calls the
    /// application subtree.
    fn primary_secret(&self) -> Result<&KeySecret> {
        cached(&self.derived.primary, || {
            let label = match self.scheme {
                Scheme::Legacy => vec![0x01],
                Scheme::Current => {
                    seed::algorithm_label(NAME_PRIMARY, self.algorithm.signing_segment())
                }
            };
            self.derive_secret(self.seeds.key()?.app(), &label, false)
        })
    }

    /// One subkey's secret, under the device's subtree or the one every card shares
    pub(super) fn role_secret(&self, role: KeyRole) -> Result<&KeySecret> {
        let index = KeyRole::PGP
            .iter()
            .position(|r| *r == role)
            .expect("every role has a slot");
        cached(&self.derived.roles[index], || {
            let parent = self.seeds.key()?.seed_for(role);
            self.derive_secret(parent, &self.label_for(role), role.is_encryption())
        })
    }

    /// Turn a secret into a key of the type its role takes under the configured algorithm
    fn secret_key<R: key::KeyRole>(
        &self,
        secret: &KeySecret,
        agreement: bool,
        time: SystemTime,
    ) -> Result<Key4<key::SecretParts, R>> {
        let bytes: &Seed256 = &secret.raw;
        match (self.algorithm, agreement) {
            (Algorithm::Curve25519, true) => Key4::import_secret_cv25519(bytes, None, None, time),
            (Algorithm::Curve25519, false) => Key4::import_secret_ed25519(bytes, time),
            (Algorithm::P384, _) => bail!(P384_REFUSED),
            (Algorithm::P256, _) => {
                // sequoia has no P-256 import, so the packet is assembled from its parts:
                // the uncompressed SEC1 point (0x04 || x || y) split into the MPI point
                // encoding, and the scalar as the secret
                let secret = p256::SecretKey::from_slice(&bytes[..])?;
                let point = secret.public_key().to_sec1_bytes();
                let q = MPI::new_point(&point[1..33], &point[33..65], 256);
                let scalar = ProtectedMPI::from(bytes.to_vec());

                if agreement {
                    // The KDF parameters RFC 6637 recommends for P-256 and sequoia's own
                    // defaults, spelled out because those are not reachable from here
                    Key4::with_secret(
                        time,
                        PublicKeyAlgorithm::ECDH,
                        mpi::PublicKey::ECDH {
                            curve: PgpCurve::NistP256,
                            q,
                            hash: HashAlgorithm::SHA256,
                            sym: SymmetricAlgorithm::AES128,
                        },
                        SecretKeyMaterial::ECDH { scalar }.into(),
                    )
                } else {
                    Key4::with_secret(
                        time,
                        PublicKeyAlgorithm::ECDSA,
                        mpi::PublicKey::ECDSA { curve: PgpCurve::NistP256, q },
                        SecretKeyMaterial::ECDSA { scalar }.into(),
                    )
                }
            }
            (Algorithm::Rsa2048 | Algorithm::Rsa3072 | Algorithm::Rsa4096, _) => {
                // One RSA key serves every role: the flags on its binding decide what for
                let key = secret
                    .rsa
                    .as_deref()
                    .ok_or_else(|| anyhow!("An RSA secret without its key"))?;
                let [p, q] = key.primes() else {
                    bail!("An RSA key without two primes")
                };
                Key4::import_secret_rsa(
                    &Zeroizing::new(key.d().to_be_bytes()),
                    &Zeroizing::new(p.to_be_bytes()),
                    &Zeroizing::new(q.to_be_bytes()),
                    time,
                )
            }
        }
    }

    /// The primary key, made from its secret
    fn primary_key(&self) -> Result<SecretPrimaryKey> {
        let secret = self.primary_secret()?;
        Ok(self.secret_key(secret, false, self.creation_time())?.into())
    }

    /// Admin pin of the card with this serial
    ///
    /// The legacy scheme knows no card serial: its admin pin is the subkey seed's.
    pub(super) fn admin_pin(&self, serial: &CardSerial) -> Result<Zeroizing<String>> {
        let root = self.seeds.card()?;
        Ok(match self.scheme {
            Scheme::Legacy => root.base64(Some(b"admin")),
            Scheme::Current => root.ascii_credential(NAME_ADMIN, serial, ADMIN_PIN_LENGTH),
        })
    }

    /// The identifier that names the card with this serial as the card seed's, published in
    /// data object 0102
    ///
    /// The scheme stamp and 16 derived bytes in hex: readable to anyone who looks, as the
    /// derived PIV identifiers are, and revealing neither the card seed nor any key. `None`
    /// under the legacy scheme, which predates it and stays frozen as it was.
    pub fn card_identifier(&self, serial: &CardSerial) -> Result<Option<String>> {
        Ok(match self.scheme {
            Scheme::Legacy => None,
            Scheme::Current => {
                let id: String = self
                    .seeds
                    .card()?
                    .card_id(NAME_CARD_ID, serial, 16)
                    .iter()
                    .map(|byte| format!("{byte:02X}"))
                    .collect();
                Some(seed::stamp(&id))
            }
        })
    }

    /// Creation time of the primary key
    fn creation_time(&self) -> SystemTime {
        self.identity_time.unwrap_or_else(seed::epoch_creation)
    }

    /// Creation time of the subkeys: the generation's date, which is part of every subkey's
    /// fingerprint and so shows which generation a card holds
    ///
    /// The legacy scheme took it as an option of its own, defaulting to the primary's.
    pub fn subkey_creation_time(&self) -> SystemTime {
        match self.scheme {
            Scheme::Current => self.path.creation_time(),
            Scheme::Legacy => self.legacy_subkey_time.unwrap_or(self.creation_time()),
        }
    }

    /// Helper to create primary key-based signature builder including metadata.
    fn new_primary_sbuilder(&self, stype: SignatureType) -> Result<SignatureBuilder> {
        SignatureBuilder::new(stype)
            .set_features(Features::sequoia())?
            .set_hash_algo(HashAlgorithm::SHA512)
            .set_key_validity_period(None)?
            .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256])?
            .set_preferred_symmetric_algorithms(vec![
                SymmetricAlgorithm::AES256,
                SymmetricAlgorithm::AES128,
            ])?
            .set_signature_creation_time(self.creation_time())
    }

    /// Helper to create primary key-based signer
    fn new_primary_signer(&self) -> Result<DerivedSigner> {
        DerivedSigner::new(&self.primary_key()?)
    }

    /// The primary key as a certificate of its own, its secret encrypted under `passphrase`
    /// where there is one
    ///
    /// `signed` adds the direct key signature, which policy evaluation needs (check, upload)
    /// and the published primary and full certificates carry; the user ids and the subkeys
    /// parts leave it out, being merged into a certificate that has it.
    pub(super) fn primary_cert(&self, signed: bool, passphrase: Option<&Password>) -> Result<Cert> {
        let primary = self.primary_key()?;

        let mut primary_enc = primary.clone();
        if let Some(passphrase) = passphrase {
            primary_enc
                .secret_mut()
                .encrypt_in_place(primary.parts_as_public(), passphrase)?;
        }
        let mut packets = vec![Packet::SecretKey(primary_enc)];

        if signed {
            let mut signer = DerivedSigner::new(&primary)?;
            let sig = self.new_primary_sbuilder(SignatureType::DirectKey)?;
            packets.push(
                sig.sign_direct_key(&mut signer, primary.parts_as_public())?
                    .into(),
            );
        }

        Cert::try_from(packets)
    }

    /// Append self-signed user ids to a primary certificate
    pub(super) fn append_uids(&self, mut cert: Cert) -> Result<Cert> {
        let mut signer = self.new_primary_signer()?;

        for (i, uid) in self.userids.iter().enumerate() {
            let mut sig = self.new_primary_sbuilder(SignatureType::PositiveCertification)?;

            if i == 0 {
                sig = sig.set_primary_userid(true)?;
            }

            let signature = uid.bind(&mut signer, &cert, sig)?;
            cert = cert
                .insert_packets(vec![Packet::from(uid.clone()), signature.into()])
                .map(|(c, _)| c)?;
        }

        Ok(cert)
    }

    /// Append the chosen self-signed subkeys to a primary certificate, their secrets encrypted
    /// under `passphrase` where there is one
    pub(super) fn append_subkeys(
        &self,
        mut cert: Cert,
        passphrase: Option<&Password>,
    ) -> Result<Cert> {
        let primary = self.primary_key()?;
        let mut signer = DerivedSigner::new(&primary)?;

        let subkey_creation_time = self.subkey_creation_time();

        for &role in &self.keys {
            let flags = role.flags();

            let agreement = role.is_encryption();
            let mut subkey: SecretSubKey = self
                .secret_key(self.role_secret(role)?, agreement, subkey_creation_time)?
                .into();

            let mut builder = SignatureBuilder::new(SignatureType::SubkeyBinding)
                .set_hash_algo(HashAlgorithm::SHA512)
                .set_signature_creation_time(subkey_creation_time)?
                .set_key_flags(flags.clone())?
                .set_key_validity_period(self.subkey_validity)?;

            if flags.for_certification() || flags.for_signing() {
                // We need to create a primary key binding signature.
                let mut subkey_signer = DerivedSigner::new(&subkey)?;
                let backsig = SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
                    .set_signature_creation_time(subkey_creation_time)?
                    .set_hash_algo(HashAlgorithm::SHA512)
                    .sign_primary_key_binding(&mut subkey_signer, &primary, &subkey)?;

                builder = builder.set_embedded_signature(backsig)?;
            }

            let signature = subkey.bind(&mut signer, &cert, builder)?;

            // A clone for the public half, which the borrow of the secret would otherwise lock
            if let Some(passphrase) = passphrase {
                let subkey_pub = subkey.clone();
                subkey
                    .secret_mut()
                    .encrypt_in_place(subkey_pub.parts_as_public(), passphrase)?;
            }

            cert = cert
                .insert_packets(vec![Packet::SecretSubkey(subkey), signature.into()])
                .map(|(c, _)| c)?;
        }

        Ok(cert)
    }

    /// Sign uids in external certificate with our primary key
    pub(super) fn sign_uids(
        &self,
        mut cert: Cert,
        other: Cert,
        kind: SignatureType,
    ) -> Result<Cert> {
        let mut signer = self.new_primary_signer()?;

        let policy = &StandardPolicy::new();
        let valid_other = other.with_policy(policy, None)?;

        for uid in valid_other.userids() {
            log::info!("Signing userid '{}'", common::printable(&uid.userid().to_string()));

            // Use a minimal builder without subpackets
            let sig = SignatureBuilder::new(kind)
                .set_hash_algo(HashAlgorithm::SHA512)
                .set_signature_creation_time(self.creation_time())?;

            let signature = uid.userid().bind(&mut signer, &cert, sig)?;

            // Insert each signed UserID with its signature to associate them
            cert = cert
                .insert_packets(vec![Packet::from(uid.userid().clone()), signature.into()])
                .map(|(c, _)| c)?;
        }

        Ok(cert)
    }

    /// Generate revocation certificate
    pub(super) fn generate_revcert(
        &self,
        cert: &mut Cert,
        code: u8,
        reason_text: &str,
    ) -> Result<Packet> {
        let creation_time = self.creation_time();

        let mut signer = self.new_primary_signer()?;

        let revocation: Packet = CertRevocationBuilder::new()
            .set_signature_creation_time(creation_time)?
            .set_reason_for_revocation(reason(code), reason_text.as_bytes())?
            .build(&mut signer, cert, None)?
            .into();

        Ok(revocation)
    }

    /// Revoke this device's chosen subkeys, leaving the primary and other cards untouched
    ///
    /// The decryption key is the identity's, the same on every card, so revoking one device
    /// leaves it standing; only a choice of the decryption key alone (`--key decryption`)
    /// revokes it, which is how the identity retires a decryption key.
    pub(super) fn generate_subkey_revcerts(
        &self,
        cert: &Cert,
        code: u8,
        reason_text: &str,
    ) -> Result<Vec<Packet>> {
        // No earlier than the subkeys it revokes: a revocation made before its key existed is
        // one no implementation honours, and a dated generation's subkeys postdate the primary
        let creation_time = self.creation_time().max(self.subkey_creation_time());
        let decryption_alone = self.keys == [KeyRole::Decryption];

        // A subkey is revoked by its *primary*, which is what makes this possible at all: the
        // primary is re-derivable from the seed, so a card can be retired without it present
        let mut signer = self.new_primary_signer()?;

        // Judged when the subkeys were created, so an expired generation is revoked too
        let policy = StandardPolicy::new();
        let valid = cert.with_policy(&policy, Some(self.subkey_creation_time()))?;

        valid
            .keys()
            .subkeys()
            .filter(|subkey| {
                let Some(flags) = subkey.key_flags() else {
                    return true;
                };
                let shared = KeyRole::PGP
                    .iter()
                    .any(|role| !role.is_device_bound() && role.matches(&flags));
                if shared && !decryption_alone {
                    log::warn!(
                        "Leaving the decryption subkey {} in service: every card of the identity \
                         holds it",
                        subkey.key().fingerprint()
                    );
                }
                !shared || decryption_alone
            })
            .map(|subkey| {
                Ok(SubkeyRevocationBuilder::new()
                    .set_signature_creation_time(creation_time)?
                    .set_reason_for_revocation(reason(code), reason_text.as_bytes())?
                    .build(&mut signer, cert, subkey.key(), None)?
                    .into())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::{KeyPath, Seeds};

    use sha2::{Digest, Sha256};

    /// The admin pin is frozen with the keys, under both schemes.
    ///
    /// It is what `check`, `upload` and `pin --reset` authenticate with, so a pin that moved
    /// would lock this tool out of every card it initialized while the key vectors, which
    /// never see the pin, kept passing. Pinned by digest, which says as much as the pin
    /// itself would without putting pin-shaped strings in the source.
    #[test]
    fn admin_pin_is_frozen() {
        let serial = CardSerial::pgp(0x0006, 0x1234_5678);
        let current = |path: KeyPath, serial: &CardSerial| {
            SeededSmartcard::new(Seeds::one(&[1u8; 32]), path, "Alice".into())
                .admin_pin(serial)
                .unwrap()
        };
        let legacy = |id: Option<&str>| {
            SeededSmartcard::legacy(&[1u8; 32], id.map(String::from), "Alice".into())
                .admin_pin(&serial)
                .unwrap()
        };
        let digest = |pin: Zeroizing<String>| -> String {
            Sha256::digest(pin.as_bytes())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        };

        // The subkey id is no part of the admin pin any more: the card serial is
        let laptop = KeyPath { subkey: Some("laptop".into()), date: None };
        let pin = current(KeyPath::default(), &serial);
        assert_eq!(pin, current(laptop, &serial));
        assert_eq!(pin.len(), ADMIN_PIN_LENGTH);
        assert_eq!(
            digest(pin.clone()),
            "96a39150a1756b9e13e7adde0921aa3a44d27334a5e111e68e82c328d3b05f4f",
            "admin pin moved"
        );
        let other = current(KeyPath::default(), &CardSerial::pgp(0x0006, 0x1234_5679));
        assert_ne!(other, pin, "two cards share an admin pin");

        for (id, expected) in [
            (None, "5b3916a728ab1dbf54ce29c93a56347937a96029bfb5e3a17157f1121a52862d"),
            (Some("laptop"), "0097d54a537a4ee1db421ce4d817420f2807f248124939cb1049bad59ef12cab"),
        ] {
            assert_eq!(digest(legacy(id)), expected, "legacy admin pin moved for {id:?}");
        }
    }
}
