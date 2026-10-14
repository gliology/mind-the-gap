//! The key set and its signatures, derived from the seeds.
//!
//! Part of the frozen `mtg1` derivation: the golden vectors in `tests/pgp/golden.rs` pin every
//! label, creation time and signature made here.

use super::{P384_REFUSED, Scheme, SeededSmartcard, SubkeyRole};
use crate::common;
use crate::seed::{self, Algorithm, Seed256, Seed256Derive};

use std::time::{Duration, SystemTime};

use anyhow::{Result, anyhow, bail};

use zeroize::Zeroizing;

use openpgp::Packet;
use openpgp::cert::{Cert, CertRevocationBuilder, SubkeyRevocationBuilder};
use openpgp::crypto::mpi::{MPI, ProtectedMPI, SecretKeyMaterial};
use openpgp::crypto::{KeyPair, mpi};
use openpgp::packet::key::Key4;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::packet::{Key, key};
use openpgp::policy::StandardPolicy;
use openpgp::types::{
    Curve as PgpCurve, Features, HashAlgorithm, PublicKeyAlgorithm, ReasonForRevocation,
    SignatureType, SymmetricAlgorithm,
};
use sequoia_openpgp as openpgp;

use rsa::RsaPrivateKey;
use rsa::traits::PrivateKeyParts;

pub(super) type SecretPrimaryKey = Key<key::SecretParts, key::PrimaryRole>;
pub(super) type SecretSubKey = Key<key::SecretParts, key::SubordinateRole>;

/// Map a numeric reason code onto the OpenPGP set
pub(super) fn reason(code: u8) -> ReasonForRevocation {
    match code {
        0 => ReasonForRevocation::Unspecified,
        1 => ReasonForRevocation::KeySuperseded,
        2 => ReasonForRevocation::KeyCompromised,
        3 => ReasonForRevocation::KeyRetired,
        32 => ReasonForRevocation::UIDRetired,
        100..=110 => ReasonForRevocation::Private(code),
        _ => ReasonForRevocation::Unknown(code),
    }
}

/// Notation naming the card a subkey was provisioned for
///
/// On the *subkey binding* signature rather than the user id: a user id is bound to the
/// primary key, and the primary is identical on every card, so a comment there would label one
/// shared identity with one card's name -- and merging two cards' certificates would leave two
/// user ids for the same person. The binding signature is the only part that is genuinely per
/// card, and it survives a merge with each subkey keeping its own.
pub(super) const NOTATION_SUBKEY: &str = "subkey@mind-the-gap.gli.al";

/// Derivation name of the primary key under the current scheme
pub(super) const NAME_PRIMARY: &str = "primary";

impl SeededSmartcard {
    /// Label a subkey is derived under
    ///
    /// The legacy labels are the OpenPGP key flag values themselves, which ties the derivation
    /// to how those flags happen to be bundled -- 0x0C is transport(0x04)|storage(0x08), so
    /// splitting them later would silently move the key.
    pub(super) fn label_for(&self, role: SubkeyRole) -> Vec<u8> {
        match self.scheme {
            Scheme::Legacy => role.code().to_le_bytes().to_vec(),
            Scheme::Current => {
                seed::algorithm_label(role.name(), role.algorithm_segment(self.algorithm))
            }
        }
    }

    /// Derive the raw secret of one key for the configured algorithm
    ///
    /// What comes out is exactly what the card imports: a valid P-256 scalar, an Ed25519
    /// seed, or a clamped X25519 scalar (Curve25519 paper, section 3: clear bits 0, 1, 2 of
    /// the first byte, clear bit 7 and set bit 6 of the last). For RSA it is the seed the
    /// primes are searched from, see [`crate::rsa::derive_key`].
    pub(super) fn derive_secret(
        &self,
        parent: &Seed256,
        label: Option<&[u8]>,
        agreement: bool,
    ) -> Result<Zeroizing<Seed256>> {
        match self.algorithm {
            Algorithm::P256 => seed::derive_p256_scalar(parent, label),
            Algorithm::P384 => bail!(P384_REFUSED),
            Algorithm::Curve25519 => {
                let mut bytes = parent.derive(label);
                if agreement {
                    bytes[0] &= 0b1111_1000;
                    bytes[31] &= !0b1000_0000;
                    bytes[31] |= 0b0100_0000;
                }
                Ok(bytes)
            }
            Algorithm::Rsa2048 | Algorithm::Rsa3072 | Algorithm::Rsa4096 => {
                Ok(parent.derive(label))
            }
        }
    }

    /// Turn a raw secret into a key of the type its role takes under the configured algorithm
    fn secret_key<R: key::KeyRole>(
        &self,
        bytes: &Seed256,
        agreement: bool,
        time: SystemTime,
    ) -> Result<Key4<key::SecretParts, R>> {
        match (self.algorithm, agreement) {
            (Algorithm::Curve25519, true) => Key4::import_secret_cv25519(bytes, None, None, time),
            (Algorithm::Curve25519, false) => Key4::import_secret_ed25519(bytes, time),
            (Algorithm::P384, _) => bail!(P384_REFUSED),
            (Algorithm::P256, _) => {
                // sequoia has no P-256 import, so the packet is assembled from its parts:
                // the uncompressed SEC1 point (0x04 || x || y) split into the MPI point
                // encoding, and the scalar as the secret
                let secret = p256::SecretKey::from_bytes(&(*bytes).into())?;
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
                let key = self.rsa_key(bytes)?;
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

    /// The RSA key a raw secret stands for, in the configured size
    pub(super) fn rsa_key(&self, bytes: &Seed256) -> Result<RsaPrivateKey> {
        let bits = self
            .algorithm
            .rsa_bits()
            .ok_or_else(|| anyhow!("Not an RSA algorithm"))?;
        crate::rsa::derive_key(bytes, bits)
    }

    /// The primary key, re-derived from its raw secret
    fn primary_key(&self) -> Result<SecretPrimaryKey> {
        Ok(self
            .secret_key(&self.seed, false, self.creation_time())?
            .into())
    }

    /// Admin pin for this card
    pub(super) fn admin_pin(&self) -> Zeroizing<String> {
        match self.scheme {
            Scheme::Legacy => self.subseed.base64(Some(b"admin")),
            Scheme::Current => self.subseed.pin("admin"),
        }
    }

    /// Seed a subkey is derived from, which is the shared one only when asked for
    pub(super) fn seed_for(&self, role: SubkeyRole) -> &Seed256 {
        if self.shared.contains(&role) {
            &self.shared_seed
        } else {
            &self.subseed
        }
    }

    /// Helper to determine creation time
    fn creation_time(&self) -> SystemTime {
        self.creation_time
            .unwrap_or(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
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
    fn new_primary_signer(&self) -> Result<KeyPair> {
        self.primary_key()?.into_keypair()
    }

    /// The primary key as a certificate of its own, its secret encrypted under the pin if
    /// there is one
    ///
    /// `signed` adds the direct key signature that policy evaluation needs (check, upload);
    /// the exported certificates leave it out, the user ids carry the self-signatures there.
    pub(super) fn primary_cert(&self, signed: bool) -> Result<Cert> {
        let primary = self.primary_key()?;

        let mut primary_enc = primary.clone();
        if let Some(pin) = self.pin.as_ref() {
            primary_enc
                .secret_mut()
                .encrypt_in_place(primary.parts_as_public(), pin)?;
        }
        let mut packets = vec![Packet::SecretKey(primary_enc)];

        if signed {
            let mut signer = primary.clone().into_keypair()?;
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

    /// Append self-signed subkeys to a primary certificate
    pub(super) fn append_subkeys(&self, mut cert: Cert) -> Result<Cert> {
        let primary = self.primary_key()?;
        let mut signer = primary.clone().into_keypair()?;

        let subkey_creation_time = self.subkey_creation_time.unwrap_or(self.creation_time());

        for role in SubkeyRole::ALL {
            let flags = role.flags();

            // Derive subkey specific seed and turn into key
            let agreement = role.is_encryption();
            let seed =
                self.derive_secret(self.seed_for(role), Some(&self.label_for(role)), agreement)?;
            let mut subkey: SecretSubKey = self
                .secret_key(&seed, agreement, subkey_creation_time)?
                .into();

            let mut builder = SignatureBuilder::new(SignatureType::SubkeyBinding)
                .set_hash_algo(HashAlgorithm::SHA512)
                .set_signature_creation_time(subkey_creation_time)?
                .set_key_flags(flags.clone())?
                .set_key_validity_period(self.subkey_validity)?;

            // Record which card this subkey belongs to. Not applied under the legacy scheme,
            // which has to keep producing exactly the certificates it always did.
            if self.scheme == Scheme::Current
                && let Some(id) = &self.subkey
            {
                builder = builder.add_notation(
                    NOTATION_SUBKEY,
                    seed::stamp(id).as_bytes(),
                    NotationDataFlags::empty().set_human_readable(),
                    false,
                )?;
            }

            if flags.for_certification() || flags.for_signing() {
                // We need to create a primary key binding signature.
                let mut subkey_signer = subkey.clone().into_keypair()?;
                let backsig = SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
                    .set_signature_creation_time(subkey_creation_time)?
                    .set_hash_algo(HashAlgorithm::SHA512)
                    .sign_primary_key_binding(&mut subkey_signer, &primary, &subkey)?;

                builder = builder.set_embedded_signature(backsig)?;
            }

            let signature = subkey.bind(&mut signer, &cert, builder)?;

            // Apply password protection (use a clone for the key reference to avoid borrow conflict)
            if let Some(pin) = self.pin.as_ref() {
                let subkey_pub = subkey.clone();
                subkey
                    .secret_mut()
                    .encrypt_in_place(subkey_pub.parts_as_public(), pin)?;
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

    /// Revoke every subkey of this card, leaving the primary and other cards untouched
    pub(super) fn generate_subkey_revcerts(
        &self,
        cert: &Cert,
        code: u8,
        reason_text: &str,
    ) -> Result<Vec<Packet>> {
        let creation_time = self.creation_time();

        // A subkey is revoked by its *primary*, which is what makes this possible at all: the
        // primary is re-derivable from the seed, so a card can be retired without it present
        let mut signer = self.new_primary_signer()?;

        let policy = StandardPolicy::new();
        let valid = cert.with_policy(&policy, None)?;

        valid
            .keys()
            .subkeys()
            .filter(|subkey| {
                // A subkey derived without the subkey id is byte-identical on every card,
                // so revoking it here would retire it fleet-wide -- exactly what
                // `--kind subkeys` promises not to do. Leave shared subkeys standing.
                let Some(flags) = subkey.key_flags() else {
                    return true;
                };
                let shared = self.shared.iter().any(|role| role.matches(&flags));
                if shared {
                    log::warn!(
                        "Leaving shared subkey {} in service: it is not this card's alone",
                        subkey.key().fingerprint()
                    );
                }
                !shared
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

    use sha2::{Digest, Sha256};

    /// The admin pin is frozen with the keys, under both schemes.
    ///
    /// It is what `check`, `config` and a re-upload authenticate with, so a pin that moved
    /// would lock this tool out of every card it provisioned while the key vectors, which
    /// never see the pin, kept passing. Pinned by digest, which says as much as the pin
    /// itself would without putting pin-shaped strings in the source.
    #[test]
    fn admin_pin_is_frozen() {
        for (scheme, id, expected) in [
            (
                Scheme::Current,
                None,
                "19a58d9c66d0408cf679afcb41a11bbc5f48e41ff556b0f2227424613b614abd",
            ),
            (
                Scheme::Current,
                Some("laptop"),
                "0d136d8ffafe653a3dac721c99bfb8d2c729798a0c21dc7b01df789a3b44bfff",
            ),
            (
                Scheme::Legacy,
                None,
                "5b3916a728ab1dbf54ce29c93a56347937a96029bfb5e3a17157f1121a52862d",
            ),
            (
                Scheme::Legacy,
                Some("laptop"),
                "0097d54a537a4ee1db421ce4d817420f2807f248124939cb1049bad59ef12cab",
            ),
        ] {
            let card = SeededSmartcard::with_scheme(
                &[1u8; 32],
                id.map(String::from),
                "Alice".into(),
                scheme,
            );
            let digest: String = Sha256::digest(card.admin_pin().as_bytes())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert_eq!(digest, expected, "{scheme:?} admin pin moved for {id:?}");
        }
    }
}
