//! The signer behind every OpenPGP signature: self-signatures, bindings, certifications and
//! revocations alike.
//!
//! sequoia's `KeyPair` signs ECDSA through nettle with a random nonce, so a P-256 signature
//! would differ on every run. P-256 is signed here instead, by RustCrypto's RFC 6979 with
//! the HMAC on the signature's own hash: the code the PIV certificates are signed with, and
//! the signature RFC 6979 defines, so other implementations of it agree byte for byte.
//! Ed25519 (RFC 8032) and RSA (PKCS#1 v1.5) are deterministic already and stay with sequoia.
//!
//! Every signature is made twice and compared, then verified, before it leaves, whatever
//! the algorithm: a computation faulted by a flipped bit or an attacker gives a signature
//! that, next to the valid one a rerun makes, would give the key away. All three algorithms
//! are deterministic, so two runs that disagree mean a fault, also one in the nonce that
//! leaves the signature valid. Clippy refuses `into_keypair` outside this module
//! (clippy.toml), so no signature reaches sequoia's signer by accident.

use anyhow::{Result, anyhow, bail};

use zeroize::Zeroizing;

use ecdsa::hazmat::sign_prehashed_rfc6979;
use p256::NistP256;
use p256::ecdsa::SigningKey;
use sha2_ecdsa as sha2;

use openpgp::crypto::mpi::{self, MPI};
use openpgp::crypto::{KeyPair, Signer};
use openpgp::packet::Key;
use openpgp::packet::key::{self, SecretKeyMaterial};
use openpgp::types::{Curve, HashAlgorithm};
use sequoia_openpgp as openpgp;

/// Size of a P-256 scalar
const P256_SCALAR: usize = 32;

/// The hashes a P-256 signature is made over, preferred first: every signature this crate
/// makes is SHA-512
const P256_HASHES: [HashAlgorithm; 3] = [
    HashAlgorithm::SHA512,
    HashAlgorithm::SHA384,
    HashAlgorithm::SHA256,
];

/// Signs with one key, by the algorithm the key is for, and checks every signature
pub(super) struct DerivedSigner {
    public: Key<key::PublicParts, key::UnspecifiedRole>,
    secret: Secret,
}

enum Secret {
    P256(SigningKey),
    Sequoia(Box<KeyPair>),
    /// A P-256 signer that is not deterministic, which the comparison has to refuse
    #[cfg(test)]
    Varying(SigningKey, u8),
}

impl DerivedSigner {
    /// The signer for `key`, refusing a key it would not sign deterministically
    pub(super) fn new<R: key::KeyRole>(key: &Key<key::SecretParts, R>) -> Result<Self> {
        let secret = match key.mpis() {
            mpi::PublicKey::ECDSA { curve: Curve::NistP256, .. } => Secret::P256(p256_secret(key)?),
            mpi::PublicKey::EdDSA { curve: Curve::Ed25519, .. }
            | mpi::PublicKey::Ed25519 { .. }
            | mpi::PublicKey::RSA { .. } =>
            {
                #[allow(clippy::disallowed_methods)]
                Secret::Sequoia(Box::new(key.clone().into_keypair()?))
            }
            _ => bail!("No deterministic signer for a {} key", key.pk_algo()),
        };
        let public = key.clone().parts_into_public().role_into_unspecified();
        Ok(Self { public, secret })
    }
}

impl Signer for DerivedSigner {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        &self.public
    }

    fn acceptable_hashes(&self) -> &[HashAlgorithm] {
        match &self.secret {
            Secret::P256(_) => &P256_HASHES,
            Secret::Sequoia(pair) => pair.acceptable_hashes(),
            #[cfg(test)]
            Secret::Varying(..) => &P256_HASHES,
        }
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8]) -> Result<mpi::Signature> {
        let signature = self.sign_once(hash_algo, digest)?;
        if self.sign_once(hash_algo, digest)? != signature {
            bail!(
                "Two signatures by {} of the same digest differ, and neither was used; this \
                 points at a fault in the machine, so do not use output made on it",
                self.public.fingerprint()
            );
        }
        verified(&self.public, signature, hash_algo, digest)
    }
}

impl DerivedSigner {
    /// One signature, unchecked
    fn sign_once(&mut self, hash_algo: HashAlgorithm, digest: &[u8]) -> Result<mpi::Signature> {
        match &mut self.secret {
            Secret::P256(secret) => sign_p256(secret, hash_algo, digest),
            Secret::Sequoia(pair) => pair.sign(hash_algo, digest),
            #[cfg(test)]
            Secret::Varying(secret, calls) => {
                *calls += 1;
                let mut k = p256::FieldBytes::default();
                k[31] = *calls;
                let k = p256::NonZeroScalar::from_repr(k).unwrap();
                let (signature, _) =
                    ecdsa::hazmat::sign_prehashed(secret.as_nonzero_scalar(), &k, digest)?;
                let (r, s) = signature.split_bytes();
                Ok(mpi::Signature::ECDSA { r: MPI::new(&r), s: MPI::new(&s) })
            }
        }
    }
}

/// The P-256 secret of `key`, from its scalar
///
/// The MPI encoding drops leading zero bytes, one key in 256 loses one. They are put back
/// here rather than left to `SigningKey::from_slice`, which pads a scalar of 24 to 31 bytes in
/// time that depends on its length, and refuses a shorter one.
fn p256_secret<R: key::KeyRole>(key: &Key<key::SecretParts, R>) -> Result<SigningKey> {
    let SecretKeyMaterial::Unencrypted(material) = key.secret() else {
        bail!("The P-256 key {} is encrypted", key.fingerprint())
    };
    material.map(|material| {
        let mpi::SecretKeyMaterial::ECDSA { scalar } = material else {
            bail!("The P-256 key {} holds no ECDSA scalar", key.fingerprint())
        };
        let value = scalar.value();
        let offset = P256_SCALAR
            .checked_sub(value.len())
            .ok_or_else(|| anyhow!("A P-256 scalar of {} bytes", value.len()))?;
        let mut bytes = Zeroizing::new([0u8; P256_SCALAR]);
        bytes[offset..].copy_from_slice(value);
        Ok(SigningKey::from_slice(&bytes[..])?)
    })
}

/// Sign `digest` with an RFC 6979 nonce whose HMAC runs on the signature's hash
fn sign_p256(
    secret: &SigningKey,
    hash_algo: HashAlgorithm,
    digest: &[u8],
) -> Result<mpi::Signature> {
    // Borrowed, not copied: a `NonZeroScalar` is `Copy` and is never wiped, the key is on drop
    let scalar = secret.as_nonzero_scalar();
    let (signature, _) = match hash_algo {
        HashAlgorithm::SHA256 => {
            sign_prehashed_rfc6979::<NistP256, sha2::Sha256>(scalar, digest, &[])
        }
        HashAlgorithm::SHA384 => {
            sign_prehashed_rfc6979::<NistP256, sha2::Sha384>(scalar, digest, &[])
        }
        HashAlgorithm::SHA512 => {
            sign_prehashed_rfc6979::<NistP256, sha2::Sha512>(scalar, digest, &[])
        }
        other => bail!("P-256 signs over SHA-256, SHA-384 or SHA-512, not {other}"),
    };
    let (r, s) = signature.split_bytes();
    Ok(mpi::Signature::ECDSA { r: MPI::new(&r), s: MPI::new(&s) })
}

/// `signature` if it verifies under `public`, and an error otherwise
fn verified(
    public: &Key<key::PublicParts, key::UnspecifiedRole>,
    signature: mpi::Signature,
    hash_algo: HashAlgorithm,
    digest: &[u8],
) -> Result<mpi::Signature> {
    public
        .verify(&signature, hash_algo, digest)
        .map_err(|err| {
            anyhow!(
                "A signature by {} came out invalid and was withheld ({err}); this points at a \
             fault in the machine, so do not use output made on it",
                public.fingerprint()
            )
        })?;
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    use openpgp::crypto::mpi::ProtectedMPI;
    use openpgp::packet::key::Key4;
    use openpgp::types::PublicKeyAlgorithm;

    use p256::SecretKey;

    use sha2_ecdsa::Digest;

    use std::time::SystemTime;

    /// A P-256 signing key with scalar `x`, built as `pgp::keys` builds one
    fn p256_key(x: &[u8; 32]) -> Key<key::SecretParts, key::PrimaryRole> {
        let secret = SecretKey::from_slice(x).unwrap();
        let point = secret.public_key().to_sec1_bytes();
        Key4::with_secret(
            SystemTime::UNIX_EPOCH,
            PublicKeyAlgorithm::ECDSA,
            mpi::PublicKey::ECDSA {
                curve: Curve::NistP256,
                q: MPI::new_point(&point[1..33], &point[33..65], 256),
            },
            mpi::SecretKeyMaterial::ECDSA { scalar: ProtectedMPI::from(x.to_vec()) }.into(),
        )
        .unwrap()
        .into()
    }

    fn sign(x: &[u8; 32], hash_algo: HashAlgorithm, digest: &[u8]) -> Vec<u8> {
        let key = p256_key(x);
        let mut signer = DerivedSigner::new(&key).unwrap();
        let signature = signer.sign(hash_algo, digest).unwrap();
        key.verify(&signature, hash_algo, digest).unwrap();
        let mpi::Signature::ECDSA { r, s } = signature else {
            panic!("not an ECDSA signature")
        };
        [r.value_padded(32).unwrap(), s.value_padded(32).unwrap()].concat()
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 6979 appendix A.2.5, through the signer and sequoia's verification
    #[test]
    fn signs_the_rfc_6979_vectors() {
        let x: [u8; 32] = hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")
            .try_into()
            .unwrap();
        let vectors = [
            (
                HashAlgorithm::SHA256,
                sha2::Sha256::digest(b"sample").to_vec(),
                "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716\
                 F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
            ),
            (
                HashAlgorithm::SHA384,
                sha2::Sha384::digest(b"sample").to_vec(),
                "0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719\
                 4861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954",
            ),
            (
                HashAlgorithm::SHA512,
                sha2::Sha512::digest(b"sample").to_vec(),
                "8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00\
                 2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE",
            ),
            (
                HashAlgorithm::SHA512,
                sha2::Sha512::digest(b"test").to_vec(),
                "461D93F31B6540894788FD206C07CFA0CC35F46FA3C91816FFF1040AD1581A04\
                 39AF9F15DE0DB8D97E72719C74820D304CE5226E32DEDAE67519E840D1194E55",
            ),
        ];
        for (hash_algo, digest, expected) in vectors {
            let expected: String = expected.split_whitespace().collect();
            assert_eq!(sign(&x, hash_algo, &digest), hex(&expected), "{hash_algo}");
        }
    }

    /// A scalar whose MPI encoding lost leading zero bytes signs as the full scalar does
    #[test]
    fn pads_a_short_scalar() {
        let digest = sha2::Sha512::digest(b"a certification").to_vec();
        // Nine zeros leave 23 bytes, which `SigningKey::from_slice` would refuse
        for zeros in [1, 2, 9] {
            let mut x = [0x5au8; 32];
            x[..zeros].fill(0);

            let key = SigningKey::from_slice(&x).unwrap();
            let (expected, _) = sign_prehashed_rfc6979::<NistP256, sha2::Sha512>(
                key.as_nonzero_scalar(),
                &digest,
                &[],
            );
            let (r, s) = expected.split_bytes();
            assert_eq!(
                sign(&x, HashAlgorithm::SHA512, &digest),
                [r.as_slice(), s.as_slice()].concat(),
                "{zeros} leading zero bytes"
            );
        }
    }

    #[test]
    fn refuses_other_hashes() {
        let mut signer = DerivedSigner::new(&p256_key(&[0x5a; 32])).unwrap();
        for hash_algo in [
            HashAlgorithm::SHA224,
            HashAlgorithm::SHA1,
            HashAlgorithm::SHA3_512,
        ] {
            let digest = vec![0x42; hash_algo.digest_size().unwrap()];
            assert!(signer.sign(hash_algo, &digest).is_err(), "{hash_algo} signed");
        }
    }

    #[test]
    fn withholds_an_invalid_signature() {
        let key = p256_key(&[0x5a; 32]);
        let public = key.clone().parts_into_public().role_into_unspecified();
        let digest = sha2::Sha512::digest(b"a revocation").to_vec();
        let mpi::Signature::ECDSA { r, s } = DerivedSigner::new(&key)
            .unwrap()
            .sign(HashAlgorithm::SHA512, &digest)
            .unwrap()
        else {
            panic!("not an ECDSA signature")
        };

        // One flipped bit of s, as a fault would leave it
        let mut faulted = s.value().to_vec();
        faulted[7] ^= 0x10;
        let faulted = mpi::Signature::ECDSA { r: r.clone(), s: MPI::new(&faulted) };
        assert!(verified(&public, faulted, HashAlgorithm::SHA512, &digest).is_err());

        let valid = mpi::Signature::ECDSA { r, s };
        assert!(verified(&public, valid, HashAlgorithm::SHA512, &digest).is_ok());
    }

    /// A key whose public half belongs to another secret signs nothing: the signature does
    /// not verify, and `sign` withholds it, on both arms
    #[test]
    fn withholds_a_signature_its_public_key_refuses() {
        let mixed = |public: Key<key::SecretParts, key::PrimaryRole>,
                     secret: Key<key::SecretParts, key::PrimaryRole>| {
            let key: Key<key::SecretParts, key::PrimaryRole> = Key4::with_secret(
                SystemTime::UNIX_EPOCH,
                public.pk_algo(),
                public.mpis().clone(),
                secret.secret().clone(),
            )
            .unwrap()
            .into();
            key
        };
        let ed25519 = |seed: u8| -> Key<key::SecretParts, key::PrimaryRole> {
            Key4::import_secret_ed25519(&[seed; 32], SystemTime::UNIX_EPOCH)
                .unwrap()
                .into()
        };
        let digest = sha2::Sha512::digest(b"a binding").to_vec();

        for key in [
            mixed(p256_key(&[0x5b; 32]), p256_key(&[0x5a; 32])),
            mixed(ed25519(0x5b), ed25519(0x5a)),
        ] {
            let mut signer = DerivedSigner::new(&key).unwrap();
            assert!(
                signer.sign(HashAlgorithm::SHA512, &digest).is_err(),
                "{} signed with a foreign public key",
                key.pk_algo()
            );
        }
    }

    /// Two runs that disagree are refused, though each signature verifies on its own
    #[test]
    fn withholds_signatures_that_differ() {
        let x = [0x5a; 32];
        let key = p256_key(&x);
        let mut signer = DerivedSigner::new(&key).unwrap();
        signer.secret = Secret::Varying(SigningKey::from_slice(&x).unwrap(), 0);
        let digest = sha2::Sha512::digest(b"a certification").to_vec();

        let single = signer.sign_once(HashAlgorithm::SHA512, &digest).unwrap();
        key.verify(&single, HashAlgorithm::SHA512, &digest).unwrap();
        assert!(signer.sign(HashAlgorithm::SHA512, &digest).is_err());
    }
}
