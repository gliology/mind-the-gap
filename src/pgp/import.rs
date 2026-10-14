//! Key material in the shapes `openpgp-card` uploads.

use anyhow::{Result, anyhow, bail};

use zeroize::Zeroizing;

use openpgp_card::ocard::crypto::{CardUploadableKey, EccKey, EccType, PrivateKeyMaterial, RSAKey};

use openpgp_card::ocard::data::{Fingerprint as CardFingerprint, KeyGenerationTime};

use crypto_bigint::BoxedUint;
use rsa::RsaPrivateKey;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};

/// RSA key material for uploading to an OpenPGP card, in every form the card's import
/// format may ask for: `openpgp-card` picks the fields from the card's algorithm attributes.
pub(super) struct RawRsaKey {
    material: Box<RsaParts>,
    fingerprint: CardFingerprint,
    timestamp: KeyGenerationTime,
}

/// The big-endian numbers of one RSA key, each in its own wiping allocation
#[derive(Clone)]
struct RsaParts {
    e: Vec<u8>,
    p: Zeroizing<Vec<u8>>,
    q: Zeroizing<Vec<u8>>,
    pq: Zeroizing<Vec<u8>>,
    dp1: Zeroizing<Vec<u8>>,
    dq1: Zeroizing<Vec<u8>>,
    n: Vec<u8>,
}

impl RawRsaKey {
    pub(super) fn new(
        key: &RsaPrivateKey,
        fingerprint: CardFingerprint,
        timestamp: KeyGenerationTime,
    ) -> Result<Self> {
        let mut key = key.clone();
        key.precompute()?;
        let [p, q] = key.primes() else {
            bail!("An RSA key without two primes")
        };
        let secret = |value: Option<&BoxedUint>| -> Result<Zeroizing<Vec<u8>>> {
            let value = value.ok_or_else(|| anyhow!("RSA CRT values missing"))?;
            Ok(Zeroizing::new(value.to_be_bytes().into_vec()))
        };

        let material = Box::new(RsaParts {
            e: crate::rsa::PUBLIC_EXPONENT
                .to_be_bytes()
                .into_iter()
                .skip_while(|&b| b == 0)
                .collect(),
            p: secret(Some(p))?,
            q: secret(Some(q))?,
            // The card's PQ is 1/q mod p, which is the rsa crate's CRT coefficient as well
            pq: secret(key.crt_coefficient().as_ref())?,
            dp1: secret(key.dp())?,
            dq1: secret(key.dq())?,
            n: key.n().to_be_bytes().into_vec(),
        });
        Ok(RawRsaKey { material, fingerprint, timestamp })
    }
}

impl CardUploadableKey for RawRsaKey {
    fn private_key(&self) -> std::result::Result<PrivateKeyMaterial, openpgp_card::Error> {
        Ok(PrivateKeyMaterial::R(self.material.clone()))
    }

    fn timestamp(&self) -> KeyGenerationTime {
        self.timestamp
    }

    fn fingerprint(&self) -> std::result::Result<CardFingerprint, openpgp_card::Error> {
        Ok(self.fingerprint.clone())
    }
}

impl RSAKey for RsaParts {
    fn e(&self) -> &[u8] {
        &self.e
    }

    fn p(&self) -> &[u8] {
        &self.p
    }

    fn q(&self) -> &[u8] {
        &self.q
    }

    fn pq(&self) -> &[u8] {
        &self.pq
    }

    fn dp1(&self) -> &[u8] {
        &self.dp1
    }

    fn dq1(&self) -> &[u8] {
        &self.dq1
    }

    fn n(&self) -> &[u8] {
        &self.n
    }
}

/// Raw ECC key material for uploading to an OpenPGP card.
/// Implements both `CardUploadableKey` and `EccKey`.
pub(super) struct RawEccKey {
    pub(super) oid: &'static [u8],
    pub(super) private_bytes: Zeroizing<Vec<u8>>,
    pub(super) public_bytes: Vec<u8>,
    pub(super) ecc_type: EccType,
    pub(super) fingerprint: CardFingerprint,
    pub(super) timestamp: KeyGenerationTime,
}

impl CardUploadableKey for RawEccKey {
    fn private_key(&self) -> std::result::Result<PrivateKeyMaterial, openpgp_card::Error> {
        // Box self as an EccKey implementor — clone fields into a new heap-allocated instance
        Ok(PrivateKeyMaterial::E(Box::new(RawEccKeyRef {
            oid: self.oid,
            private_bytes: self.private_bytes.clone(),
            public_bytes: self.public_bytes.clone(),
            ecc_type: self.ecc_type,
        })))
    }

    fn timestamp(&self) -> KeyGenerationTime {
        self.timestamp
    }

    fn fingerprint(&self) -> std::result::Result<CardFingerprint, openpgp_card::Error> {
        Ok(self.fingerprint.clone())
    }
}

/// Inner ECC key reference, separated from `RawEccKey` to satisfy `Box<dyn EccKey>`.
struct RawEccKeyRef {
    oid: &'static [u8],
    private_bytes: Zeroizing<Vec<u8>>,
    public_bytes: Vec<u8>,
    ecc_type: EccType,
}

impl EccKey for RawEccKeyRef {
    fn oid(&self) -> &[u8] {
        self.oid
    }

    // openpgp-card 0.7 borrows the key material instead of taking owned copies, so the
    // private scalar never leaves its Zeroizing allocation on this side of the trait
    fn private(&self) -> &[u8] {
        &self.private_bytes
    }

    fn public(&self) -> &[u8] {
        &self.public_bytes
    }

    fn ecc_type(&self) -> EccType {
        self.ecc_type
    }
}
