//! Public key algorithms as X.509 names them, and the derivation algorithm a key was made with.

use crate::seed::Algorithm;

use spki::{ObjectIdentifier, SubjectPublicKeyInfoOwned};

/// id-ecPublicKey, RFC 5480, which names its curve in the parameters
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// secp256r1, RFC 5480
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// secp384r1, RFC 5480
const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
/// X25519, RFC 8410
pub(super) const OID_X25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");
/// Ed25519, RFC 8410
pub(super) const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
/// rsaEncryption, RFC 8017
const OID_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// The derivation algorithm a signing key was made with, read off its public key
pub(crate) fn algorithm_of(spki: &SubjectPublicKeyInfoOwned) -> Option<Algorithm> {
    let oid = spki.algorithm.oid;
    if oid == OID_ED25519 {
        return Some(Algorithm::Curve25519);
    }
    if oid == OID_EC_PUBLIC_KEY {
        let curve: ObjectIdentifier = spki.algorithm.parameters.as_ref()?.decode_as().ok()?;
        return match curve {
            OID_P256 => Some(Algorithm::P256),
            OID_P384 => Some(Algorithm::P384),
            _ => None,
        };
    }
    if oid == OID_RSA {
        // The modulus is a DER INTEGER inside the key; its byte length gives the size
        // closely enough to tell 2048, 3072 and 4096 apart
        let key = spki.subject_public_key.as_bytes()?;
        return match key.len() {
            250..=300 => Some(Algorithm::Rsa2048),
            380..=430 => Some(Algorithm::Rsa3072),
            510..=560 => Some(Algorithm::Rsa4096),
            _ => None,
        };
    }
    None
}
