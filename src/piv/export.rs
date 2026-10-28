//! PIV keys out of the gap: PKCS#8, encrypted under a passphrase.
//!
//! For reading what was encrypted to a key that no card holds any more, or for escrow. The
//! encryption is PBES2 (RFC 8018) with PBKDF2-HMAC-SHA256 and AES-256-CBC, which is what
//! `openssl pkcs8 -topk8` writes by default and what mail clients import, once wrapped in
//! PKCS#12 with the certificate. Unlike everything else here it is not derived: the salt and
//! the IV are random, so each export is its own file.

use super::SeededSmartcard;
use super::algorithms::{OID_ED25519, OID_X25519};
use super::keys::{SlotKey, SlotSecret};
use crate::role::KeyRole;

use anyhow::{Result, anyhow, bail};

use der::asn1::OctetString;
use der::oid::ObjectIdentifier;
use der::{Any, Encode, EncodePem, Sequence};

use spki::AlgorithmIdentifierOwned;

use yubikey::piv::AlgorithmId;

use zeroize::Zeroizing;

/// PBES2, RFC 8018 appendix A.4
const OID_PBES2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.13");
/// PBKDF2, RFC 8018 appendix A.2
const OID_PBKDF2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.12");
/// HMAC-SHA256, RFC 8018 appendix B.1.2
const OID_HMAC_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.2.9");
/// AES-256 in CBC mode, RFC 8018 appendix B.2.5
const OID_AES256_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42");

/// PBKDF2 iterations: OWASP's figure for HMAC-SHA256, which a passphrase typed by a person
/// needs against offline guessing
const ITERATIONS: u32 = 600_000;

/// PBKDF2-params, RFC 8018 appendix A.2; the key length is left out, AES-256 fixes it
#[derive(Sequence)]
struct Pbkdf2Params {
    salt: OctetString,
    iteration_count: u32,
    prf: AlgorithmIdentifierOwned,
}

/// PBES2-params, RFC 8018 appendix A.4
#[derive(Sequence)]
struct Pbes2Params {
    key_derivation_func: AlgorithmIdentifierOwned,
    encryption_scheme: AlgorithmIdentifierOwned,
}

/// EncryptedPrivateKeyInfo, RFC 5958 section 3
#[derive(Sequence)]
struct EncryptedPrivateKeyInfo {
    encryption_algorithm: AlgorithmIdentifierOwned,
    encrypted_data: OctetString,
}

impl der::pem::PemLabel for EncryptedPrivateKeyInfo {
    const PEM_LABEL: &'static str = "ENCRYPTED PRIVATE KEY";
}

impl SlotKey {
    /// The key as a PKCS#8 PrivateKeyInfo, DER encoded, in its algorithm's standard form
    fn pkcs8(&self) -> Result<Zeroizing<Vec<u8>>> {
        // The curves' crates and rsa share one pkcs8, re-exported by rsa
        use rsa::pkcs8::EncodePrivateKey;
        let document = match (&self.secret, self.algorithm) {
            (SlotSecret::Rsa(key), _) => key.to_pkcs8_der()?,
            (SlotSecret::Bytes(bytes), AlgorithmId::EccP256) => {
                p256::SecretKey::from_slice(bytes.as_slice())?.to_pkcs8_der()?
            }
            (SlotSecret::Bytes(bytes), AlgorithmId::EccP384) => {
                p384::SecretKey::from_slice(bytes.as_slice())?.to_pkcs8_der()?
            }
            // RFC 8410 wraps the 32 bytes in an OCTET STRING, which goes into the
            // PrivateKeyInfo's own. Built here for both curves: x25519-dalek has no PKCS#8,
            // and ed25519-dalek writes version 2 with the public key, which OpenSSL 1.1 and
            // other older readers refuse
            (
                SlotSecret::Bytes(bytes),
                algorithm @ (AlgorithmId::Ed25519 | AlgorithmId::X25519),
            ) => {
                let oid = if algorithm == AlgorithmId::Ed25519 {
                    OID_ED25519
                } else {
                    OID_X25519
                };
                let inner = Zeroizing::new(OctetString::new(bytes.as_slice())?.to_der()?);
                let info = rsa::pkcs8::PrivateKeyInfoRef::new(
                    spki::AlgorithmIdentifierRef { oid, parameters: None },
                    rsa::pkcs8::der::asn1::OctetStringRef::new(&inner)?,
                );
                return Ok(Zeroizing::new(info.to_der()?));
            }
            (_, other) => bail!("No PKCS#8 form for {other:?} keys"),
        };
        Ok(Zeroizing::new(document.as_bytes().to_vec()))
    }
}

/// A PKCS#8 key encrypted under `passphrase`, PEM encoded
fn encrypt(plain: &[u8], passphrase: &str) -> Result<Zeroizing<String>> {
    use aes::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};

    let mut salt = [0u8; 16];
    let mut iv = [0u8; 16];
    getrandom::fill(&mut salt)
        .and_then(|()| getrandom::fill(&mut iv))
        .map_err(|err| anyhow!("No OS entropy for the export's salt: {err}"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(passphrase.as_bytes(), &salt, ITERATIONS, key.as_mut());
    let encrypted = cbc::Encryptor::<aes::Aes256>::new((&*key).into(), &iv.into())
        .encrypt_padded_vec::<Pkcs7>(plain);

    let prf = AlgorithmIdentifierOwned { oid: OID_HMAC_SHA256, parameters: Some(Any::null()) };
    let kdf = Pbkdf2Params {
        salt: OctetString::new(salt)?,
        iteration_count: ITERATIONS,
        prf,
    };
    let scheme = Pbes2Params {
        key_derivation_func: AlgorithmIdentifierOwned {
            oid: OID_PBKDF2,
            parameters: Some(Any::encode_from(&kdf)?),
        },
        encryption_scheme: AlgorithmIdentifierOwned {
            oid: OID_AES256_CBC,
            parameters: Some(Any::encode_from(&OctetString::new(iv)?)?),
        },
    };
    let info = EncryptedPrivateKeyInfo {
        encryption_algorithm: AlgorithmIdentifierOwned {
            oid: OID_PBES2,
            parameters: Some(Any::encode_from(&scheme)?),
        },
        encrypted_data: OctetString::new(encrypted)?,
    };
    Ok(Zeroizing::new(info.to_pem(der::pem::LineEnding::LF)?))
}

/// A PKCS#8 key as is, PEM encoded
fn unencrypted(plain: &[u8]) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(der::pem::encode_string("PRIVATE KEY", der::pem::LineEnding::LF, plain)?))
}

impl SeededSmartcard {
    /// The chosen keys in PKCS#8, PEM encoded, each with its certificate: encrypted under
    /// `passphrase`, or as they are without one
    pub fn secret_keys(
        &self,
        passphrase: Option<&str>,
    ) -> Result<Vec<(KeyRole, Zeroizing<String>, String)>> {
        let chain = self.generate_chain()?;
        self.keys
            .iter()
            .zip(&chain.leaves)
            .map(|(&role, (_, cert))| {
                let plain = self.role_key(role)?.pkcs8()?;
                let key = match passphrase {
                    Some(passphrase) => encrypt(&plain, passphrase)?,
                    None => unencrypted(&plain)?,
                };
                Ok((role, key, cert.to_pem(der::pem::LineEnding::LF)?))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ed25519 goes out as PKCS#8 version 1, the seed alone, which every reader takes, and
    /// reads back as the same key
    #[test]
    fn ed25519_is_written_as_version_one() {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        use rsa::pkcs8::der::Decode;

        let seed = [7u8; 32];
        let key = SlotKey {
            algorithm: AlgorithmId::Ed25519,
            secret: SlotSecret::Bytes(Zeroizing::new(seed.to_vec())),
        };
        let der = key.pkcs8().unwrap();
        let info = rsa::pkcs8::PrivateKeyInfoRef::from_der(&der).unwrap();
        assert_eq!(info.version(), rsa::pkcs8::Version::V1);
        assert_eq!(info.algorithm.oid, OID_ED25519);
        let read = ed25519_dalek::SigningKey::from_pkcs8_der(&der).unwrap();
        assert_eq!(read.to_bytes(), seed);
    }
}
