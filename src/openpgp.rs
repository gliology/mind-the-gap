use crate::seed::{Seed256, Seed256Derive};

use std::convert::TryFrom;
use std::time::{Duration, SystemTime};

use anyhow::{bail, Result};

use zeroize::{Zeroize, Zeroizing};

use sequoia_openpgp as openpgp;
use openpgp::{Packet, Result as PGPResult};
use openpgp::cert::{Cert, CertRevocationBuilder};
use openpgp::crypto::{mpi, Password};
use openpgp::packet::{self, key, Key, UserID};
use openpgp::packet::key::Key4;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::policy::StandardPolicy;
use openpgp::types::{
    Features, HashAlgorithm, KeyFlags, ReasonForRevocation, SignatureType, SymmetricAlgorithm,
};

use secrecy::SecretString;

use card_backend_pcsc::PcscBackend;

use openpgp_card::{Card, Error as CardError};
use openpgp_card::ocard::KeyType;
use openpgp_card::ocard::algorithm::Curve;
use openpgp_card::ocard::crypto::{CardUploadableKey, EccKey, EccType, PrivateKeyMaterial};
use openpgp_card::ocard::data::{Fingerprint as CardFingerprint, KeyGenerationTime, TouchPolicy};
use openpgp_card::state::Open;

// Some use type shorthands
type SecretPrimaryKey = Key<key::SecretParts, key::PrimaryRole>;
type SecretSubKey = Key<key::SecretParts, key::SubordinateRole>;

/// Subkeys to export
pub const DEFAULT_KEY_TYPES: [KeyType; 3] = [
    KeyType::Signing,
    KeyType::Decryption,
    KeyType::Authentication,
];

/// Print list of currently available OpenPGP cards
pub fn status() -> Result<()> {
    println!("Available OpenPGP cards:");

    let backends: Vec<PcscBackend> = PcscBackend::cards(None)
        .map(|iter| iter.filter_map(Result::ok).collect())
        .unwrap_or_default();

    if backends.is_empty() {
        println!(" - None");
        println!();
    }

    for backend in backends {
        let mut card = Card::new(backend)?;
        let mut transaction = card.transaction()?;

        println!(" - Card {}", transaction.application_identifier()?.ident());

        let name = transaction.cardholder_name()?;
        if !name.is_empty() {
            println!("   Cardholder: {}", name);
        }

        for kt in DEFAULT_KEY_TYPES {
            if let Ok(Some(fp)) = transaction.fingerprint(kt) {
                println!("   {:?} key: {}", kt, fp.to_spaced_hex());
            }
        }

        println!();
    }

    Ok(())
}

/// Config to create an ed25519/cv25519 user cert
pub struct SeededSmartcard {
    /// Seed used for primary key
    seed: Seed256,

    /// Seed used for all subkeys
    subseed: Seed256,

    /// Name of the owner of the cert
    name: String,

    /// Password to use to protect smartcard and secret keys
    pin: Option<Password>,

    /// Creation time of key certificate, defaults to one second after unix epoch
    creation_time: Option<SystemTime>,

    /// Creation time of subkeys, defaults to creation time of certificate
    subkey_creation_time: Option<SystemTime>,

    /// Validity duration of subkeys
    subkey_validity: Option<Duration>,

    /// List of user ids to include in cert
    userids: Vec<packet::UserID>,
}

impl SeededSmartcard {
    /// Initialize an new seeded smartcard config
    pub fn new(seed: Seed256, subkey: Option<Zeroizing<String>>, name: String) -> Self {
        // Derive application specific root seed
        let root = seed.derive(Some(b"openpgp"));

        // Derive seed for primary and subkeys
        let seed = root.derive(Some(&[0x01]));
        let subseed = root.derive(subkey.as_ref().map(|k| k.as_bytes()));

        SeededSmartcard {
            seed,
            subseed,
            name,
            pin: None,
            creation_time: None,
            subkey_creation_time: None,
            subkey_validity: None,
            userids: vec![],
        }
    }

    /// Set password to protect secret keys
    pub fn with_pin(mut self, pin: Zeroizing<String>) -> Self {
        self.pin = Some(pin.as_str().into());
        self
    }

    /// Set certificate creation time
    pub fn with_creation_time(mut self, timestamp: SystemTime) -> Self {
        self.creation_time = Some(timestamp);
        self
    }

    /// Set subkey creation time
    pub fn with_subkey_creation_time(mut self, timestamp: SystemTime) -> Self {
        self.subkey_creation_time = Some(timestamp);
        self
    }

    /// Set subkey validity period
    pub fn with_subkey_validity(mut self, validity: Duration) -> Self {
        self.subkey_validity = Some(validity);
        self
    }

    /// Add userid to certificate
    pub fn add_email(mut self, email: &str) -> Self {
        let userid = UserID::from_address(Some(&self.name[..]), None, email).unwrap();
        self.userids.push(userid);
        self
    }

    // PUBLIC OUTPUT API

    /// Check smartcard access and export
    pub fn check(&self, _target: Option<String>) -> Result<()> {
        todo!()
    }

    /// Certify subkeys or external keys
    pub fn certify(&self, other: Option<Cert>) -> Result<Cert> {
        if let Some(cert) = other {
            self.primsign_cert(cert)
        } else {
            let cert = self.generate_primcert()?;

            // FIXME: Only add signatures here
            self.append_subcerts(cert)
        }
    }

    /// Upload secret subkeys
    pub fn upload(&self, target: Option<String>) -> Result<Cert> {
        let mut cert = self.generate_primcert()?;

        cert = self.append_subcerts(cert)?;

        self.upload_subkeys(&cert, target)?;

        Ok(cert)
    }

    /// Export all secret keys
    pub fn export(&self) -> Result<Cert> {
        let cert = self.generate_primcert()?;

        self.append_subcerts(cert)
    }

    /// Generate and sign revoaction certificate
    pub fn revoke(&self) -> Result<Packet> {
        let mut cert = self.generate_primcert()?;

        self.generate_revcert(&mut cert)
    }

    // INTERNAL API

    /// Helper to create primary key-based signature builder including metadata.
    fn new_primary_sbuilder(&self, stype: SignatureType) -> PGPResult<SignatureBuilder> {
        // Determine creation time
        let creation_time = self
            .creation_time
            .unwrap_or(SystemTime::UNIX_EPOCH + Duration::from_secs(1));

        SignatureBuilder::new(stype)
            .set_features(Features::sequoia())?
            .set_hash_algo(HashAlgorithm::SHA512)
            //.set_key_flags(KeyFlags::empty().set_certification())?
            .set_key_validity_period(None)?
            .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256])?
            .set_preferred_symmetric_algorithms(vec![
                SymmetricAlgorithm::AES256,
                SymmetricAlgorithm::AES128,
            ])?
            .set_signature_creation_time(creation_time)
    }

    /// Sign a certificate with our primary key
    fn primsign_cert(&self, mut cert: Cert) -> PGPResult<Cert> {
        // Determine creation time
        let creation_time = self
            .creation_time
            .unwrap_or(SystemTime::UNIX_EPOCH + Duration::from_secs(1));

        // Generate and self-sign primary key.
        let primary: SecretPrimaryKey =
            Key4::import_secret_ed25519(&self.seed, creation_time)?.into();

        let mut signer = primary
            .clone()
            .into_keypair()
            .expect("key generated above has a secret");

        let policy = &StandardPolicy::new();
        let cc = cert.clone();
        let vc = cc.with_policy(policy, None)?;

        for ref uid in vc.userids() {
            log::info!("Signing userid '{}'", uid.userid());

            let sig = self.new_primary_sbuilder(SignatureType::GenericCertification)?;

            let signature = uid.userid().bind(&mut signer, &cert, sig)?;

            // FIXME: Currently does not end up in export
            cert = cert.insert_packets(signature.clone()).map(|(c, _)| c)?;
        }

        Ok(cert)
    }

    /// Generate primary certificate
    fn generate_primcert(&self) -> PGPResult<Cert> {
        // Determine creation time
        let creation_time = self
            .creation_time
            .unwrap_or(SystemTime::UNIX_EPOCH + Duration::from_secs(1));

        // Generate and self-sign primary key.
        let primary: SecretPrimaryKey =
            Key4::import_secret_ed25519(&self.seed, creation_time)?.into();

        let mut signer = primary
            .clone()
            .into_keypair()
            .expect("key generated above has a secret");

        let sig = self.new_primary_sbuilder(SignatureType::DirectKey)?;
        let sig = sig.sign_direct_key(&mut signer, primary.parts_as_public())?;

        // Optionally encrypt the primary key copy for the certificate
        let mut primary_enc = primary.clone();
        if let Some(ref pin) = self.pin.as_ref() {
            primary_enc.secret_mut().encrypt_in_place(primary.parts_as_public(), pin)?;
        }

        let mut cert = Cert::try_from(vec![
            Packet::SecretKey(primary_enc),
            sig.into(),
        ])?;

        // Sign and add user ids
        for (i, uid) in self.userids.iter().enumerate() {
            let mut sig = self.new_primary_sbuilder(SignatureType::PositiveCertification)?;

            if i == 0 {
                sig = sig.set_primary_userid(true)?;
            }

            let signature = uid.bind(&mut signer, &cert, sig)?;
            cert = cert.insert_packets(vec![Packet::from(uid.clone()), signature.into()]).map(|(c, _)| c)?;
        }

        Ok(cert)
    }

    /// Append subkeys to a primary certificate
    fn append_subcerts(&self, mut cert: Cert) -> PGPResult<Cert> {
        // Determine creation time
        let creation_time = self
            .creation_time
            .unwrap_or(SystemTime::UNIX_EPOCH + Duration::from_secs(1));

        // Generate and self-sign primary key.
        let primary: SecretPrimaryKey =
            Key4::import_secret_ed25519(&self.seed, creation_time)?.into();

        let mut signer = primary
            .clone()
            .into_keypair()
            .expect("key generated above has a secret");

        // Create and sign subkeys
        let subkey_creation_time = self.subkey_creation_time.unwrap_or(creation_time);

        let subkeys: [(KeyFlags, u8); 3] = [
            (KeyFlags::empty().set_signing(), 0x02),
            (
                KeyFlags::empty()
                    .set_transport_encryption()
                    .set_storage_encryption(),
                0x0C,
            ),
            (KeyFlags::empty().set_authentication(), 0x20),
        ];

        for (flags, code) in subkeys.iter() {
            // Derive subkey specific seed and turn into key
            let mut seed = self.subseed.derive(Some(&code.to_le_bytes()));

            let mut subkey: SecretSubKey =
                if flags.for_transport_encryption() || flags.for_storage_encryption() {
                    // Curve25519 Paper, Sec. 3:
                    // A user can, for example, generate 32 uniform random bytes, clear bits 0, 1, 2 of the first
                    // byte, clear bit 7 of the last byte, and set bit 6 of the last byte.
                    seed[0] &= 0b1111_1000;
                    seed[31] &= !0b1000_0000;
                    seed[31] |= 0b0100_0000;

                    Key4::import_secret_cv25519(&seed, None, None, subkey_creation_time)?.into()
                } else {
                    Key4::import_secret_ed25519(&seed, subkey_creation_time)?.into()
                };

            seed.zeroize();

            // Sign subkey with primary
            let mut builder = SignatureBuilder::new(SignatureType::SubkeyBinding)
                .set_hash_algo(HashAlgorithm::SHA512)
                .set_signature_creation_time(subkey_creation_time)?
                .set_key_flags(flags.clone())?
                .set_key_validity_period(self.subkey_validity)?;

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
            if let Some(ref pin) = self.pin.as_ref() {
                let subkey_pub = subkey.clone();
                subkey.secret_mut().encrypt_in_place(subkey_pub.parts_as_public(), pin)?;
            }

            // Add everything to certificate
            cert = cert.insert_packets(vec![Packet::SecretSubkey(subkey), signature.into()]).map(|(c, _)| c)?;
        }

        Ok(cert)
    }

    /// Upload subkeys to a smartcard and reset and lock smartcard in the process
    fn upload_subkeys(&self, cert: &Cert, target: Option<String>) -> PGPResult<()> {
        // Determine smartcard to which to connect
        let mut card: Card<Open> = match target {
            Some(ref serial) => {
                // Find card by ident by briefly connecting to each
                let backends: Vec<PcscBackend> = PcscBackend::cards(None)?
                    .filter_map(Result::ok)
                    .collect();
                let mut found = None;
                for backend in backends {
                    let mut c = Card::new(backend)?;
                    let ident = {
                        let tx = c.transaction()?;
                        tx.application_identifier()?.ident()
                    };
                    if ident.eq_ignore_ascii_case(serial) {
                        found = Some(c);
                        break;
                    }
                }
                found.ok_or_else(|| CardError::NotFound(format!("Card '{}' not found", serial)))?
            }
            None => {
                let backends: Vec<PcscBackend> = PcscBackend::cards(None)?
                    .filter_map(Result::ok)
                    .collect();

                match backends.len() {
                    0 => bail!("No card detected, please insert card"),
                    1 => Card::new(backends.into_iter().next().unwrap())?,
                    n => bail!(
                        "Multiple cards ({}) detected, please specify card by serial",
                        n
                    ),
                }
            }
        };

        // Establish connection and receive metadata
        let mut transaction = card.transaction()?;
        log::info!(
            "Connected to smartcard '{}'",
            transaction.application_identifier()?.ident()
        );

        // Factory reset smartcard
        transaction.factory_reset()?;

        // Change user pin if it was specified
        if let Some(ref pin) = self.pin.as_ref() {
            let new_pin: Zeroizing<String> =
                pin.map(|p| String::from_utf8_lossy(p).to_string()).into();
            transaction.change_user_pin(
                SecretString::new("123456".to_string()),
                SecretString::new(AsRef::<str>::as_ref(&*new_pin).to_owned()),
            )?;
        }

        // Set new admin pin derived from subseed
        let admin_pin = self.subseed.base64(Some(b"admin"));
        let admin_pin_str: String = AsRef::<str>::as_ref(&*admin_pin).to_owned();
        transaction.change_admin_pin(
            SecretString::new("12345678".to_string()),
            SecretString::new(admin_pin_str.clone()),
        )?;

        // Authenticate as admin (combines verify + elevation in one step)
        let mut admin = transaction.to_admin_card(SecretString::new(admin_pin_str))?;

        // TODO: Set language, gender, etc.
        admin.set_cardholder_name(&self.name)?;
        admin.set_lang(&[['e', 'n'].into()])?;

        // Map of (KeyType, is_encryption, seed_code)
        let key_map: [(KeyType, bool, u8); 3] = [
            (KeyType::Signing, false, 0x02),
            (KeyType::Decryption, true, 0x0C),
            (KeyType::Authentication, false, 0x20),
        ];

        let p = &StandardPolicy::new();
        let vc = cert.with_policy(p, None)?;

        for (kt, is_enc, code) in &key_map {
            // Find the matching subkey in the cert to get fingerprint, timestamp, and public bytes
            let subkey = vc
                .keys()
                .subkeys()
                .find(|k| {
                    k.key_flags().map_or(false, |flags| {
                        if *is_enc {
                            flags.for_storage_encryption() || flags.for_transport_encryption()
                        } else if *code == 0x02 {
                            flags.for_signing()
                        } else {
                            flags.for_authentication()
                        }
                    })
                })
                .ok_or_else(|| anyhow::anyhow!("{:?} key not found in cert", kt))?;

            // Extract fingerprint as 20-byte array
            let fp_bytes: [u8; 20] = subkey
                .key()
                .fingerprint()
                .as_bytes()
                .try_into()
                .map_err(|_| anyhow::anyhow!("Unexpected fingerprint length"))?;

            // Extract creation timestamp
            let ts = subkey
                .key()
                .creation_time()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|e| anyhow::anyhow!("Key creation time error: {}", e))?
                .as_secs() as u32;

            // Extract public key bytes from cert MPI (0x40-prefixed for 25519 keys)
            let pub_bytes = match subkey.key().mpis() {
                mpi::PublicKey::EdDSA { q, .. } => q.value().to_vec(),
                mpi::PublicKey::ECDH { q, .. } => q.value().to_vec(),
                _ => bail!("{:?} key has unexpected algorithm in cert", kt),
            };

            // Re-derive the raw private seed bytes
            let mut seed = self.subseed.derive(Some(&code.to_le_bytes()));

            // Apply Cv25519 clamping for decryption key
            if *is_enc {
                seed[0] &= 0b1111_1000;
                seed[31] &= !0b1000_0000;
                seed[31] |= 0b0100_0000;
            }

            let (oid, ecc_type) = if *is_enc {
                (Curve::Curve25519.oid(), EccType::ECDH)
            } else {
                (Curve::Ed25519.oid(), EccType::EdDSA)
            };

            let key = RawEccKey {
                oid,
                private_bytes: Zeroizing::new(seed.to_vec()),
                public_bytes: pub_bytes,
                ecc_type,
                fingerprint: CardFingerprint::from(fp_bytes),
                timestamp: KeyGenerationTime::from(ts),
            };

            seed.zeroize();

            log::info!("Uploading {:?} key", kt);
            admin.import_key(Box::new(key), *kt)?;

            // Set touch policy (Cached: one touch valid for ~15s)
            admin.set_touch_policy(*kt, TouchPolicy::Cached)?;
        }

        Ok(())
    }

    /// Generate revocation certificate
    fn generate_revcert(&self, cert: &mut Cert) -> PGPResult<Packet> {
        // Determine creation time
        let creation_time = self
            .creation_time
            .unwrap_or(SystemTime::UNIX_EPOCH + Duration::from_secs(1));

        // Derive signing key
        let primary: SecretPrimaryKey =
            Key4::import_secret_ed25519(&self.seed, creation_time)?.into();

        let mut signer = primary
            .clone()
            .into_keypair()
            .expect("key generated above has a secret");

        // Sign revocation certificate
        let revocation: Packet = CertRevocationBuilder::new()
            .set_signature_creation_time(creation_time)?
            .set_reason_for_revocation(ReasonForRevocation::Unspecified, b"Unspecified")?
            .build(&mut signer, &cert, None)?
            .into();

        Ok(revocation)
    }
}

/// Raw ECC key material for uploading to an OpenPGP card.
/// Implements both `CardUploadableKey` and `EccKey`.
struct RawEccKey {
    oid: &'static [u8],
    private_bytes: Zeroizing<Vec<u8>>,
    public_bytes: Vec<u8>,
    ecc_type: EccType,
    fingerprint: CardFingerprint,
    timestamp: KeyGenerationTime,
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
        self.timestamp.clone()
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

    fn private(&self) -> Vec<u8> {
        self.private_bytes.to_vec()
    }

    fn public(&self) -> Vec<u8> {
        self.public_bytes.clone()
    }

    fn ecc_type(&self) -> EccType {
        self.ecc_type
    }
}
