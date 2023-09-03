use crate::seed::{Seed256, Seed256Derive};

use std::convert::TryFrom;
use std::time::{Duration, SystemTime};

use anyhow::{bail, Result};

use zeroize::{Zeroize, Zeroizing};

use sequoia_openpgp as openpgp;
use openpgp::{Packet, Result as PGPResult};
use openpgp::cert::{Cert, CertRevocationBuilder};
use openpgp::crypto::Password;
use openpgp::packet::{self, key, Key, UserID};
use openpgp::packet::key::Key4;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::policy::StandardPolicy;
use openpgp::types::{
    Features, HashAlgorithm, KeyFlags, ReasonForRevocation, SignatureType, SymmetricAlgorithm,
};

use openpgp_card::{Error as CardError, SmartcardError};
use openpgp_card_pcsc::PcscBackend;

use openpgp_card_sequoia::sq_util;
use openpgp_card_sequoia::state::Open;
use openpgp_card_sequoia::types::{KeyType, TouchPolicy};
use openpgp_card_sequoia::Card;

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

    let cards = match PcscBackend::cards(None) {
        // Ignore missing reader and return empty list instead
        Err(CardError::Smartcard(SmartcardError::NoReaderFoundError)) => {
            Ok(Vec::<PcscBackend>::new())
        }
        other => other,
    }?;

    if cards.is_empty() {
        println!(" - None");
        println!();
    }

    for backend in cards {
        let mut card: Card<Open> = backend.into();
        let mut transaction = card.transaction()?;

        println!(" - Card {}", transaction.application_identifier()?.ident(),);

        if let Some(name) = transaction.cardholder_name()? {
            println!("   Cardholder: {}", name);
        }

        for kt in DEFAULT_KEY_TYPES {
            if let Some(sign) = transaction.public_key(kt)? {
                println!("   {:?} key: {}", kt, sign.fingerprint());
            }
        }

        println!();
    }

    Ok(())
}

/// Config to create an ed25519/cv25519 user cert
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
    pub fn check(&self, target: Option<String>) -> Result<()> {
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
            cert = cert.insert_packets(signature.clone())?;
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

        let mut cert = Cert::try_from(vec![
            Packet::SecretKey({
                let mut primary = primary.clone();
                if let Some(ref pin) = self.pin.as_ref() {
                    primary.secret_mut().encrypt_in_place(pin)?;
                }
                primary
            }),
            sig.into(),
        ])?;

        // Sign and add user ids
        for (i, uid) in self.userids.iter().enumerate() {
            let mut sig = self.new_primary_sbuilder(SignatureType::PositiveCertification)?;

            if i == 0 {
                sig = sig.set_primary_userid(true)?;
            }

            let signature = uid.bind(&mut signer, &cert, sig)?;
            cert = cert.insert_packets(vec![Packet::from(uid.clone()), signature.into()])?;
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

            // Apply password protection
            if let Some(ref pin) = self.pin.as_ref() {
                subkey.secret_mut().encrypt_in_place(pin)?;
            }

            // Add everything to certificate
            cert = cert.insert_packets(vec![Packet::SecretSubkey(subkey), signature.into()])?;
        }

        Ok(cert)
    }

    /// Upload subkeys to a smartcard and reset and lock smartcard in the process
    fn upload_subkeys(&self, cert: &Cert, target: Option<String>) -> PGPResult<()> {
        // Determine smartcard to which to connect
        let mut card: Card<Open> = match target {
            Some(serial) => {
                let backend = PcscBackend::open_by_ident(&serial, None)?;
                backend.into()
            }
            None => {
                let mut cards = PcscBackend::cards(None)?;

                if cards.len() == 1 {
                    cards.pop().unwrap().into()
                } else if cards.is_empty() {
                    Err(CardError::InternalError(
                        "No card detected, please insert card".to_string(),
                    ))?
                } else {
                    Err(CardError::InternalError(format!(
                        "Multiple cards ({}) detected, please specify card by serial",
                        cards.len()
                    )))?
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
            pin.map(|p| transaction.change_user_pin(b"123456", p))?;
        }

        // Set new admin and pin TODO: derivation path debatable
        let admin_pin = self.subseed.base64(Some(b"admin"));
        transaction.change_admin_pin(b"12345678", &admin_pin.as_bytes())?;

        // Authenticate as admin
        transaction.verify_admin(admin_pin.as_bytes())?;
        let mut admin = transaction.admin_card().expect("verify admin did not fail");

        // TODO: Set language, gender, etc.
        admin.set_name(&self.name)?;
        admin.set_lang(&[['e', 'n'].into()])?;

        // For each subkey...
        let p = &StandardPolicy::new();
        for kt in &DEFAULT_KEY_TYPES {
            if let Some(vka) = sq_util::subkey_by_type(&cert, p, *kt)? {
                // ... upload keys to smartcard ...
                log::info!("Uploading {:?} key: {}", *kt, vka.key());
                if let Some(ref pin) = self.pin.as_ref() {
                    let decrypted: Zeroizing<String> =
                        pin.map(|p| String::from_utf8_lossy(p).to_string()).into();
                    admin.upload_key(vka, *kt, Some(decrypted.to_string()))?;
                } else {
                    admin.upload_key(vka, *kt, None)?;
                }

                // ... and set pin policy
                admin.set_uif(*kt, TouchPolicy::Fixed)?;
            } else {
                bail!("{:?} key could not be found", *kt)
            }
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
