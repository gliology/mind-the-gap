use crate::seed::{base64_encode, Seed256, Seed256Derive};

use std::convert::TryFrom;
use std::time::{Duration, SystemTime};

use anyhow::anyhow;

use zeroize::{Zeroize, Zeroizing};

use openpgp::cert::{Cert, CertRevocationBuilder};
use openpgp::crypto::Password;
use openpgp::packet::key::Key4;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::{self, key, Key, UserID};
use openpgp::policy::StandardPolicy;
use openpgp::types::{
    Features, HashAlgorithm, KeyFlags, ReasonForRevocation, SignatureType, SymmetricAlgorithm,
};
use openpgp::{Packet, Result as PGPResult};
use sequoia_openpgp as openpgp;

use openpgp_card_sequoia::state::Open;
use openpgp_card_sequoia::types::{Error as CardError, KeyType, TouchPolicy};
use openpgp_card_sequoia::{sq_util, Card};

use openpgp_card_pcsc::PcscBackend;

type SecretPrimaryKey = Key<key::SecretParts, key::PrimaryRole>;
type SecretSubKey = Key<key::SecretParts, key::SubordinateRole>;

///Subkeys to export
pub const DEFAULT_KEY_TYPES: [KeyType; 3] = [KeyType::Signing, KeyType::Decryption, KeyType::Authentication];

/// Helper to create primary key-based signature builder including metadata.
fn new_primary_sbuilder(stype: SignatureType, ctime: SystemTime) -> PGPResult<SignatureBuilder> {
    SignatureBuilder::new(stype)
        .set_features(Features::sequoia())?
        .set_hash_algo(HashAlgorithm::SHA512)
        .set_key_flags(KeyFlags::empty().set_certification())?
        .set_key_validity_period(None)?
        .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256])?
        .set_preferred_symmetric_algorithms(vec![
            SymmetricAlgorithm::AES256,
            SymmetricAlgorithm::AES128,
        ])?
        .set_signature_creation_time(ctime)
}

/// Config to create an ed25519/cv25519 user cert
pub struct SeededSmartcard {
    /// Seed used for primary key
    seed: Seed256,

    /// Identifier of the subkey set to generate
    subkey: Option<Zeroizing<String>>,

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

    /// Smartcard serial to which to export (or auto)
    card_target: Option<String>,
}

impl SeededSmartcard {
    pub fn new(seed: Seed256, subkey: Option<Zeroizing<String>>, name: String) -> Self {
        SeededSmartcard {
            seed,
            subkey,
            name,
            pin: None,
            creation_time: None,
            subkey_creation_time: None,
            subkey_validity: None,
            userids: vec![],
            card_target: None,
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

    /// Set serial of smartcard to which to export
    pub fn to_smartcard(mut self, target: Option<&str>) -> Self {
        self.card_target = target.map(ToString::to_string);
        self
    }

    /// Generate certificate and revocation signature
    pub fn generate(self) -> PGPResult<(Cert, Packet)> {
        // Determine creation time
        let creation_time = self
            .creation_time
            .unwrap_or(SystemTime::UNIX_EPOCH + Duration::from_secs(1));

        // Generate and self-sign primary key.
        let primary: SecretPrimaryKey =
            Key4::import_secret_ed25519(&self.seed.derive(Some(&[0x01])), creation_time)?.into();

        let sig = new_primary_sbuilder(SignatureType::DirectKey, creation_time)?;

        let mut signer = primary
            .clone()
            .into_keypair()
            .expect("key generated above has a secret");
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
        for (i, uid) in self.userids.into_iter().enumerate() {
            let mut sig =
                new_primary_sbuilder(SignatureType::PositiveCertification, creation_time)?;

            if i == 0 {
                sig = sig.set_primary_userid(true)?;
            }

            let signature = uid.bind(&mut signer, &cert, sig)?;
            cert = cert.insert_packets(vec![Packet::from(uid), signature.into()])?;
        }

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

        let mut subseed = self.seed.derive(self.subkey.as_ref().map(|k| k.as_bytes()));

        for (flags, code) in subkeys.iter() {
            // Derive subkey specific seed and turn into key
            let mut seed = subseed.derive(Some(&code.to_le_bytes()));

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

        subseed.zeroize();

        // Generate and sign revoaction certificate
        let revocation: Packet = CertRevocationBuilder::new()
            .set_signature_creation_time(creation_time)?
            .set_reason_for_revocation(ReasonForRevocation::Unspecified, b"Unspecified")?
            .build(&mut signer, &cert, None)?
            .into();

        // Only export to smartcard if targetted
        if let Some(ref target) = self.card_target {
            // Determine if smartcard is available
            let mut card: Card<Open> = match &target[..] {
                "auto" => {
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
                serial => {
                    let backend = PcscBackend::open_by_ident(serial, None)?;
                    backend.into()
                }
            };

            // Establish connection and receive metadata
            let mut transaction = card.transaction()?;
            println!(
                "Connecting to smartcard '{}'",
                transaction.application_identifier()?.ident()
            );

            // Factory reset smartcard
            transaction.factory_reset()?;

            // Change user pin if it was specified
            if let Some(ref pin) = self.pin.as_ref() {
                pin.map(|p| transaction.change_user_pin(b"123456", p))?;
            }

            // Set new admin and user pin TODO: derivation path debatable
            let admin_pin = base64_encode(&self.seed.derive(Some(b"admin")));
            transaction.change_admin_pin(b"12345678", &admin_pin.as_bytes())?;

            // Authenticate as admin
            transaction.verify_admin(admin_pin.as_bytes())?;
            let mut admin = transaction.admin_card().expect("verify admin did not fail");

            // TODO: Set language, gender, etc.
            admin.set_name(&self.name)?;
            admin.set_lang(&[['e', 'n'].into()])?;

            //For each subkey...
            let p = &StandardPolicy::new();
            for kt in &DEFAULT_KEY_TYPES {
                if let Some(vka) = sq_util::subkey_by_type(&cert, p, *kt)? {
                    // ... upload keys to smartcard ...
                    println!("- Uploading {:?} key: {}", *kt, vka.key());
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
                    Err(anyhow!("{:?} key could not be found", *kt))?
                }
            }
            println!();
        }

        Ok((cert, revocation))
    }
}
