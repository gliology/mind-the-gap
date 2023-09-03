use std::str::FromStr;

use crate::seed::{Seed256, Seed256Derive};

use anyhow::Result;

use yubikey::{Certificate, Error as CardError, MgmKey, PinPolicy, Serial, TouchPolicy, YubiKey};
use yubikey::piv::{self, AlgorithmId, ManagementSlotId, SlotId};
use yubikey::reader::Context;

use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;

use der::asn1::Ia5String;
use der::Encode;

use sha2::{Digest, Sha256};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

/// Configuration of key slots to be generated and uploaded
const DEFAULT_KEY_SLOTS: [SlotId; 4] = [
    SlotId::Authentication,
    SlotId::Signature,
    SlotId::KeyManagement,
    SlotId::CardAuthentication,
];

/// Dummy pin used to lock card
const DUMMY_PIN: [u8; 8] = [0xff; 8];

/// Static subject alternative name oid
const OID_SUBJECT_ALT_NAME: [u64; 4] = [2, 5, 29, 17];

/// Print list of currently available PIV cards
pub fn status() -> Result<()> {

    println!("Available PIV cards:");

    let mut context = Context::open()?;
    let cards: Vec<_> = context.iter()?.collect();

    if cards.is_empty() {
        println!(" - None");
        println!();
    }

    for reader in cards {
        println!(" - Reader '{}'", reader.name());

        let mut token = reader.open()?;
        println!("   Serial: {}", token.serial());

        for key in token.piv_keys()? {
            let cert = key.certificate();

            // Fingerprint is SHA256 hash of certificate
            let mut hasher = Sha256::new();
            hasher.update(cert.clone().into_buffer());
            let fingerprint = hasher.finalize();

            println!(
                "   {} key: {:x} ({})",
                key.slot(),
                fingerprint,
                cert.subject()
            );
        }

        println!();
    }

    Ok(())
}

/// Config to create an ed25519/cv25519 user cert
pub struct SeededSmartcard {
    /// Seed used for primary key
    seed: Seed256,

    /// Seed used for subkeys
    subkey: Option<Zeroizing<String>>,

    /// Name to use for certificate
    name: String,

    /// Alternative names, e.g. emails addresses, to use in certificate
    alternatives: Vec<GeneralName>,

    /// Seed used for subkeys
    pin: Option<Zeroizing<String>>,
}

impl SeededSmartcard {
    pub fn new(seed: Seed256, subkey: Option<Zeroizing<String>>, name: String) -> Self {
        let seed = seed.derive(Some(b"piv"));
        SeededSmartcard { seed, subkey, name, alternatives: vec![], pin: None }
    }

    pub fn with_pin(mut self, pin: Zeroizing<String>) -> Self {
        self.pin = Some(pin.clone());
        self
    }

    /// Add email to list of alternative names
    pub fn add_email(mut self, address: String) -> Self {
        self.alternatives.push(GeneralName::Rfc822Name(Ia5String::new(address.as_str()).unwrap()));
        self
    }

    // PUBLIC OUTPUT API

    pub fn check(self, target: Option<String>) -> Result<()> {
        todo!()
    }

    /// Generate certificate and revocation signature
    pub fn upload(self, target: Option<String>) -> Result<()> {
        // Open connection to smart card
        let mut token = if let Some(serial) = target {
            YubiKey::open_by_serial(Serial::from_str(&serial)?)
        } else {
            YubiKey::open()
        }?;
        log::info!("Connected to reader '{}'", token.name());

        // Lock pin (by repeated tries) ...
        log::info!("Locking smart card pin");
        let mut retries = token.get_pin_retries()?;
        while retries > 0 {
            match token.verify_pin(&DUMMY_PIN) {
                Err(CardError::WrongPin { tries }) => {
                    retries = tries;
                    Ok(())
                },
                other => other,
            }?;
        }

        // ... lock puk (by repeated tries) ...
        log::info!("Locking smart card puk");
        retries = 1;
        while retries > 0 {
            match token.unblock_pin(b"", b"") {
                Err(CardError::WrongPin { tries }) => {
                    retries = tries;
                    Ok(())
                },
                Err(CardError::PinLocked) => {
                    retries = 0;
                    Ok(())
                },
                other => other,
            }?;
        };

        // ... to reset the device
        log::info!("Resetting smart card");
        token.reset_device()?;

        // Authenticate with default key
        token.authenticate(MgmKey::default())?;

        // Determine management key TODO: Switch to AES256 once supported
        let mgmt_id = u8::from(ManagementSlotId::Management);
        let mgmt_seed = self.seed.derive(Some(&mgmt_id.to_le_bytes()));
        let mgmt_key = MgmKey::from_bytes(&mgmt_seed[..24])?;

        // Update management key
        mgmt_key.set_manual(&mut token, true)?;

        println!("[Please touch device to authenticate management access!]");
        token.authenticate(mgmt_key)?;
        println!();

        // Update pin
        if let Some(pin) = self.pin {
            token.change_pin(b"123456", pin.as_bytes())?;
            token.verify_pin(pin.as_bytes())?;
        } else {
            token.verify_pin(b"123456")?;
        }

        // Disable puk
        token.block_puk()?;

        // Generate subkeys
        let subseed = self.seed.derive(self.subkey.as_ref().map(|k| k.as_bytes()));

        for slot in DEFAULT_KEY_SLOTS.iter() {
            // Generate and upload key
            log::info!("Generating and uploading {:?} subkey", slot);

            let slotid = u8::from(*slot);
            let mut slotseed = subseed.derive(Some(&slotid.to_le_bytes()));

            piv::import_ecc_key(
                &mut token,
                *slot,
                AlgorithmId::EccP256,
                &slotseed,
                TouchPolicy::Always,
                PinPolicy::Once,
            )?;

            slotseed.zeroize();

            // Retrieve metadata
            let metadata = piv::metadata(&mut token, *slot)?;

            // Generate a self-signed certificate for the new key.
            log::info!("Generating and uploading {:?} certificate", slot);

            // Generate random serial number
            let mut serial = [0u8; 20];
            OsRng.fill_bytes(&mut serial);

            // Generate extensions
            let content = SubjectAltName(self.alternatives.clone()).to_der().unwrap();
            let san = x509::Extension::regular(&OID_SUBJECT_ALT_NAME[..], &content);
            let extensions: &[x509::Extension<'_, &[u64]>] = &[san];

            println!("[Please touch device authenticate {} slot access!]", slot);
            let cert = Certificate::generate_self_signed(
                &mut token,
                *slot,
                serial,
                None,
                &[x509::RelativeDistinguishedName::common_name(&self.name)],
                metadata.public.unwrap(),
                extensions,
            )?;
            println!();

            // Determine cert fingerprint
            let mut hasher = Sha256::new();
            hasher.update(cert.clone().into_buffer());
            let fingerprint = hasher.finalize();
            log::info!("Uploaded certificate with fingerprint '{:x}'", fingerprint);
        }

        token.deauthenticate()?;

        Ok(())
    }
}
