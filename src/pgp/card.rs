//! Everything that talks to a card: status, check, configuration and the key upload.

use super::{
    CardSettings, P384_REFUSED, SeededSmartcard, SignPinValidity, SubkeyRole, import::RawEccKey,
    import::RawRsaKey,
};
use crate::common;
use crate::seed::Algorithm;

use std::convert::TryFrom;
use std::time::SystemTime;

use anyhow::{Result, anyhow, bail};

use zeroize::Zeroizing;

use openpgp::Result as PGPResult;
use openpgp::cert::Cert;
use openpgp::crypto::mpi;
use openpgp::fmt::hex;
use openpgp::policy::StandardPolicy;
use sequoia_openpgp as openpgp;

use secrecy::SecretString;

use card_backend_pcsc::PcscBackend;

use openpgp_card::ocard::KeyType;
use openpgp_card::ocard::algorithm::Curve as CardCurve;
use openpgp_card::ocard::crypto::EccType;
use openpgp_card::{Card, Error as CardError};

use openpgp_card::ocard::data::{
    Fingerprint as CardFingerprint, KeyGenerationTime, TouchPolicy, UserInteractionFlag,
};
use openpgp_card::state::Open;

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
            println!("   Cardholder: {}", common::printable(&name));
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

// Determine smartcard to which to connect based on optional target string
fn open_card(target: Option<String>) -> Result<Card<Open>> {
    let card = match target {
        Some(ref serial) => {
            // Find card by ident by briefly connecting to each
            let backends: Vec<PcscBackend> =
                PcscBackend::cards(None)?.filter_map(Result::ok).collect();
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
            let backends: Vec<PcscBackend> =
                PcscBackend::cards(None)?.filter_map(Result::ok).collect();

            match backends.len() {
                0 => bail!("No card detected, please insert card"),
                1 => Card::new(backends.into_iter().next().unwrap())?,
                n => bail!("Multiple cards ({n}) detected, please specify card by serial"),
            }
        }
    };

    Ok(card)
}

/// Set the touch policy of one key, on cards that predate OpenPGP card 3 as well
///
/// `openpgp-card` looks the user interaction flags up in the application related data,
/// where only version 3 cards list them. A YubiKey 4 speaks version 2.1 and still has the
/// flags, at the same data objects, so when the lookup comes back empty they are written
/// directly, with the button as the card's interaction feature.
fn set_touch_policy(
    admin: &mut Card<openpgp_card::state::Admin<'_, '_>>,
    kt: KeyType,
    policy: TouchPolicy,
) -> std::result::Result<(), CardError> {
    match admin.set_touch_policy(kt, policy) {
        Err(CardError::UnsupportedFeature(_)) => {
            let mut uif = UserInteractionFlag::try_from(vec![0x00, 0x20])?;
            uif.set_touch_policy(policy);
            let card = admin.as_transaction().card();
            match kt {
                KeyType::Signing => card.set_uif_pso_cds(&uif),
                KeyType::Decryption => card.set_uif_pso_dec(&uif),
                KeyType::Authentication => card.set_uif_pso_aut(&uif),
                KeyType::Attestation => card.set_uif_attestation(&uif),
            }
        }
        result => result,
    }
}

impl SeededSmartcard {
    /// Check smartcard access and subkeys
    pub fn check(&self, target: Option<String>) -> Result<()> {
        // Fingerprints first: comparing them costs no pin retries, so a wrong seed, subkey id
        // or scheme fails here without consuming one of the card's three admin attempts --
        // three mistaken checks would otherwise lock the admin pin.
        //
        // The primary has to be *signed*: `check_subkeys` evaluates the certificate under the
        // standard policy, and a bare primary key packet carries no binding signature at all,
        // so an unsigned one fails with "No binding signature" before any card is consulted.
        // The direct key signature does not affect the subkey fingerprints being compared.
        let mut cert = self.generate_signed_primary()?;
        cert = self.append_subkeys(cert)?;
        self.check_subkeys(&cert, target.clone())?;

        // Only now check that the card is managed by the derived admin pin
        self.check_admin_pin(target.clone())?;

        // And that the supplied user pin, if any, actually opens the card
        if self.pin.is_some() {
            self.check_user_pin(target.clone())?;
        }

        // Advisory, like PIV's policy lines: say what the card's touch policies are,
        // since upload and config both shape them and nothing else surfaces them
        self.report_touch_policies(target);

        Ok(())
    }

    /// Report the card's touch policies, informational only
    fn report_touch_policies(&self, target: Option<String>) {
        let Ok(mut card) = open_card(target) else {
            return;
        };
        let Ok(mut transaction) = card.transaction() else {
            return;
        };
        for (label, key_type) in [
            ("signing", KeyType::Signing),
            ("decryption", KeyType::Decryption),
            ("authentication", KeyType::Authentication),
        ] {
            if let Ok(Some(uif)) = transaction.user_interaction_flag(key_type) {
                log::info!("Touch policy for {label}: {:?}", uif.touch_policy());
            }
        }
    }

    /// Adjust a provisioned card's settings under the derived admin pin.
    ///
    /// The counterpart to `upload`'s defaults: provisioning writes the keys with sensible
    /// policies, and this changes them to the user's liking afterwards without wiping
    /// anything. Fingerprints are compared first -- that costs no pin retries, so a wrong
    /// seed, subkey id or scheme fails here without spending one of the card's three admin
    /// attempts.
    pub fn configure(&self, target: Option<String>, settings: CardSettings) -> Result<()> {
        let mut cert = self.generate_signed_primary()?;
        cert = self.append_subkeys(cert)?;
        self.check_subkeys(&cert, target.clone())?;

        let mut card = open_card(target)?;
        let mut transaction = card.transaction()?;
        log::info!("Connected to smartcard '{}'", transaction.application_identifier()?.ident());

        let admin_pin = self.admin_pin();
        let mut admin =
            transaction.as_admin_card(SecretString::from(admin_pin.as_str().to_owned()))?;

        for (role, policy) in &settings.touch {
            log::info!("Setting {:?} key touch policy: {:?}", role, policy);
            set_touch_policy(&mut admin, role.key_type(), (*policy).into())?;
        }

        if !settings.lang.is_empty() {
            let langs: Vec<_> = settings
                .lang
                .iter()
                .map(|pair| [pair[0] as char, pair[1] as char].into())
                .collect();
            log::info!(
                "Setting cardholder language preferences: {}",
                settings
                    .lang
                    .iter()
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            admin.set_lang(&langs)?;
        }

        if let Some(url) = &settings.url {
            log::info!("Setting public certificate url: {}", url);
            admin.set_url(url)?;
        }

        if let Some(login) = &settings.login {
            log::info!("Setting login data: {}", login);
            admin.set_login_data(login.as_bytes())?;
        }

        if let Some(validity) = settings.sign_pin {
            log::info!("Setting pin signing validity: {:?}", validity);
            admin.set_user_pin_signing_validity(validity == SignPinValidity::Once)?;
        }

        Ok(())
    }

    /// Upload secret subkeys
    pub fn upload(&self, target: Option<String>) -> Result<Cert> {
        let mut cert = self.generate_primary()?;

        cert = self.append_uids(cert)?;
        cert = self.append_subkeys(cert)?;

        self.upload_subkeys(&cert, target)?;

        Ok(cert)
    }

    /// Check that smartcard can be accessed with derived admin pin
    pub fn check_admin_pin(&self, target: Option<String>) -> Result<()> {
        // Determine smartcard to which to connect
        let mut card = open_card(target)?;

        // Establish connection and receive metadata
        let mut transaction = card.transaction()?;
        log::info!("Connected to smartcard '{}'", transaction.application_identifier()?.ident());

        // Verify admin pin derived from subseed
        let admin_pin = self.admin_pin();
        transaction.verify_admin_pin(SecretString::from(admin_pin.as_str().to_owned()))?;

        Ok(())
    }

    /// Check that the supplied user pin opens the smartcard
    pub fn check_user_pin(&self, target: Option<String>) -> Result<()> {
        let pin = match self.pin.as_ref() {
            Some(pin) => pin,
            None => return Ok(()),
        };

        // Determine smartcard to which to connect
        let mut card = open_card(target)?;
        let mut transaction = card.transaction()?;

        // A valid UTF-8 pin borrows through `from_utf8_lossy`, and the `String` moves into
        // `SecretString`, which zeroizes it -- no unwiped copy is left behind
        let pin_str = pin.map(|p| String::from_utf8_lossy(p).to_string());
        transaction.verify_user_pin(SecretString::from(pin_str))?;

        log::info!("User pin verified");

        Ok(())
    }

    /// Check that subkey fingerprints of certificate matches those on smartcard
    pub fn check_subkeys(&self, cert: &Cert, target: Option<String>) -> Result<()> {
        // Determine smartcard to which to connect
        let mut card = open_card(target)?;

        // Establish connection and receive metadata
        let mut transaction = card.transaction()?;
        log::info!("Connected to smartcard '{}'", transaction.application_identifier()?.ident());

        // Get the certificate subkeys
        let policy = &StandardPolicy::new();
        let valid_cert = cert.with_policy(policy, None)?;

        // Collected rather than raised, so that one bad subkey does not hide the others. A
        // card provisioned from the wrong seed disagrees in all three.
        let mut mismatches: Vec<String> = Vec::new();

        // For each of the expected subkeys...
        for role in SubkeyRole::ALL {
            let kt = role.key_type();

            // ... get fingerprint of matching subkey in cert ...
            let subkey = valid_cert
                .keys()
                .subkeys()
                .find(|k| k.key_flags().is_some_and(|flags| role.matches(&flags)))
                .ok_or_else(|| anyhow!("{:?} key not found in cert", kt))?;

            let cert_fp_bytes: [u8; 20] = subkey
                .key()
                .fingerprint()
                .as_bytes()
                .try_into()
                .map_err(|_| anyhow!("Unexpected fingerprint length"))?;

            // ... and try to compare it to the fingerprint on the smartcard
            match transaction.fingerprint(kt) {
                Ok(Some(card_fp)) if card_fp.as_bytes() == cert_fp_bytes => {
                    log::info!("Fingerprint match for {:?} key: {}", kt, card_fp.to_spaced_hex())
                }
                Ok(Some(card_fp)) => mismatches.push(format!(
                    "Fingerprint mismatch for {:?} key: certificate={}, card={}",
                    kt,
                    hex::encode_pretty(cert_fp_bytes),
                    card_fp.to_spaced_hex()
                )),
                Ok(None) => mismatches.push(format!("No {kt:?} key found on card")),
                Err(err) => mismatches.push(format!("Could not read {kt:?} fingerprint: {err}")),
            }
        }

        crate::common::report_mismatches("certificate", mismatches)
    }

    /// Upload subkeys to a smartcard and reset and lock smartcard in the process
    fn upload_subkeys(&self, cert: &Cert, target: Option<String>) -> PGPResult<()> {
        // Determine smartcard to which to connect
        let mut card = open_card(target)?;

        // Establish connection and receive metadata
        let mut transaction = card.transaction()?;
        log::info!("Connected to smartcard '{}'", transaction.application_identifier()?.ident());

        // Factory reset smartcard
        transaction.factory_reset()?;

        // Change user pin if it was specified
        if let Some(pin) = self.pin.as_ref() {
            let new_pin: Zeroizing<String> =
                pin.map(|p| String::from_utf8_lossy(p).to_string()).into();
            transaction.change_user_pin(
                SecretString::from("123456".to_string()),
                SecretString::from(AsRef::<str>::as_ref(&*new_pin).to_owned()),
            )?;
        }
        // The missing-pin case was already warned about at the command layer, once

        // Set new admin pin derived from subseed
        let admin_pin = self.admin_pin();
        transaction.change_admin_pin(
            SecretString::from("12345678".to_string()),
            SecretString::from(admin_pin.as_str().to_owned()),
        )?;

        // Authenticate as admin (combines verify + elevation in one step)
        let mut admin =
            transaction.as_admin_card(SecretString::from(admin_pin.as_str().to_owned()))?;

        admin.set_cardholder_name(&self.name)?;
        admin.set_lang(&[['e', 'n'].into()])?;

        let p = &StandardPolicy::new();
        let vc = cert.with_policy(p, None)?;

        for role in SubkeyRole::ALL {
            let kt = role.key_type();

            // Find the matching subkey in the cert to get fingerprint, timestamp, and public bytes
            let subkey = vc
                .keys()
                .subkeys()
                .find(|k| k.key_flags().is_some_and(|flags| role.matches(&flags)))
                .ok_or_else(|| anyhow!("{:?} key not found in cert", kt))?;

            // Extract fingerprint as 20-byte array
            let fp_bytes: [u8; 20] = subkey
                .key()
                .fingerprint()
                .as_bytes()
                .try_into()
                .map_err(|_| anyhow!("Unexpected fingerprint length"))?;

            // Extract creation timestamp
            let ts = subkey
                .key()
                .creation_time()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|e| anyhow!("Key creation time error: {}", e))?
                .as_secs() as u32;

            // Re-derive the raw private key bytes, exactly as they went into the certificate
            let agreement = role.is_encryption();
            let seed =
                self.derive_secret(self.seed_for(role), Some(&self.label_for(role)), agreement)?;
            let fingerprint = CardFingerprint::from(fp_bytes);
            let timestamp = KeyGenerationTime::from(ts);

            log::info!("Uploading {:?} key", kt);
            if self.algorithm.rsa_bits().is_some() {
                let key = RawRsaKey::new(&self.rsa_key(&seed)?, fingerprint, timestamp)?;
                admin.import_key(&key, kt)?;
            } else {
                // Extract public key bytes from cert MPI (0x40-prefixed for 25519 keys, the
                // uncompressed 0x04 point for P-256, which is what the card wants for both)
                let pub_bytes = match subkey.key().mpis() {
                    mpi::PublicKey::EdDSA { q, .. } => q.value().to_vec(),
                    mpi::PublicKey::ECDSA { q, .. } => q.value().to_vec(),
                    mpi::PublicKey::ECDH { q, .. } => q.value().to_vec(),
                    _ => bail!("{:?} key has unexpected algorithm in cert", kt),
                };

                let (oid, ecc_type) = match (self.algorithm, agreement) {
                    (Algorithm::Curve25519, true) => (CardCurve::Curve25519.oid(), EccType::ECDH),
                    (Algorithm::Curve25519, false) => (CardCurve::Ed25519.oid(), EccType::EdDSA),
                    (Algorithm::P256, true) => (CardCurve::NistP256r1.oid(), EccType::ECDH),
                    (Algorithm::P256, false) => (CardCurve::NistP256r1.oid(), EccType::ECDSA),
                    (Algorithm::P384, _) => bail!(P384_REFUSED),
                    _ => unreachable!("RSA is handled above"),
                };

                // OpenPGP cards take the X25519 scalar big-endian, the way GnuPG stores it,
                // where RFC 7748 and everything derived here is little-endian: sent as is,
                // the card would hold a different key than the certificate advertises
                let mut private_bytes = Zeroizing::new(seed.to_vec());
                if matches!(self.algorithm, Algorithm::Curve25519) && agreement {
                    private_bytes.reverse();
                }

                let key = RawEccKey {
                    oid,
                    private_bytes,
                    public_bytes: pub_bytes,
                    ecc_type,
                    fingerprint,
                    timestamp,
                };
                admin.import_key(&key, kt)?;
            }

            // Prefer Cached (one touch valid for ~15s), but only advisorily: Cached is a
            // Yubico extension to the UIF data object, and a spec-conforming card -- the
            // Nitrokey 3's opcard rejects it with "incorrect parameters" -- must not lose
            // its freshly imported keys over a nicety. `pgp configure --touch` can set
            // whatever the card actually supports afterwards.
            if let Err(err) = set_touch_policy(&mut admin, kt, TouchPolicy::Cached) {
                log::warn!(
                    "Card refused the cached touch policy for the {kt:?} key ({err}); \
                     set a supported one with `pgp configure --touch`"
                );
            }
        }

        Ok(())
    }
}
