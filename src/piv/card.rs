//! Everything that writes to a card: the reset, the keys, certificates and identifiers.

use super::{
    CertChain, ManagementKeyArg, SeededSmartcard, SlotRole,
    keys::NAME_CCC_ID,
    keys::NAME_CHUID_ID,
    slots::{FIRST_RETIRED_SLOT, LAST_RETIRED_SLOT},
};
use crate::common;
use crate::readers;
use crate::seed::{Algorithm, Seed256Derive};
use crate::target::CardTarget;

use anyhow::{Result, anyhow, bail};

use yubikey::certificate::CertInfo;
use yubikey::piv::{self, AlgorithmId, RetiredSlotId, SlotId};
use yubikey::reader::Context;
use yubikey::{
    CardId, CccId, Certificate as CardCertificate, ChuId, Error as CardError, MgmAlgorithmId,
    MgmKey, MsRoots, TouchPolicy, Version, YubiKey,
};

use cms::content_info::ContentInfo;

use der::Encode;

use sha2::{Digest, Sha256};

/// Dummy pin used to lock card
const DUMMY_PIN: [u8; 8] = [0xff; 8];

/// The factory management key of every PIV card in the Yubico ecosystem, whatever its
/// algorithm
const DEFAULT_MANAGEMENT_KEY: [u8; 24] = [
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
];

/// First firmware with AES management keys; YubiKey 4 and YubiKey 5 before 5.4 take 3DES only
const FIRST_AES_MANAGEMENT: Version = Version { major: 5, minor: 4, patch: 0 };

/// First YubiKey firmware that imports Ed25519, X25519, RSA-3072 and RSA-4096 keys
const FIRST_EXTENDED_ALGORITHMS: Version = Version { major: 5, minor: 7, patch: 0 };

/// First YubiKey firmware with the cached touch policy
const FIRST_CACHED_TOUCH: Version = Version { major: 4, minor: 3, patch: 0 };

/// FIPS 201 CHUID, with a zeroed Card UUID.
///
/// Replicated from `yubikey`'s private `CHUID_TMPL`, because `ChuId::set` overwrites the
/// template with all 59 bytes it is handed -- there is no way to supply only the GUID. Every
/// field but the UUID is fixed: a non-federal FASC-N, the hard-coded 2030-01-01 expiry, and
/// empty signature and error-detection blocks.
const CHUID_TEMPLATE: [u8; ChuId::BYTE_SIZE] = [
    0x30, 0x19, 0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73, 0x9d, 0x83, 0x68, 0x58,
    0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0xc8, 0x42, 0x10, 0xc3, 0xeb, 0x34, 0x10, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35, 0x08, 0x32,
    0x30, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x3e, 0x00, 0xfe, 0x00,
];

/// Offset of the 16-byte Card UUID within [`CHUID_TEMPLATE`]
const CHUID_GUID_OFFSET: usize = 29;

/// GSC-IS Cardholder Capability Container, with a zeroed card identifier.
///
/// Replicated from `yubikey`'s private `CCC_TMPL` for the same reason as [`CHUID_TEMPLATE`].
const CCC_TEMPLATE: [u8; CccId::BYTE_SIZE] = [
    0xf0, 0x15, 0xa0, 0x00, 0x00, 0x01, 0x16, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1, 0x01, 0x21, 0xf2, 0x01, 0x21, 0xf3, 0x00, 0xf4,
    0x01, 0x00, 0xf5, 0x01, 0x10, 0xf6, 0x00, 0xf7, 0x00, 0xfa, 0x00, 0xfb, 0x00, 0xfc, 0x00, 0xfd,
    0x00, 0xfe, 0x00,
];

/// Offset of the 14-byte card identifier within [`CCC_TEMPLATE`]
const CCC_ID_OFFSET: usize = 9;

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
        println!(" - Reader '{}'", common::printable(&reader.name()));

        // A reader that is busy or holds a non-PIV card must not abort the whole listing:
        // status is a read-only overview and is expected to report what it can.
        let mut token = match reader.open() {
            Ok(token) => token,
            Err(err) => {
                println!("   Unavailable: {err}");
                println!();
                continue;
            }
        };
        println!("   Serial: {}", token.serial());

        // Read each real certificate slot directly instead of `piv_keys()`: the crate's
        // slot table behind that call maps pseudo-slots onto unrelated objects -- "Pin"
        // onto the key management certificate and "Puk" onto the key history object,
        // whose content is no certificate at all, so one written key history object (as
        // any card with retired certificates has) makes the whole listing fail.
        let slots = [
            SlotId::Authentication,
            SlotId::Signature,
            SlotId::KeyManagement,
            SlotId::CardAuthentication,
            SlotId::Attestation,
        ]
        .into_iter()
        .chain(
            (FIRST_RETIRED_SLOT..=LAST_RETIRED_SLOT)
                .filter_map(|byte| RetiredSlotId::try_from(byte).ok().map(SlotId::Retired)),
        );

        for slot in slots {
            let cert = match CardCertificate::read(&mut token, slot) {
                Ok(cert) => cert,
                // An empty slot is the normal case, not something to report
                Err(_) => continue,
            };

            match cert.cert.to_der() {
                Ok(der) => {
                    println!(
                        "   {} key: {:x} ({})",
                        slot,
                        Sha256::digest(der),
                        common::printable(&cert.subject().to_string())
                    )
                }
                Err(err) => println!(
                    "   {} key: unreadable certificate: {}",
                    slot,
                    common::printable(&err.to_string())
                ),
            }
        }
        // Dropping a token resets the card, which would throw any other program off it
        let _ = token.disconnect(pcsc::Disposition::LeaveCard);

        println!();
    }

    Ok(())
}

/// Connect to a PIV token, named by serial number or reader, or the only one attached
///
/// Mirrors [`crate::pgp`]'s `open_card`: bare `YubiKey::open()` silently picks the first
/// reader, which is the wrong behaviour when several cards are attached.
pub(super) fn open_token(target: Option<CardTarget>) -> Result<YubiKey> {
    let reader = match target {
        Some(CardTarget::Reader(name)) => name,
        Some(CardTarget::Serial(serial)) => reader_of(serial)?,
        Some(CardTarget::Ident(ident)) => bail!(
            "--card {ident} is an OpenPGP card identifier; name a PIV card by its serial \
             number or its reader, as `piv status` shows them"
        ),
        None => {
            let (context, readers) = readers::list()?;
            match readers.as_slice() {
                [] => bail!("No card detected, please insert card"),
                [only] => only.to_string_lossy().into_owned(),
                _ => {
                    let cards: Vec<String> = readers
                        .iter()
                        .map(|reader| {
                            let name = common::printable(&reader.to_string_lossy());
                            match readers::ask(&context, reader, read_serial) {
                                Ok(Some(serial)) => format!("  {name}, serial {serial}"),
                                _ => format!("  {name} (not a PIV card)"),
                            }
                        })
                        .collect();
                    bail!(
                        "{} cards are attached, pick one with --card <serial>:\n{}",
                        readers.len(),
                        cards.join("\n")
                    )
                }
            }
        }
    };

    let token = open_reader(&reader)?;
    log::info!("Connected to {}", describe(&token));
    Ok(token)
}

/// Open the PIV card in exactly this reader, without asking any other
fn open_reader(name: &str) -> Result<YubiKey> {
    let mut context = Context::open()?;
    let reader = context
        .iter()?
        .find(|reader| reader.name() == name)
        .ok_or_else(|| {
            anyhow!(
                "No reader named '{}'; `piv status` lists the attached ones",
                common::printable(name)
            )
        })?;
    Ok(reader.open()?)
}

/// The reader holding the PIV card with this serial, found without disturbing the other cards
///
/// `YubiKey::open_by_serial` would open every card through the crate and leave each one
/// reset; here each is asked inside a transaction and left as it was.
fn reader_of(serial: u32) -> Result<String> {
    let (context, readers) = readers::list()?;
    let mut held = None;
    for reader in readers {
        match readers::ask(&context, &reader, read_serial) {
            Ok(Some(found)) if found == serial => return Ok(reader.to_string_lossy().into_owned()),
            Err(pcsc::Error::SharingViolation) => {
                held.get_or_insert(reader);
            }
            _ => {}
        }
    }
    match held {
        // The card may well be the one another program holds, so say which and who usually
        Some(reader) => bail!(
            "No PIV card with serial {serial} found, and reader '{}' could not be asked: {}. \
             Usually gpg's scdaemon holds it: `gpgconf --kill scdaemon`",
            common::printable(&reader.to_string_lossy()),
            pcsc::Error::SharingViolation
        ),
        None => {
            bail!("No PIV card with serial {serial} found; `piv status` lists the attached ones")
        }
    }
}

/// The serial number a PIV card reports, the way yubikey.rs reads it, or `None` for a card
/// without the PIV application or a serial
fn read_serial(transaction: &pcsc::Transaction<'_>) -> Option<u32> {
    // YubiKeys answer to the RID alone, other implementations only to the full AID
    readers::transmit(transaction, &readers::select(&PIV_RID))
        .or_else(|| readers::transmit(transaction, &readers::select(&PIV_AID)))?;
    let version = readers::transmit(transaction, &GET_VERSION)?;
    let serial = match version.first()? {
        // A YubiKey 4 tells its serial through the OTP application only
        4 => {
            readers::transmit(transaction, &readers::select(&OTP_AID))?;
            let serial = readers::transmit(transaction, &OTP_GET_SERIAL);
            readers::transmit(transaction, &readers::select(&PIV_RID));
            serial?
        }
        _ => readers::transmit(transaction, &GET_SERIAL)?,
    };
    Some(u32::from_be_bytes(serial.get(..4)?.try_into().ok()?))
}

/// The PIV application's registered identifier, which YubiKeys select by
const PIV_RID: [u8; 5] = [0xA0, 0x00, 0x00, 0x03, 0x08];
/// The full PIV application identifier of SP 800-73
const PIV_AID: [u8; 11] = [
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];
/// Yubico's OTP application, where a YubiKey 4 keeps its serial
const OTP_AID: [u8; 8] = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01];
/// Yubico's GET VERSION of the PIV application
const GET_VERSION: [u8; 5] = [0x00, 0xFD, 0x00, 0x00, 0x00];
/// Yubico's GET SERIAL of the PIV application, firmware 5 and later and the trussed app
const GET_SERIAL: [u8; 5] = [0x00, 0xF8, 0x00, 0x00, 0x00];
/// The OTP application's serial number request
const OTP_GET_SERIAL: [u8; 5] = [0x00, 0x01, 0x10, 0x00, 0x00];

/// Spend the tries of a pin or puk until the card itself reports it blocked
///
/// The counter is never taken on trust: a card that keeps a verified pin across SELECT
/// answers the status query with 9000, which reads as no tries left, and skipping the pin on
/// that word would then block the puk of a card whose pin still works. Bounded, because the
/// counters are a u8 on the wire: a conversation that does not converge within that is
/// firmware misbehaving, and a report beats hammering the card forever.
fn exhaust(
    what: &str,
    accepted: &str,
    mut attempt: impl FnMut() -> yubikey::Result<()>,
) -> Result<()> {
    for _ in 0..=u8::MAX {
        match attempt() {
            // The lock-out value was accepted: the counter has just reset, so spending tries
            // can never converge from here
            Ok(()) => bail!("{accepted}"),
            // Depending on the firmware, a blocked pin comes back as PinLocked instead of a
            // zero try count
            Err(CardError::WrongPin { tries: 0 }) | Err(CardError::PinLocked) => return Ok(()),
            Err(CardError::WrongPin { .. }) => {}
            Err(other) => return Err(other.into()),
        }
    }
    bail!("Card {what} did not lock after exhausting its retries")
}

/// The card as the confirmation and the logs name it: reader, serial and firmware
fn describe(token: &YubiKey) -> String {
    let version = token.version();
    format!(
        "{}, serial {}, firmware {}.{}.{}",
        common::printable(token.name()),
        token.serial(),
        version.major,
        version.minor,
        version.patch
    )
}

/// An algorithm as the error messages name it
fn card_algorithm_name(algorithm: AlgorithmId) -> &'static str {
    match algorithm {
        AlgorithmId::Rsa1024 => "RSA-1024",
        AlgorithmId::Rsa2048 => "RSA-2048",
        AlgorithmId::Rsa3072 => "RSA-3072",
        AlgorithmId::Rsa4096 => "RSA-4096",
        AlgorithmId::EccP256 => "P-256",
        AlgorithmId::EccP384 => "P-384",
        AlgorithmId::Ed25519 => "Ed25519",
        AlgorithmId::X25519 => "X25519",
    }
}

impl SeededSmartcard {
    /// Generate keys and certificates and upload them to a card
    pub fn upload(&self, target: Option<CardTarget>) -> Result<CertChain> {
        // Build the whole chain before touching the card, so that a derivation or encoding
        // failure never leaves a freshly reset card half provisioned.
        let chain = self.generate_chain()?;

        let mut token = open_token(target)?;
        self.refuse_unfit(&token)?;

        let algorithm = self.reset_and_lock(&mut token)?;
        self.upload_card_identifiers(&mut token)?;
        self.upload_subcerts(&chain, &mut token)?;

        if self.msroots {
            // Windows-only, so a failure here must not abort an otherwise good provisioning
            if let Err(err) = self.upload_msroots(&chain, &mut token) {
                log::warn!("Failed to store certificate authorities in msroots: {err}");
            }
        }

        // Everything is on the card, so future management access can now demand a touch. Done
        // last on purpose: setting the flag needs no touch itself (we are still authenticated),
        // and leaving it until the end means a card is never wiped for a button that was not
        // pressed in time. A card that opts out keeps the key installed without the flag by
        // `reset_and_lock`: a build server's card is provisioned on an air-gapped machine, and
        // the derived management key never reaches the server it then lives in, so the touch
        // would guard nothing there while costing every unattended re-check a button press.
        if self.policy.management_touch() {
            log::info!("Requiring touch for future management access");
            // Everything else is on the card by now, so a card that refuses the flag (stock
            // piv-authenticator rejects P2=FE) keeps a working provisioning; `check` reports
            // the missing touch as a policy mismatch
            if let Err(err) = self.management_key(algorithm)?.set_manual(&mut token, true) {
                log::warn!("The card refused a touch requirement for management access: {err}");
            }
        } else {
            log::info!("Management access stays touch-free, as the policy asks for no touch");
        }

        // Dropping the session works by selecting the Yubico management applet, which only
        // exists on YubiKeys -- on other PIV implementations the authentication simply ends
        // with the connection, so a failure here must not fail the finished provisioning
        if let Err(err) = token.deauthenticate() {
            log::warn!("Could not deauthenticate management key: {err}");
        }

        Ok(chain)
    }

    /// Open the card `upload` would wipe, refuse it if it cannot hold the keys, and name it
    ///
    /// Meant for the confirmation: the question can name the card, and a card that would be
    /// wiped for nothing is refused while it is still intact. `upload` repeats the check on
    /// the card it opens itself.
    pub fn preflight(&self, target: Option<CardTarget>) -> Result<String> {
        let token = open_token(target)?;
        self.refuse_unfit(&token)?;
        Ok(describe(&token))
    }

    /// Refuse a card that cannot take what `upload` installs, before anything on it changes
    ///
    /// A YubiKey is judged by its firmware version. Other PIV cards are judged by the
    /// algorithms their SELECT response lists, where they list any; a card that lists
    /// nothing can only answer with the import itself, once it is reset. piv-authenticator
    /// lists every algorithm it knows whatever its build carries until its pending change to
    /// list only what the build supports is released, so on today's builds this check passes
    /// and the import remains the first answer.
    fn refuse_unfit(&self, token: &YubiKey) -> Result<()> {
        let version = token.version();
        let firmware = format!("{}.{}.{}", version.major, version.minor, version.patch);
        if !token.name().starts_with("Yubico") {
            let missing = token
                .piv_application_properties()
                .and_then(|properties| self.unlisted(properties));
            match missing {
                Some(missing) if !missing.is_empty() => bail!(
                    "The card lists the algorithms it supports, and {} is not among them; \
                     the card was not touched",
                    missing.join(" or ")
                ),
                Some(_) => {}
                None => log::warn!(
                    "Not a YubiKey: whether the card imports {} keys shows only once it is reset",
                    self.algorithm
                ),
            }
            return Ok(());
        }

        let extended = matches!(
            self.algorithm,
            Algorithm::Curve25519 | Algorithm::Rsa3072 | Algorithm::Rsa4096
        );
        if extended && version < FIRST_EXTENDED_ALGORITHMS {
            bail!(
                "YubiKey firmware {firmware} cannot import {} keys into PIV (5.7 and later can); \
                 the card was not touched",
                self.algorithm
            );
        }
        if self.management_algorithm == ManagementKeyArg::Aes256 && version < FIRST_AES_MANAGEMENT {
            bail!(
                "YubiKey firmware {firmware} takes 3DES management keys only (AES from 5.4); \
                 use --management-algorithm auto or tdes. The card was not touched"
            );
        }
        let cached = SlotRole::ALL
            .iter()
            .any(|role| self.policies_for(role.slot()).1 == TouchPolicy::Cached);
        if cached && version < FIRST_CACHED_TOUCH {
            bail!(
                "YubiKey firmware {firmware} has no cached touch policy (4.3 and later have); \
                 pass a --policy without cached touch, such as strict or never-touch. The \
                 card was not touched"
            );
        }
        Ok(())
    }

    /// What `upload` would install that a card's algorithm list leaves out, or `None` if the
    /// card lists no algorithms to judge by
    ///
    /// `auto` settles on AES-256 or falls back to 3DES after the reset, so it needs one of
    /// the two; an explicit management key algorithm needs exactly that one.
    pub(super) fn unlisted(&self, properties: &piv::ApplicationProperties) -> Option<Vec<String>> {
        let mut missing: Vec<String> = Vec::new();
        for role in SlotRole::ALL {
            let algorithm = role.card_algorithm(self.algorithm);
            let name = card_algorithm_name(algorithm).to_string();
            if !properties.supports(algorithm)? && !missing.contains(&name) {
                missing.push(name);
            }
        }

        let (management, name): (&[MgmAlgorithmId], _) = match self.management_algorithm {
            ManagementKeyArg::Aes256 => (&[MgmAlgorithmId::Aes256], "an AES-256"),
            ManagementKeyArg::Tdes => (&[MgmAlgorithmId::ThreeDes], "a 3DES"),
            ManagementKeyArg::Auto => {
                (&[MgmAlgorithmId::Aes256, MgmAlgorithmId::ThreeDes], "an AES-256 or 3DES")
            }
        };
        let mut listed = false;
        for algorithm in management {
            listed |= properties.supports_management(*algorithm)?;
        }
        if !listed {
            missing.push(format!("{name} management key"));
        }

        Some(missing)
    }

    /// Algorithm of the management key `upload` installs on `token`
    pub(super) fn management_algorithm(&self, token: &YubiKey) -> MgmAlgorithmId {
        match self.management_algorithm {
            ManagementKeyArg::Aes256 => MgmAlgorithmId::Aes256,
            ManagementKeyArg::Tdes => MgmAlgorithmId::ThreeDes,
            // The reported version is what decides: a Nitrokey 3 or the trussed PIV app
            // reports 6.6.6 and takes AES, a YubiKey 4 reports 4.x and takes 3DES only
            ManagementKeyArg::Auto if token.version() >= FIRST_AES_MANAGEMENT => {
                MgmAlgorithmId::Aes256
            }
            ManagementKeyArg::Auto => MgmAlgorithmId::ThreeDes,
        }
    }

    /// Write the CHUID and CCC data objects
    ///
    /// Windows smartcard logon and a good deal of middleware refuse a card carrying neither.
    /// Both identifiers are *derived* rather than generated -- `CardId::generate` would pick a
    /// random one -- so that re-provisioning from the same seed reproduces the same card.
    ///
    /// Each identifier has its own label rather than taking a slice of a shared derivation.
    /// All three are published, so sharing material buys no secrecy, and independent labels
    /// mean a format changing width cannot disturb the others.
    fn upload_card_identifiers(&self, token: &mut YubiKey) -> Result<()> {
        log::info!("Storing card identifiers in CHUID and CCC");

        let mut chuid = CHUID_TEMPLATE;
        chuid[CHUID_GUID_OFFSET..CHUID_GUID_OFFSET + 16]
            .copy_from_slice(&self.subseed.id(NAME_CHUID_ID, 16));
        ChuId(chuid).set(token)?;

        let mut ccc = CCC_TEMPLATE;
        ccc[CCC_ID_OFFSET..CCC_ID_OFFSET + CardId::BYTE_SIZE]
            .copy_from_slice(&self.subseed.id(NAME_CCC_ID, CardId::BYTE_SIZE));
        CccId(ccc).set(token)?;

        Ok(())
    }

    /// Wipe the card and install the derived management key and user pin
    ///
    /// Returns the algorithm of the installed management key, for `upload` to finish with.
    fn reset_and_lock(&self, token: &mut YubiKey) -> Result<MgmAlgorithmId> {
        // Lock pin and puk by spending their tries, so that the card allows a reset ...
        log::info!("Locking smart card pin");
        exhaust("pin", "Card pin equals the lock-out pin; change it and retry", || {
            token.verify_pin(&DUMMY_PIN)
        })?;
        log::info!("Locking smart card puk");
        exhaust("puk", "Card puk is empty; set one and retry", || token.unblock_pin(b"", b""))?;

        // ... to reset the device
        log::info!("Resetting smart card");
        token.reset_device()?;

        // Authenticate with the default key in whatever algorithm the reset installed: the
        // firmware version table behind `MgmKey::get_default` only knows YubiKeys
        let algorithm = MgmAlgorithmId::current(token)?;
        let default = MgmKey::from_bytes(DEFAULT_MANAGEMENT_KEY, Some(algorithm))?;
        token.authenticate(&default)?;

        // Install our management key, but *without* the touch requirement for now.
        //
        // Requiring a touch at this point means a missed button press aborts after
        // `reset_device` has already wiped the card and blocked its puk, leaving it bare with
        // nothing provisioned in exchange -- and the prompt only lasts as long as the token's
        // touch timeout. `require_touch` is switched on at the end of `upload` instead, where
        // the same failure costs nothing and can simply be repeated.
        let mut algorithm = self.management_algorithm(token);
        log::info!("Installing the derived {algorithm:?} management key");
        let mut mgmt_key = self.management_key(algorithm)?;
        if let Err(err) = mgmt_key.set_manual(token, false) {
            // Outside the YubiKey table the version only hints at AES, and the default key is
            // still in force after a refusal, so `auto` can still settle on 3DES
            if self.management_algorithm != ManagementKeyArg::Auto
                || algorithm == MgmAlgorithmId::ThreeDes
            {
                return Err(err.into());
            }
            log::warn!("The card refused an {algorithm:?} management key ({err}); using 3DES");
            algorithm = MgmAlgorithmId::ThreeDes;
            mgmt_key = self.management_key(algorithm)?;
            mgmt_key.set_manual(token, false)?;
        }
        token.authenticate(&mgmt_key)?;

        if let Some(pin) = &self.pin {
            token.change_pin(common::FACTORY_USER_PIN.as_bytes(), pin.as_bytes())?;
            token.verify_pin(pin.as_bytes())?;
        } else {
            // Warned about once at the command layer; here it only needs verifying
            token.verify_pin(common::FACTORY_USER_PIN.as_bytes())?;
        }

        // Disable puk. Blocked by a bounded loop of our own first: `block_puk` retries any
        // error but a wrong pin forever, and a card answering 6300 to a wrong puk would never
        // let go. Called afterwards, it stops at once and only records the blocked puk in the
        // admin data, where ykman looks for it.
        exhaust("puk", "Card puk equals the lock-out value; reset the card and retry", || {
            token.change_puk(&DUMMY_PIN, &DUMMY_PIN)
        })?;
        token.block_puk()?;

        Ok(algorithm)
    }

    /// Import the slot keys and store their certificates
    fn upload_subcerts(&self, chain: &CertChain, token: &mut YubiKey) -> Result<()> {
        for (slot, cert) in &chain.leaves {
            log::info!("Generating and uploading {:?} subkey", slot);

            // The very same derived bytes have to reach the card, otherwise the on-card key
            // and the key we just certified would diverge.
            let key = self.slot_key(*slot)?;
            let (pin_policy, touch_policy) = self.policies_for(*slot);

            key.import(token, *slot, touch_policy, pin_policy)?;

            // Invariant: the card has to hold the key we certified. A card without GET
            // METADATA (YubiKey before 5.3) cannot say which key it holds; `check` proves it
            // by a signature challenge instead, which needs the pin and possibly a touch per
            // slot, too much to impose on every upload.
            match piv::metadata(token, *slot) {
                Ok(metadata) => {
                    let on_card = metadata
                        .public
                        .ok_or_else(|| anyhow!("Failed to retrieve public key"))?;
                    let want = cert.tbs_certificate().subject_public_key_info().to_der()?;
                    if on_card.to_der()? != want {
                        bail!("Imported key for {:?} does not match the certified key", slot);
                    }
                }
                Err(CardError::NotSupported) => {
                    log::info!("Card has no GET METADATA; the imported key is verified by `check`")
                }
                Err(err) => return Err(err.into()),
            }

            log::info!("Uploading {:?} certificate", slot);
            CardCertificate::from_bytes(cert.to_der()?)?.write(
                token,
                *slot,
                CertInfo::Uncompressed,
            )?;

            log::info!(
                "Uploaded certificate with fingerprint '{:x}'",
                Sha256::digest(cert.to_der()?)
            );
        }

        Ok(())
    }

    /// Store the certificate authorities in the card's `msroots` object
    fn upload_msroots(&self, chain: &CertChain, token: &mut YubiKey) -> Result<()> {
        log::info!("Storing certificate authorities in msroots");

        // `msroots` holds a degenerate PKCS#7 certs-only SignedData blob
        let content = ContentInfo::try_from(chain.cas())?;
        MsRoots::new(content.to_der()?)?.write(token)?;

        Ok(())
    }
}
