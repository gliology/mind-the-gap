//! Everything that writes to a card: the reset, the keys, certificates and identifiers.

use super::{
    CertChain, ManagementKeyArg, SeededSmartcard, SlotRole,
    keys::PUK_LENGTH,
    ownership::Facts,
    slots::{FIRST_RETIRED_SLOT, LAST_RETIRED_SLOT},
};
use crate::common;
use crate::ownership::{ListedKey, Listing, Ownership};
use crate::readers;
use crate::seed::{Algorithm, CardSerial};
use crate::target::{Attached, CardTarget};

use anyhow::{Result, anyhow, bail};

use yubikey::PinPolicy;
use yubikey::certificate::CertInfo;
use yubikey::piv::{self, AlgorithmId, RetiredSlotId, SlotId};

use x509_cert::Certificate as X509Certificate;
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

/// The factory puk of every PIV card in the Yubico ecosystem
const FACTORY_PUK: &str = "12345678";

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

/// What `list` shows of every attached card with a PIV application
///
/// With a card seed at hand (`owner`), each card also says whether it initialized it, and with
/// a key seed which keys are its own. That is read from public objects only, so the listing
/// still spends no pin tries, asks for no touch and leaves every card as it was found.
pub fn list(owner: Option<&SeededSmartcard>, cards: &[Attached]) -> Result<Vec<Listing>> {
    // Derived once, not per card: which keys the key seed's chosen generation holds, to mark
    // them wherever they turn up
    let derived: Vec<Vec<u8>> = owner
        .filter(|owner| owner.seeds.has_key())
        .map(|owner| {
            owner
                .keys
                .iter()
                .filter_map(|&role| owner.role_key(role).and_then(|key| key.spki()).ok())
                .filter_map(|spki| spki.to_der().ok())
                .collect()
        })
        .unwrap_or_default();

    let mut listings = Vec::new();
    for card in cards.iter().filter(|card| card.piv.is_some()) {
        // A card gone since it was asked is simply not listed
        let Ok(mut token) = open_reader(&card.reader) else {
            continue;
        };
        let mut listing = Listing {
            reader: card.reader.clone(),
            applet: "PIV",
            card: token.serial().to_string(),
            owner: None,
            holder: None,
            keys: Vec::new(),
        };

        if let Some(owner) = owner
            && owner.seeds.has_card()
        {
            listing.owner = Some(match owner.ownership(&Facts::read(&mut token)) {
                Ok(ownership) => format!("{ownership}"),
                Err(err) => format!("cannot tell whose ({err})"),
            });
        }

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

            let ours = cert
                .cert
                .tbs_certificate()
                .subject_public_key_info()
                .to_der()
                .is_ok_and(|spki| derived.contains(&spki));
            listing.keys.push(ListedKey {
                slot: slot.to_string(),
                fingerprint: match cert.cert.to_der() {
                    Ok(der) => format!("{:x}", Sha256::digest(der)),
                    Err(err) => format!("unreadable certificate: {err}"),
                },
                subject: Some(cert.subject().to_string()),
                ours,
            });
        }
        // Dropping a token resets the card, which would throw any other program off it
        let _ = token.disconnect(pcsc::Disposition::LeaveCard);
        listings.push(listing);
    }

    Ok(listings)
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
             number or its reader, as `list` shows them"
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
            anyhow!("No reader named '{}'; `list` shows the attached ones", common::printable(name))
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
            bail!("No PIV card with serial {serial} found; `list` shows the attached ones")
        }
    }
}

/// The serial number a PIV card reports, the way yubikey.rs reads it, or `None` for a card
/// without the PIV application or a serial
pub(crate) fn read_serial(transaction: &pcsc::Transaction<'_>) -> Option<u32> {
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
pub(super) fn describe(token: &YubiKey) -> String {
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

/// End the management session on a card that was written to
///
/// Dropping the session works by selecting the Yubico management applet, which only exists on
/// YubiKeys -- on other PIV implementations the authentication simply ends with the
/// connection, so a failure here must not fail the finished write.
pub(super) fn finish(token: &mut YubiKey) {
    if let Err(err) = token.deauthenticate() {
        log::warn!("Could not deauthenticate management key: {err}");
    }
}

/// Refuse a user pin a PIV card cannot take: six to eight ASCII characters
///
/// Counted in characters, not bytes: the card takes up to 8 bytes, but a multi-byte
/// character miscounted here would produce an off-by-N error message rather than a wrong
/// length on the card.
pub fn refuse_unfit_pin(pin: &str) -> Result<()> {
    let length = pin.chars().count();
    if !(6..=8).contains(&length) || !pin.is_ascii() {
        bail!("PIV pin needs to be between 6 and 8 ASCII characters")
    }
    Ok(())
}

/// Change the user pin of a PIV card, proven by the current one
///
/// Needs no seed: the pin is the card's own. A forgotten one is reset with the card seed's
/// derived puk instead, `pin --reset`.
pub fn change_pin(target: Option<CardTarget>, current: &str, new: &str) -> Result<()> {
    refuse_unfit_pin(new)?;
    let mut token = open_token(target)?;
    let lost = "set a new one with `pin --reset`, which takes the card seed";
    // GET METADATA tells the tries left; without it the empty VERIFY has to do, which answers
    // as if none were left also when another program on a shared connection has verified
    // the pin, so there a zero decides nothing and the card's answer to the change does
    let remaining = piv::metadata(&mut token, SlotId::Management(piv::ManagementSlotId::Pin))
        .ok()
        .and_then(|metadata| metadata.retries)
        .map(|retries| retries.remaining_count)
        .or_else(|| token.get_pin_retries().ok().filter(|tries| *tries > 0));
    match remaining {
        Some(0) => bail!("The card's user pin is blocked; {lost}"),
        Some(1) => bail!(
            "The card's user pin has one try left, and a wrong current pin would block it; \
             {lost}"
        ),
        _ => {}
    }
    match token.change_pin(current.as_bytes(), new.as_bytes()) {
        Ok(()) => {}
        Err(CardError::WrongPin { tries }) => {
            bail!("The current pin is wrong, {tries} tries left; if it is forgotten, {lost}")
        }
        Err(CardError::PinLocked) => bail!("The card's user pin is now blocked; {lost}"),
        Err(err) => return Err(err.into()),
    }
    log::info!("User pin changed on {}", describe(&token));
    Ok(())
}

/// Whether authenticating to the management key will wait for a touch
///
/// What the card reports wins; a card without GET METADATA cannot say, and then the policy
/// it was presumably provisioned under has to do.
fn management_touch_prompt(reported: Option<TouchPolicy>, policy: bool) -> bool {
    match reported {
        Some(touch) => touch != TouchPolicy::Never,
        None => policy,
    }
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
    /// Reset a card and give it what the card seed derives for it: the management key, the
    /// user pin and the puk, the CHUID and CCC, and the 9E key with its certificate
    ///
    /// No key of the identity's: `upload` adds those, under the management key installed here.
    pub(super) fn init(&self, target: Option<CardTarget>) -> Result<()> {
        let mut token = open_token(target)?;
        self.refuse_unfit(&token, &[SlotRole::CardAuthentication])?;
        let serial = CardSerial::piv(token.serial().into());
        // Derived before the reset, so that a failure here never leaves a wiped card behind
        let nine_e_key = self.card_authentication_key(self.algorithm, &serial)?;
        let nine_e = self.card_authentication_certificate_of(&nine_e_key, &serial)?;

        reset(&mut token)?;
        let algorithm = self.install_credentials(&mut token, &serial)?;

        log::info!("Storing card identifiers in CHUID and CCC");
        ChuId(self.chuid(&serial)?).set(&mut token)?;
        CccId(self.ccc(&serial)?).set(&mut token)?;

        log::info!("Uploading the card authentication key");
        let slot = SlotId::CardAuthentication;
        nine_e_key.import(&mut token, slot, TouchPolicy::Never, PinPolicy::Never)?;
        verify_import(&mut token, slot, &nine_e)?;
        write_certificate(&mut token, slot, &nine_e)?;

        // Everything is on the card, so future management access can now demand a touch. Done
        // last on purpose: setting the flag needs no touch itself (we are still authenticated),
        // and leaving it until the end means a card is never wiped for a button that was not
        // pressed in time. A card that opts out keeps the key installed without the flag: a
        // build server's card is initialized on an air-gapped machine, and the derived
        // management key never reaches the server it then lives in, so the touch would guard
        // nothing there while costing every unattended re-check a button press.
        if self.policy.management_touch() {
            log::info!("Requiring touch for future management access");
            // A card that refuses the flag (stock piv-authenticator rejects P2=FE) keeps a
            // working initialization; `check` reports the missing touch as a policy mismatch
            if let Err(err) = self
                .management_key(algorithm, &serial)?
                .set_manual(&mut token, true)
            {
                log::warn!("The card refused a touch requirement for management access: {err}");
            }
        } else {
            log::info!("Management access stays touch-free, as the policy asks for no touch");
        }
        finish(&mut token);
        Ok(())
    }

    /// Authenticate to a card this card seed initialized, with its derived management key
    ///
    /// The management key's algorithm is read off the card, since the derivation for each
    /// is fixed. The touch prompt follows what the card reports for its management key, and
    /// the policy where it cannot report it: a card initialized under another policy than the
    /// one given now still gets its prompt.
    pub(super) fn authenticate(
        &self,
        token: &mut YubiKey,
        serial: &CardSerial,
    ) -> Result<MgmAlgorithmId> {
        let algorithm = MgmAlgorithmId::current(token)?;
        let reported = piv::metadata(token, SlotId::Management(piv::ManagementSlotId::Management))
            .ok()
            .and_then(|metadata| metadata.policy)
            .map(|(_, touch)| touch);
        let touch = management_touch_prompt(reported, self.policy.management_touch());

        // The prompt goes to stderr: stdout may be carrying PEM or a report, and a buried
        // prompt is a missed touch and a failed run
        log::info!("Verifying smart card {algorithm:?} management key");
        if touch {
            eprintln!("[Please touch device to authenticate management access!]");
        }
        token.authenticate(&self.management_key(algorithm, serial)?)?;
        if touch {
            eprintln!();
        }
        Ok(algorithm)
    }

    /// Open the card `init` would wipe, refuse it if it cannot hold the card's own key, and
    /// name it
    ///
    /// Meant for the confirmation: the question can name the card, and a card that would be
    /// wiped for nothing is refused while it is still intact. `init` repeats the check on
    /// the card it opens itself.
    pub(super) fn preflight(&self, target: Option<CardTarget>) -> Result<String> {
        let token = open_token(target)?;
        self.refuse_unfit(&token, &[SlotRole::CardAuthentication])?;
        Ok(describe(&token))
    }

    /// Open the card `wipe` would reset and refuse it unless this card seed initialized it,
    /// or `force` says it may be anyone's; returns the card's name for the confirmation
    pub(super) fn plan_wipe(&self, target: Option<CardTarget>, force: bool) -> Result<String> {
        let mut token = open_token(target)?;
        if !force {
            self.refuse_unowned(&mut token, "wiped")?;
        }
        Ok(describe(&token))
    }

    /// Reset the card's PIV application, as `plan_wipe` named it; the card is left with the
    /// factory pin, puk and management key, and nothing else
    pub(super) fn wipe(&self, target: Option<CardTarget>, force: bool) -> Result<()> {
        let mut token = open_token(target)?;
        if !force {
            self.refuse_unowned(&mut token, "wiped")?;
        }
        reset(&mut token)?;
        log::info!("Wiped {}", describe(&token));
        Ok(())
    }

    /// Refuse a card this card seed did not initialize, before anything is spent on it
    pub(super) fn refuse_unowned(&self, token: &mut YubiKey, what: &str) -> Result<()> {
        let ownership = self.ownership(&Facts::read(token))?;
        if ownership != Ownership::Owned {
            let hint = match ownership {
                Ownership::Blank => "`init` gives it what the card seed derives",
                _ => "give the card seed it was initialized with, or reset it with `init`",
            };
            bail!("The card is {ownership}, so it cannot be {what}; {hint}");
        }
        Ok(())
    }

    /// Set a new user pin on a card this card seed initialized, with its derived puk
    ///
    /// The current pin is not needed, so this recovers a forgotten or blocked one without a
    /// reset: the keys stay where they are.
    pub(super) fn reset_pin(&self, target: Option<CardTarget>, new: &str) -> Result<()> {
        refuse_unfit_pin(new)?;
        let mut token = open_token(target)?;
        self.refuse_unowned(&mut token, "unblocked")?;
        let serial = CardSerial::piv(token.serial().into());
        // The card counts the puk's tries like the pin's; only GET METADATA tells them, and a
        // card without it is trusted to its ownership, which this card seed just proved
        let remaining = piv::metadata(&mut token, SlotId::Management(piv::ManagementSlotId::Puk))
            .ok()
            .and_then(|metadata| metadata.retries)
            .map(|retries| retries.remaining_count);
        match remaining {
            Some(0) => bail!(
                "The card's puk is blocked, so only a reset brings it back: `init`, then `upload`"
            ),
            Some(1) => bail!(
                "The card's puk has one try left, and a wrong card seed would block it for good; \
                 check the card seed, or reset the card with `init`"
            ),
            _ => {}
        }
        token.unblock_pin(self.puk(&serial)?.as_bytes(), new.as_bytes())?;
        log::info!("User pin reset on {}", describe(&token));
        Ok(())
    }

    /// Install the derived management key, the user pin and the derived puk on a freshly
    /// reset card, leaving it authenticated under the new management key
    ///
    /// Returns the algorithm of the installed management key.
    fn install_credentials(
        &self,
        token: &mut YubiKey,
        serial: &CardSerial,
    ) -> Result<MgmAlgorithmId> {
        // Authenticate with the default key in whatever algorithm the reset installed: the
        // firmware version table behind `MgmKey::get_default` only knows YubiKeys
        let algorithm = MgmAlgorithmId::current(token)?;
        let default = MgmKey::from_bytes(DEFAULT_MANAGEMENT_KEY, Some(algorithm))?;
        token.authenticate(&default)?;

        // Install our management key, but *without* the touch requirement for now.
        //
        // Requiring a touch at this point means a missed button press aborts after the reset
        // has already wiped the card, leaving it bare with nothing in exchange, and the
        // prompt only lasts as long as the token's touch timeout. The touch is switched on at
        // the end of `init` instead, where the same failure costs nothing.
        let mut algorithm = self.management_algorithm(token);
        log::info!("Installing the derived {algorithm:?} management key");
        let mut mgmt_key = self.management_key(algorithm, serial)?;
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
            mgmt_key = self.management_key(algorithm, serial)?;
            mgmt_key.set_manual(token, false)?;
        }
        token.authenticate(&mgmt_key)?;

        if let Some(pin) = &self.pin {
            token.change_pin(common::FACTORY_USER_PIN.as_bytes(), pin.as_bytes())?;
        }

        log::info!("Installing the derived puk");
        let puk = self.puk(serial)?;
        debug_assert_eq!(puk.len(), PUK_LENGTH);
        token.change_puk(FACTORY_PUK.as_bytes(), puk.as_bytes())?;

        Ok(algorithm)
    }

    /// Refuse a card that cannot take what is about to be written to `roles`, before anything
    /// on it changes
    ///
    /// A YubiKey is judged by its firmware version, whether its reader names it or, held to
    /// an NFC reader, it lists no algorithms and reports a YubiKey's firmware. Other PIV cards
    /// are judged by the algorithms their SELECT response lists, where they list any; a card
    /// that lists nothing can only answer with the import itself. piv-authenticator lists every algorithm
    /// it knows whatever its build carries until its pending change to list only what the
    /// build supports is released, so on today's builds this check passes and the import
    /// remains the first answer.
    pub(super) fn refuse_unfit(&self, token: &YubiKey, roles: &[SlotRole]) -> Result<()> {
        let version = token.version();
        let firmware = format!("{}.{}.{}", version.major, version.minor, version.patch);
        let initializing = roles.contains(&SlotRole::CardAuthentication);
        if !token.name().starts_with("Yubico") {
            let missing = token
                .piv_application_properties()
                .and_then(|properties| self.unlisted(properties, roles, initializing));
            match missing {
                Some(missing) if !missing.is_empty() => bail!(
                    "The card lists the algorithms it supports, and {} is not among them; \
                     the card was not touched",
                    missing.join(" or ")
                ),
                Some(_) => return Ok(()),
                // The reader names a YubiKey on USB, but not one held to an NFC reader: a
                // card that lists nothing and reports a YubiKey's firmware is judged as one
                None if matches!(version.major, 4 | 5) => {}
                None => {
                    log::warn!(
                        "Not a YubiKey: whether the card imports {} keys shows only on the import",
                        self.algorithm
                    );
                    return Ok(());
                }
            }
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
        if initializing
            && self.management_algorithm == ManagementKeyArg::Aes256
            && version < FIRST_AES_MANAGEMENT
        {
            bail!(
                "YubiKey firmware {firmware} takes 3DES management keys only (AES from 5.4); \
                 use --management-algorithm auto or tdes. The card was not touched"
            );
        }
        let cached = roles.iter().any(|role| {
            *role != SlotRole::CardAuthentication
                && self.policies_for(role.slot()).1 == TouchPolicy::Cached
        });
        if cached && version < FIRST_CACHED_TOUCH {
            bail!(
                "YubiKey firmware {firmware} has no cached touch policy (4.3 and later have); \
                 pass a --policy without cached touch, such as strict or never-touch. The \
                 card was not touched"
            );
        }
        Ok(())
    }

    /// What a card's algorithm list leaves out of what is about to be written to `roles`, or
    /// `None` if the card lists no algorithms to judge by
    ///
    /// `auto` settles on AES-256 or falls back to 3DES, so initializing needs one of the two;
    /// an explicit management key algorithm needs exactly that one.
    pub(super) fn unlisted(
        &self,
        properties: &piv::ApplicationProperties,
        roles: &[SlotRole],
        initializing: bool,
    ) -> Option<Vec<String>> {
        let mut missing: Vec<String> = Vec::new();
        for role in roles {
            let algorithm = role.card_algorithm(self.algorithm);
            let name = card_algorithm_name(algorithm).to_string();
            if !properties.supports(algorithm)? && !missing.contains(&name) {
                missing.push(name);
            }
        }
        if !initializing {
            return Some(missing);
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

    /// Algorithm of the management key `init` installs on `token`
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

    /// The CHUID the card with this serial carries, its Card UUID derived from the card seed
    ///
    /// Windows smartcard logon and a good deal of middleware refuse a card carrying neither a
    /// CHUID nor a CCC. Both identifiers are *derived* rather than generated (where
    /// `CardId::generate` would pick a random one), so that re-initializing from the same
    /// card seed reproduces the same card, and each has its own label rather than a slice of
    /// a shared derivation, so a format changing width cannot disturb the others.
    pub(super) fn chuid(&self, serial: &CardSerial) -> Result<[u8; ChuId::BYTE_SIZE]> {
        let mut chuid = CHUID_TEMPLATE;
        chuid[CHUID_GUID_OFFSET..CHUID_GUID_OFFSET + 16].copy_from_slice(&self.chuid_guid(serial)?);
        Ok(chuid)
    }

    /// The CCC the card with this serial carries, its card identifier derived from the card seed
    pub(super) fn ccc(&self, serial: &CardSerial) -> Result<[u8; CccId::BYTE_SIZE]> {
        let mut ccc = CCC_TEMPLATE;
        ccc[CCC_ID_OFFSET..CCC_ID_OFFSET + CardId::BYTE_SIZE]
            .copy_from_slice(&self.ccc_id(serial)?);
        Ok(ccc)
    }

    /// Import a usable key's derived bytes into `slot` under `policies`, and make sure the
    /// card holds the key `cert` certifies
    pub(super) fn import_slot(
        &self,
        token: &mut YubiKey,
        role: crate::role::KeyRole,
        slot: SlotId,
        cert: &X509Certificate,
        (pin_policy, touch_policy): (PinPolicy, TouchPolicy),
    ) -> Result<()> {
        log::info!("Uploading the {role} key into {slot:?}");

        // The very same derived bytes have to reach the card, otherwise the on-card key
        // and the key we just certified would diverge.
        self.role_key(role)?
            .import(token, slot, touch_policy, pin_policy)?;
        verify_import(token, slot, cert)
    }

    /// Store the certificate authorities in the card's `msroots` object
    pub(super) fn upload_msroots(&self, chain: &CertChain, token: &mut YubiKey) -> Result<()> {
        log::info!("Storing certificate authorities in msroots");

        // `msroots` holds a degenerate PKCS#7 certs-only SignedData blob
        let content = ContentInfo::try_from(chain.cas())?;
        MsRoots::new(content.to_der()?)?.write(token)?;

        Ok(())
    }
}

/// Make sure the card holds the key `cert` certifies, right after an import
///
/// A card without GET METADATA (YubiKey before 5.3) cannot say which key it holds; `check`
/// proves it by a signature challenge instead, which needs the pin and possibly a touch per
/// slot, too much to impose on every import.
fn verify_import(token: &mut YubiKey, slot: SlotId, cert: &X509Certificate) -> Result<()> {
    match piv::metadata(token, slot) {
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
    Ok(())
}

/// Reset a card's PIV application: spend the pin's and the puk's tries, which a card demands
/// before it lets itself be reset, then reset it to its factory credentials
fn reset(token: &mut YubiKey) -> Result<()> {
    log::info!("Locking smart card pin");
    exhaust("pin", "Card pin equals the lock-out pin; change it and retry", || {
        token.verify_pin(&DUMMY_PIN)
    })?;
    log::info!("Locking smart card puk");
    exhaust("puk", "Card puk is empty; set one and retry", || token.unblock_pin(b"", b""))?;
    log::info!("Resetting smart card");
    token.reset_device()?;
    Ok(())
}

/// Store a slot's certificate
pub(super) fn write_certificate(
    token: &mut YubiKey,
    slot: SlotId,
    cert: &X509Certificate,
) -> Result<()> {
    log::info!("Uploading {:?} certificate", slot);
    CardCertificate::from_bytes(cert.to_der()?)?.write(token, slot, CertInfo::Uncompressed)?;
    log::info!("Uploaded certificate with fingerprint '{:x}'", Sha256::digest(cert.to_der()?));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_management_touch_prompt_follows_the_card_over_the_policy() {
        // A card provisioned under another policy than the one given now still gets its prompt
        assert!(management_touch_prompt(Some(TouchPolicy::Always), false));
        assert!(management_touch_prompt(Some(TouchPolicy::Cached), false));
        assert!(!management_touch_prompt(Some(TouchPolicy::Never), true));
        // A card without GET METADATA cannot say, and the policy has to do
        assert!(management_touch_prompt(None, true));
        assert!(!management_touch_prompt(None, false));
    }
}
