//! Everything that talks to a card: the listing, check, init, wipe and the key import.

use super::ownership::{Facts, Fingerprints};
use super::{Kdf, KeyRole, P384_REFUSED, SeededSmartcard, import::RawEccKey, import::RawRsaKey};
use crate::common;
use crate::ownership::{ListedKey, Listing, Ownership};
use crate::policy::Touch;
use crate::readers;
use crate::seed::{Algorithm, CardSerial};
use crate::target::{Attached, CardTarget};

use std::ffi::CString;
use std::time::SystemTime;

use anyhow::{Result, anyhow, bail};

use zeroize::Zeroizing;

use openpgp::cert::Cert;
use openpgp::crypto::mpi;
use openpgp::fmt::hex;
use openpgp::packet::{Key, key};
use openpgp::policy::StandardPolicy;
use sequoia_openpgp as openpgp;

use secrecy::SecretString;

use card_backend_pcsc::PcscBackend;

use openpgp_card::ocard::KeyType;
use openpgp_card::ocard::algorithm::Curve as CardCurve;
use openpgp_card::ocard::crypto::EccType;
use openpgp_card::{Card, Error as CardError};

use openpgp_card::ocard::algorithm::AlgorithmAttributes;
use openpgp_card::ocard::data::{
    ApplicationIdentifier, Fingerprint as CardFingerprint, KdfDo, KeyGenerationTime, Lang,
    TouchPolicy, UserInteractionFlag,
};
use openpgp_card::state::{Admin, Open, Transaction};

/// What `list` shows of every attached card with an OpenPGP application
///
/// With a card seed at hand (`owner`), each card also says whether it initialized it, and with
/// a key seed which keys are its own. That is read without a pin, so the listing spends no
/// tries, asks for no touch and leaves every card as it was found.
pub fn list(owner: Option<&SeededSmartcard>, cards: &[Attached]) -> Result<Vec<Listing>> {
    // Derived once, not per card: an RSA certificate takes seconds to derive
    let keys = owner
        .filter(|owner| owner.seeds.has_key())
        .map(|owner| owner.fingerprints(&owner.signed_cert()?))
        .transpose()?;

    let readers = cards
        .iter()
        .filter(|card| card.pgp.is_some())
        .filter_map(|card| CString::new(card.reader.clone()).ok());
    let mut listings = Vec::new();
    for card in summaries_in(&readers::context()?, readers) {
        let mut listing = Listing {
            reader: card.reader.to_string_lossy().into_owned(),
            applet: "OpenPGP",
            card: card.aid.ident(),
            owner: None,
            holder: (!card.name.is_empty()).then(|| card.name.clone()),
            keys: Vec::new(),
        };
        if let Some(owner) = owner
            && owner.seeds.has_card()
        {
            listing.owner = Some(match owner.ownership(&card.facts(), keys.as_ref()) {
                Ok(ownership) => format!("{ownership}"),
                Err(err) => format!("cannot tell whose ({err})"),
            });
        }
        for (role, fingerprint) in KeyRole::PGP.iter().zip(card.keys) {
            if let Some(fingerprint) = fingerprint {
                let ours = keys.as_ref().is_some_and(|keys| {
                    fp_bytes(&fingerprint).is_some_and(|bytes| {
                        keys.iter()
                            .any(|(r, expected)| r == role && *expected == bytes)
                    })
                });
                listing.keys.push(ListedKey {
                    slot: role.name().to_string(),
                    fingerprint: fingerprint.to_string(),
                    subject: None,
                    ours,
                });
            }
        }
        listings.push(listing);
    }
    Ok(listings)
}

/// The identifier of the OpenPGP card in a transaction, or `None` for a card without the
/// OpenPGP application
pub(crate) fn read_ident(transaction: &pcsc::Transaction<'_>) -> Option<String> {
    readers::transmit(transaction, &readers::select(&OPENPGP_AID))?;
    let aid = readers::transmit(transaction, &GET_DATA_AID)?;
    ApplicationIdentifier::try_from(aid.as_slice())
        .ok()
        .map(|aid| aid.ident())
}

/// What `status` and the card choice show of one OpenPGP card
struct Summary {
    reader: CString,
    aid: ApplicationIdentifier,
    name: String,
    /// Signing, decryption and authentication fingerprint, `None` for an empty slot
    keys: [Option<CardFingerprint>; 3],
    /// The private-use data object 0102, where `init` names the card's card seed
    identifier: Option<Vec<u8>>,
}

impl Summary {
    /// What ownership is decided from
    fn facts(&self) -> Facts {
        Facts {
            serial: serial_of(&self.aid),
            identifier: self.identifier.clone(),
            keys: self
                .keys
                .each_ref()
                .map(|fingerprint| fingerprint.as_ref().and_then(fp_bytes)),
        }
    }
}

/// The serial a card's credentials and identifier are bound to: its manufacturer and serial
fn serial_of(aid: &ApplicationIdentifier) -> CardSerial {
    CardSerial::pgp(aid.manufacturer(), aid.serial())
}

/// The OpenPGP cards attached, read over plain PC/SC and left as they were
///
/// Opening each card through `openpgp-card` would reset every one of them when it is
/// dropped, throwing off any other program using a card, a parallel test run included.
fn summaries() -> Result<Vec<Summary>> {
    let (context, readers) = readers::list()?;
    Ok(summaries_in(&context, readers))
}

/// The OpenPGP cards in `readers`, read as [`summaries`] reads them
fn summaries_in(
    context: &pcsc::Context,
    readers: impl IntoIterator<Item = CString>,
) -> Vec<Summary> {
    let mut cards = Vec::new();
    for reader in readers {
        // An empty reader, or a card another program holds exclusively, has nothing to show
        let Ok(Some(card)) =
            readers::ask(context, &reader, |transaction| read_summary(transaction, reader.clone()))
        else {
            continue;
        };
        cards.push(card);
    }
    cards
}

/// What `status` shows of the card in a transaction, `None` without an OpenPGP application
fn read_summary(transaction: &pcsc::Transaction<'_>, reader: CString) -> Option<Summary> {
    readers::transmit(transaction, &readers::select(&OPENPGP_AID))?;
    let aid = readers::transmit(transaction, &GET_DATA_AID)?;
    let aid = ApplicationIdentifier::try_from(aid.as_slice()).ok()?;

    // The name is ISO 8859-1 on the card, as `openpgp-card` reads it too
    let holder = readers::transmit(transaction, &GET_DATA_CARDHOLDER).unwrap_or_default();
    let name = readers::find_tlv(&holder, 0x5B)
        .map(|name| name.iter().map(|&byte| char::from(byte)).collect())
        .unwrap_or_default();

    let related = readers::transmit(transaction, &GET_DATA_APPLICATION_RELATED).unwrap_or_default();
    let mut keys = [None, None, None];
    if let Some(fingerprints) = readers::find_tlv(&related, 0xC5) {
        for (slot, chunk) in keys.iter_mut().zip(fingerprints.chunks_exact(20)) {
            if chunk.iter().any(|&byte| byte != 0) {
                *slot = CardFingerprint::try_from(chunk).ok();
            }
        }
    }

    // Read only where the card announces private-use data objects (extended capabilities,
    // first byte, bit 4): one without them may answer for 0102 all the same, with an object
    // of its own, as CanoKey does with its touch cache time
    let private_use = readers::find_tlv(&related, 0xC0)
        .and_then(|capabilities| capabilities.first())
        .is_some_and(|byte| byte & 0x08 != 0);
    let identifier = private_use
        .then(|| readers::transmit(transaction, &GET_DATA_PRIVATE_USE))
        .flatten()
        .filter(|identifier| !identifier.is_empty());
    Some(Summary { reader, aid, name, keys, identifier })
}

/// Ownership facts of the card in an open transaction, as `status` reads them over PC/SC
pub(super) fn card_facts(card: &mut Card<Transaction<'_>>) -> Result<Facts> {
    let keys = KeyRole::PGP.map(|role| {
        card.fingerprint(role.key_type())
            .ok()
            .flatten()
            .and_then(|fp| fp_bytes(&fp))
    });
    // As in the listing: only a card that announces private-use data objects has one there
    let private_use = card
        .extended_capabilities()
        .is_ok_and(|capabilities| capabilities.private_use_dos());
    let identifier = private_use
        .then(|| card.private_use_do(CARD_IDENTIFIER_DO).ok())
        .flatten()
        .filter(|identifier| !identifier.is_empty());
    Ok(Facts {
        serial: serial_of(&card.application_identifier()?),
        identifier,
        keys,
    })
}

/// A card fingerprint as plain bytes, `None` for one that is not 20 bytes long
fn fp_bytes(fingerprint: &CardFingerprint) -> Option<[u8; 20]> {
    fingerprint.as_bytes().try_into().ok()
}

/// The OpenPGP application, as SELECT names it
const OPENPGP_AID: [u8; 6] = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
/// GET DATA of the application identifier (4F)
const GET_DATA_AID: [u8; 5] = [0x00, 0xCA, 0x00, 0x4F, 0x00];
/// GET DATA of the cardholder related data (65), where the name is
const GET_DATA_CARDHOLDER: [u8; 5] = [0x00, 0xCA, 0x00, 0x65, 0x00];
/// GET DATA of the application related data (6E), where the fingerprints are
const GET_DATA_APPLICATION_RELATED: [u8; 5] = [0x00, 0xCA, 0x00, 0x6E, 0x00];
/// GET DATA of the private-use data object 0102, where the card identifier is
const GET_DATA_PRIVATE_USE: [u8; 5] = [0x00, 0xCA, 0x01, 0x02, 0x00];
/// The private-use data object `init` names the card's card seed in: 0102, which anyone can
/// read and only the admin pin can write, where 0101 would take the user pin's word for it
pub(super) const CARD_IDENTIFIER_DO: u8 = 2;

/// SHA-256 in the KDF data object, the one hash Gnuk takes there
const KDF_SHA256: u8 = 0x08;

// Determine smartcard to which to connect based on optional target string
pub(super) fn open_card(target: Option<CardTarget>) -> Result<Card<Open>> {
    let reader = match target {
        Some(CardTarget::Ident(ident)) => reader_of(&ident)?.ok_or_else(|| {
            CardError::NotFound(format!("Card '{ident}' not found; `list` shows the attached ones"))
        })?,
        Some(CardTarget::Reader(name)) => CString::new(name)?,
        Some(CardTarget::Serial(serial)) => bail!(
            "--card {serial} is a PIV serial number; name an OpenPGP card by its identifier \
             (MMMM:SSSSSSSS) or its reader, as `list` shows them"
        ),
        None => {
            let mut cards = summaries()?;
            match cards.len() {
                0 => bail!("No OpenPGP card detected, please insert card"),
                1 => cards.remove(0).reader,
                n => {
                    let cards: Vec<String> = cards
                        .iter()
                        .map(|card| {
                            format!(
                                "  {} OpenPGP card {} in '{}'",
                                card.aid.manufacturer_name(),
                                card.aid.ident(),
                                common::printable(&card.reader.to_string_lossy())
                            )
                        })
                        .collect();
                    bail!(
                        "{n} OpenPGP cards are attached, pick one with --card <ident>:\n{}",
                        cards.join("\n")
                    )
                }
            }
        }
    };

    let context = crate::readers::context()?;
    let backend = PcscBackend::from_pcsc_reader(&context, &reader, None).map_err(|err| {
        anyhow!(
            "Cannot open the card in reader '{}': {err}; `list` shows the attached ones",
            common::printable(&reader.to_string_lossy())
        )
    })?;
    Ok(Card::new(backend)?)
}

/// The reader holding the OpenPGP card `ident`, found without disturbing the other cards
fn reader_of(ident: &str) -> Result<Option<CString>> {
    let (context, readers) = readers::list()?;
    for reader in readers {
        // An empty reader, or a card another program holds exclusively, is not this one
        let found = readers::ask(&context, &reader, |transaction| {
            readers::transmit(transaction, &readers::select(&OPENPGP_AID))?;
            let aid = readers::transmit(transaction, &GET_DATA_AID)?;
            ApplicationIdentifier::try_from(aid.as_slice()).ok()
        });
        if let Ok(Some(aid)) = found
            && aid.ident().eq_ignore_ascii_case(ident)
        {
            return Ok(Some(reader));
        }
    }
    Ok(None)
}

/// Report the card's touch policies, informational only
fn report_touch_policies(transaction: &mut Card<Transaction<'_>>) {
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

/// Refuse to spend the last try of the admin pin
///
/// The admin pin is derived per card seed and card, so a wrong card seed costs a try, and
/// three lock the card for good. With one try left, the next mistake is that lock; only
/// `init`, which resets the card, may go on.
pub(super) fn guard_admin_tries(card: &mut Card<Transaction<'_>>) -> Result<()> {
    match card.pw_status_bytes()?.err_count_pw3() {
        0 => bail!("The card's admin pin is blocked; only `init` can recover the card"),
        1 => bail!(
            "The card's admin pin has one try left, and a wrong card seed would block it; \
             check the card seed, or reset the card with `init`"
        ),
        2 => log::warn!("The card's admin pin has two tries left: an earlier attempt failed"),
        _ => {}
    }
    Ok(())
}

/// The card as the confirmation and the logs name it: manufacturer and ident
pub(super) fn describe(card: &Card<Transaction<'_>>) -> Result<String> {
    let aid = card.application_identifier()?;
    Ok(format!("{} OpenPGP card {}", aid.manufacturer_name(), aid.ident()))
}

impl SeededSmartcard {
    /// Give one key the policy's touch requirement, advisorily: no card must lose its keys
    /// over a touch flag
    ///
    /// `write_off` writes an off policy too, which an update needs to turn a touch off; after
    /// a reset every key's touch is off already, and writing it would only risk a refusal.
    pub(super) fn set_policy_touch(
        &self,
        admin: &mut Card<openpgp_card::state::Admin<'_, '_>>,
        kt: KeyType,
        write_off: bool,
    ) {
        let fixed = self.fixed_touch;
        let (wanted, fallback) = match (self.policy.pgp_touch(), fixed) {
            // A reset leaves every key's touch off already, and writing it would only risk a
            // refusal on cards without the flag; there is no fixed variant of off
            (Touch::Never, _) => {
                if fixed {
                    log::info!("No touch to fix for the {kt:?} key: the policy asks for none");
                }
                if write_off && let Err(err) = set_touch_policy(admin, kt, TouchPolicy::Off) {
                    log::warn!("Card refused to turn off the touch for the {kt:?} key ({err})");
                }
                return;
            }
            (Touch::Always, false) => (TouchPolicy::On, None),
            (Touch::Always, true) => (TouchPolicy::Fixed, Some(TouchPolicy::On)),
            // Cached is a Yubico extension to the flag that a spec-conforming card (the
            // Nitrokey 3's opcard, Gnuk) and a YubiKey 4 refuse; plain on is the closest
            (Touch::Cached, false) => (TouchPolicy::Cached, Some(TouchPolicy::On)),
            (Touch::Cached, true) => (TouchPolicy::CachedFixed, Some(TouchPolicy::Fixed)),
        };
        let Err(refused) = set_touch_policy(admin, kt, wanted) else {
            return;
        };
        let Some(fallback) = fallback else {
            log::warn!(
                "Card refused a touch policy for the {kt:?} key ({refused}); \
                 choose a --policy it supports"
            );
            return;
        };
        // A card without the fixed variants may still take the plain one
        let attempts = [Some(fallback), fixed.then_some(TouchPolicy::On)];
        for attempt in attempts.into_iter().flatten() {
            if set_touch_policy(admin, kt, attempt).is_ok() {
                log::info!(
                    "Card refused the {wanted:?} touch policy for the {kt:?} key ({refused}), \
                     set {attempt:?} instead"
                );
                return;
            }
        }
        log::warn!(
            "Card refused a touch policy for the {kt:?} key ({refused}); \
             choose a --policy it supports"
        );
    }
}

/// Set the touch policy of one key, on cards that predate OpenPGP card 3 as well
///
/// `openpgp-card` looks the user interaction flags up in the application related data,
/// where only version 3 cards list them. A YubiKey 4 speaks version 2.1 and still has the
/// flags, at the same data objects, so when the lookup comes back empty they are written
/// directly, with the button as the card's interaction feature.
/// Make a card fresh from a reset take hashed pins
///
/// The data object names the scheme, fresh salts and the factory pins' hashes under them,
/// so the factory pins keep opening the card until `init` changes them, now as hashes. The
/// salts are public, readable by any client that has to hash a pin.
fn set_up_kdf(card: &mut Card<Transaction<'_>>) -> Result<()> {
    let mut salts = [[0u8; 8]; 3];
    for salt in &mut salts {
        getrandom::fill(salt).map_err(|err| anyhow!("No randomness for the KDF salts: {err}"))?;
    }
    let [user, reset, admin] = salts.map(|salt| salt.to_vec());
    let kdf = KdfDo::iter_salted(KDF_SHA256, user, reset, admin)?;
    // Writing it takes the admin pin, which is the factory one and still goes as typed
    card.verify_admin_pin(SecretString::from(common::FACTORY_ADMIN_PIN.to_string()))?;
    card.card().set_kdf_do(&kdf)?;
    // The pins are hashed from here on, under the data object just written
    card.invalidate_cache()?;
    log::info!("The card takes its pins hashed, through the KDF data object");
    Ok(())
}

pub(super) fn set_touch_policy(
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
    /// Check that an available OpenPGP card holds what the seeds derive
    ///
    /// With the key seed, the chosen keys' fingerprints first: comparing them costs no pin
    /// retries. With the card seed, whose card it is, and only then the admin pin, which a
    /// wrong card seed would spend a try of.
    pub(super) fn check(&self, target: Option<CardTarget>) -> Result<()> {
        let keys = self
            .seeds
            .has_key()
            .then(|| self.fingerprints(&self.signed_cert()?))
            .transpose()?;

        let mut card = open_card(target)?;
        let mut transaction = card.transaction()?;
        log::info!("Connected to {}", describe(&transaction)?);
        let mut mismatches = Vec::new();
        if let Some(keys) = &keys {
            self.check_subkeys(keys, &mut transaction, &mut mismatches);
        }

        if self.seeds.has_card() {
            let ownership = self.ownership(&card_facts(&mut transaction)?, keys.as_ref())?;
            println!("Card seed: {ownership}");
            // A card without room for the identifier cannot show whose it is, so the admin
            // pin has to tell, as it does for an upload
            let private_use = transaction
                .extended_capabilities()
                .is_ok_and(|capabilities| capabilities.private_use_dos());
            match ownership {
                Ownership::Owned => self.authenticate(&mut transaction).map(drop)?,
                _ if !private_use => self.authenticate(&mut transaction).map(drop)?,
                other => mismatches.push(format!("card seed: {other}")),
            }
        }

        // And that the supplied user pin, if any, actually opens the card
        self.check_user_pin(&mut transaction)?;

        // Advisory, like PIV's policy lines: say what the card's touch policies are, since
        // upload shapes them and nothing else surfaces them, and which differ from --policy
        report_touch_policies(&mut transaction);
        self.warn_policy_differences(&mut transaction);

        crate::common::report_mismatches("card", &mismatches)
    }

    /// The certificate with the chosen subkeys, to compare a card's fingerprints with
    ///
    /// The primary has to be *signed*: the subkeys are looked up under the standard policy,
    /// and a bare primary key packet carries no binding signature at all, so an unsigned one
    /// fails with "No binding signature" before any card is consulted. The direct key
    /// signature does not affect the subkey fingerprints being compared.
    pub(super) fn signed_cert(&self) -> Result<Cert> {
        let cert = self.primary_cert(true, None)?;
        self.append_subkeys(cert, None)
    }

    /// Reset a card and give it what the card seed derives for it: the admin pin and the card
    /// identifier, with the user pin given and the language preferences
    ///
    /// No key of the identity's: `upload` adds those, under the admin pin installed here.
    pub(super) fn init(&self, target: Option<CardTarget>) -> Result<()> {
        let mut card = open_card(target)?;
        let mut transaction = card.transaction()?;
        log::info!("Connected to {}", describe(&transaction)?);
        self.refuse_unfit(&mut transaction)?;
        let serial = serial_of(&transaction.application_identifier()?);
        let admin_pin = self.admin_pin(&serial)?;

        let kdf = self.wants_kdf(&mut transaction)?;
        transaction.factory_reset()?;
        if kdf {
            set_up_kdf(&mut transaction)?;
        }
        transaction.change_admin_pin(
            SecretString::from(common::FACTORY_ADMIN_PIN.to_string()),
            SecretString::from(admin_pin.as_str().to_owned()),
        )?;

        {
            // Verify and elevation in one step
            let mut admin =
                transaction.as_admin_card(SecretString::from(admin_pin.as_str().to_owned()))?;
            let langs: Vec<Lang> = if self.card_data.lang.is_empty() {
                vec![['e', 'n'].into()]
            } else {
                self.card_data
                    .lang
                    .iter()
                    .map(|code| Lang::Value(*code))
                    .collect()
            };
            admin.set_lang(&langs)?;
            self.write_card_identifier(&mut admin, &serial)?;
        }

        // Gnuk wraps the keys it holds under the user pin and refuses to change it while it
        // holds none: such a card keeps the factory pin until `pin` changes it after `upload`
        if let Some(pin) = self.pin.as_ref()
            && let Err(err) = transaction.change_user_pin(
                SecretString::from(common::FACTORY_USER_PIN.to_string()),
                SecretString::from(pin.as_str().to_owned()),
            )
        {
            log::warn!(
                "The card refused a new user pin before it holds keys ({err}); it keeps the \
                 factory pin {} until `pin` changes it after `upload`",
                common::FACTORY_USER_PIN
            );
        }
        Ok(())
    }

    /// Open the card `init` would wipe, refuse it if it cannot take what the card seed derives,
    /// and name it
    ///
    /// Meant for the confirmation: the question can name the card, and a card that would be
    /// wiped for nothing is refused while it is still intact. `init` repeats the check on
    /// the card it opens itself.
    pub(super) fn preflight(&self, target: Option<CardTarget>) -> Result<String> {
        let mut card = open_card(target)?;
        let mut transaction = card.transaction()?;
        self.refuse_unfit(&mut transaction)?;
        describe(&transaction)
    }

    /// Open the card `wipe` would reset and refuse it unless this card seed initialized it,
    /// or `force` says it may be anyone's; returns the card's name for the confirmation
    pub(super) fn plan_wipe(&self, target: Option<CardTarget>, force: bool) -> Result<String> {
        let mut card = open_card(target)?;
        let mut transaction = card.transaction()?;
        if !force {
            self.refuse_unowned(&mut transaction, None, "wiped")?;
        }
        describe(&transaction)
    }

    /// Reset the card's OpenPGP application, as `plan_wipe` named it; the card is left with the
    /// factory pins and nothing else
    pub(super) fn wipe(&self, target: Option<CardTarget>, force: bool) -> Result<()> {
        let mut card = open_card(target)?;
        let mut transaction = card.transaction()?;
        if !force {
            self.refuse_unowned(&mut transaction, None, "wiped")?;
        }
        transaction.factory_reset()?;
        log::info!("Wiped {}", describe(&transaction)?);
        Ok(())
    }

    /// Refuse a card that cannot take what `init` and `upload` install, before anything on it
    /// changes
    ///
    /// A card that fails half way is left wiped, with pins of our choosing and without the
    /// keys. Everything that decides those steps is readable without a pin.
    fn refuse_unfit(&self, card: &mut Card<Transaction<'_>>) -> Result<()> {
        let status = card.pw_status_bytes()?;
        // Under the KDF data object the card is sent each pin's 32-byte digest, whatever
        // the pin's length
        let hashed = self.wants_kdf(card)?;
        let pin = self.pin.as_ref().map_or(6, |pin| pin.len());
        if !hashed && pin > usize::from(status.pw1_max_len()) {
            bail!(
                "The card takes user pins of up to {} characters, this one has {pin}; \
                 the card was not touched",
                status.pw1_max_len()
            );
        }
        let serial = serial_of(&card.application_identifier()?);
        let admin = self.admin_pin(&serial)?.len();
        if !hashed && admin > usize::from(status.pw3_max_len()) {
            bail!(
                "The card takes admin pins of up to {} characters, the derived one has {admin}; \
                 the card was not touched",
                status.pw3_max_len()
            );
        }
        if self.seeds.has_key() {
            self.refuse_unfit_keys(card)?;
        }
        Ok(())
    }

    /// Whether `init` sets up the KDF data object on this card, refusing `--kdf on` where the
    /// card offers none
    fn wants_kdf(&self, card: &mut Card<Transaction<'_>>) -> Result<bool> {
        let offered = card.extended_capabilities()?.kdf_do();
        Ok(match self.kdf {
            Kdf::Off => false,
            Kdf::On if !offered => {
                bail!("The card offers no KDF data object for --kdf on; the card was not touched")
            }
            Kdf::On => true,
            // The specification added the data object in version 3.3, so a card that offers
            // it and calls itself 2.0 is a Gnuk
            Kdf::Auto => offered && card.application_identifier()?.version() < 0x0300,
        })
    }

    /// Refuse a card whose key slots cannot hold this algorithm's keys
    pub(super) fn refuse_unfit_keys(&self, card: &mut Card<Transaction<'_>>) -> Result<()> {
        let aid = card.application_identifier()?;
        let changeable = card.extended_capabilities()?.algo_attrs_changeable();
        // A card without the list may refuse the request rather than answer it empty, as a
        // YubiKey 4 does with 6B00; the version is no guide, since Gnuk has the list and
        // calls itself 2.0
        let information = match card.algorithm_information() {
            Err(CardError::CardStatus(_)) => None,
            information => information?,
        };
        for &role in &self.keys {
            let kt = role.key_type();
            let fits = |attributes: &AlgorithmAttributes| self.fits(role, attributes);
            let supported = match &information {
                Some(information) => information.for_keytype(kt).into_iter().any(fits),
                None if !changeable => fits(&card.algorithm_attributes(kt)?),
                // Without the list (OpenPGP card 3.4 added it) the version has to do: cards
                // before 3.0 and YubiKeys before 5.2.3 (manufacturer 0006) hold RSA only
                None if aid.version() < 0x0300 || aid.manufacturer() == 0x0006 => {
                    self.algorithm.rsa_bits().is_some()
                }
                None => true,
            };
            if !supported {
                bail!(
                    "The card cannot hold {} keys for {kt:?}; the card was not touched",
                    self.algorithm
                );
            }
        }

        if self.cardholder_name().is_none() {
            log::warn!(
                "Cards take the cardholder name in ASCII and under 40 bytes; this one is left \
                 unset, the user id carries the name"
            );
        }
        Ok(())
    }

    /// Whether a key slot with these attributes holds a key of this card's algorithm
    pub(super) fn fits(&self, role: KeyRole, attributes: &AlgorithmAttributes) -> bool {
        match attributes {
            AlgorithmAttributes::Rsa(rsa) => {
                self.algorithm.rsa_bits() == Some(u32::from(rsa.len_n()))
            }
            AlgorithmAttributes::Ecc(ecc) => self
                .card_curve(role.is_encryption())
                .is_ok_and(|(oid, _)| ecc.oid() == oid),
            AlgorithmAttributes::Unknown(_) => false,
        }
    }

    /// The name for the card's cardholder data object, when the card can store it
    ///
    /// Cosmetic, unlike the user id: no card needs it to work, and refusing a name over it
    /// would turn away every non-ASCII name.
    pub(super) fn cardholder_name(&self) -> Option<&str> {
        (self.name.is_ascii() && self.name.len() < 40).then_some(self.name.as_str())
    }

    /// The curve and key type the card stores a key under, for ECC algorithms
    fn card_curve(&self, agreement: bool) -> Result<(&'static [u8], EccType)> {
        Ok(match (self.algorithm, agreement) {
            (Algorithm::Curve25519, true) => (CardCurve::Curve25519.oid(), EccType::ECDH),
            (Algorithm::Curve25519, false) => (CardCurve::Ed25519.oid(), EccType::EdDSA),
            (Algorithm::P256, true) => (CardCurve::NistP256r1.oid(), EccType::ECDH),
            (Algorithm::P256, false) => (CardCurve::NistP256r1.oid(), EccType::ECDSA),
            (Algorithm::P384, _) => bail!(P384_REFUSED),
            (algorithm, _) => bail!("{algorithm} is not an ECC algorithm"),
        })
    }

    /// Check that the supplied user pin opens the smartcard
    fn check_user_pin(&self, transaction: &mut Card<Transaction<'_>>) -> Result<()> {
        let Some(pin) = self.pin.as_ref() else {
            return Ok(());
        };

        // The copy moves into `SecretString`, which zeroizes it
        transaction.verify_user_pin(SecretString::from(pin.as_str().to_owned()))?;

        log::info!("User pin verified");

        Ok(())
    }

    /// Compare the chosen keys' fingerprints with the card's, collecting what differs
    fn check_subkeys(
        &self,
        keys: &Fingerprints,
        transaction: &mut Card<Transaction<'_>>,
        mismatches: &mut Vec<String>,
    ) {
        for (role, expected) in keys {
            let kt = role.key_type();
            match transaction.fingerprint(kt) {
                Ok(Some(card_fp)) if card_fp.as_bytes() == expected => {
                    log::info!("Fingerprint match for {:?} key: {}", kt, card_fp.to_spaced_hex())
                }
                Ok(Some(card_fp)) => mismatches.push(format!(
                    "Fingerprint mismatch for {:?} key: derived={}, card={}",
                    kt,
                    hex::encode_pretty(expected),
                    card_fp.to_spaced_hex()
                )),
                Ok(None) => mismatches.push(format!("No {kt:?} key found on card")),
                Err(err) => mismatches.push(format!("Could not read {kt:?} fingerprint: {err}")),
            }
        }
    }

    /// Open the admin state of a card this card seed initialized, with its derived admin pin
    ///
    /// Guarded: a wrong card seed spends one of three tries.
    pub(super) fn authenticate<'app, 'open>(
        &self,
        transaction: &'open mut Card<Transaction<'app>>,
    ) -> Result<Card<Admin<'app, 'open>>> {
        guard_admin_tries(transaction)?;
        let serial = serial_of(&transaction.application_identifier()?);
        let admin_pin = self.admin_pin(&serial)?;
        Ok(transaction.as_admin_card(SecretString::from(admin_pin.as_str().to_owned()))?)
    }

    /// Import one role's derived key, exactly the one the certificate's subkey carries
    pub(super) fn import_role(
        &self,
        admin: &mut Card<Admin<'_, '_>>,
        role: KeyRole,
        subkey: &Subkey,
    ) -> Result<()> {
        let kt = role.key_type();
        let ts = subkey
            .creation_time()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| anyhow!("Key creation time error: {}", e))?
            .as_secs();
        // OpenPGP stores creation times in 32 bits, which run out in 2106
        let ts = u32::try_from(ts)
            .map_err(|_| anyhow!("Key creation time lies beyond what OpenPGP can store"))?;

        // The very secret that went into the certificate
        let agreement = role.is_encryption();
        let secret = self.role_secret(role)?;
        let fingerprint = CardFingerprint::from(fingerprint_bytes(subkey)?);
        let timestamp = KeyGenerationTime::from(ts);

        log::info!("Uploading {:?} key", kt);
        if let Some(key) = &secret.rsa {
            let key = RawRsaKey::new(key, fingerprint, timestamp)?;
            admin.import_key(&key, kt)?;
        } else {
            // Extract public key bytes from cert MPI (0x40-prefixed for 25519 keys, the
            // uncompressed 0x04 point for P-256, which is what the card wants for both)
            let pub_bytes = match subkey.mpis() {
                mpi::PublicKey::EdDSA { q, .. } => q.value().to_vec(),
                mpi::PublicKey::ECDSA { q, .. } => q.value().to_vec(),
                mpi::PublicKey::ECDH { q, .. } => q.value().to_vec(),
                _ => bail!("{:?} key has unexpected algorithm in cert", kt),
            };

            let (oid, ecc_type) = self.card_curve(agreement)?;

            // OpenPGP cards take the X25519 scalar big-endian, the way GnuPG stores it,
            // where RFC 7748 and everything derived here is little-endian: sent as is,
            // the card would hold a different key than the certificate advertises
            let mut private_bytes = Zeroizing::new(secret.raw.to_vec());
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

        Ok(())
    }

    /// Name the card's card seed on the card, advisorily: a card without private-use data
    /// objects still works, it just cannot show whose it is
    pub(super) fn write_card_identifier(
        &self,
        admin: &mut Card<Admin<'_, '_>>,
        serial: &CardSerial,
    ) -> Result<()> {
        let Some(identifier) = self.card_identifier(serial)? else {
            return Ok(());
        };
        let fits = admin
            .as_transaction()
            .extended_capabilities()
            .is_ok_and(|capabilities| {
                capabilities.private_use_dos()
                    && capabilities
                        .max_len_special_do()
                        .is_none_or(|max| identifier.len() <= usize::from(max))
            });
        if !fits {
            log::info!("The card has no room for a card identifier, so it cannot show whose it is");
            return Ok(());
        }
        if let Err(err) = admin.set_private_use_do(CARD_IDENTIFIER_DO, identifier.into_bytes()) {
            log::warn!("Card refused the card identifier ({err}); it cannot show whose it is");
        }
        Ok(())
    }
}

/// Refuse a user pin no OpenPGP card takes: one shorter than the six characters the
/// specification asks for at least
///
/// How long a pin a card takes at most shows only on the card, which `pin --reset` asks.
pub fn refuse_unfit_pin(pin: &str) -> Result<()> {
    if pin.chars().count() < 6 {
        bail!("OpenPGP user pin needs at least 6 characters")
    }
    Ok(())
}

/// Change the user pin of an OpenPGP card, proven by the current one
///
/// Needs no seed: the pin is the card's own. A forgotten one is reset with the card seed's
/// derived admin pin instead, `pin --reset`.
pub fn change_pin(target: Option<CardTarget>, current: &str, new: &str) -> Result<()> {
    refuse_unfit_pin(new)?;
    let mut card = open_card(target)?;
    let mut transaction = card.transaction()?;
    let status = transaction.pw_status_bytes()?;
    let lost = "set a new one with `pin --reset`, which takes the card seed";
    match status.err_count_pw1() {
        0 => bail!("The card's user pin is blocked; {lost}"),
        1 => bail!(
            "The card's user pin has one try left, and a wrong current pin would block it; \
             {lost}"
        ),
        _ => {}
    }
    let longest = usize::from(status.pw1_max_len());
    if !(6..=longest).contains(&new.len()) {
        bail!(
            "The card takes user pins of 6 to {longest} characters, this one has {}; nothing \
             was changed",
            new.len()
        );
    }
    transaction
        .change_user_pin(SecretString::from(current.to_owned()), SecretString::from(new.to_owned()))
        .map_err(|err| {
            anyhow!("The card refused the change ({err}); if the pin is lost, {lost}")
        })?;
    log::info!("User pin changed on {}", describe(&transaction)?);
    Ok(())
}

/// A subkey of the certificate, as the card stores it
pub(super) type Subkey = Key<key::PublicParts, key::SubordinateRole>;

/// The certificate's subkey for each of `roles`, in their order, as valid at `at`
///
/// Judged at the subkeys' own creation time rather than now: a generation that has expired
/// since, or one dated ahead, still names the keys a card holds.
pub(super) fn role_keys(
    cert: &Cert,
    roles: &[KeyRole],
    at: SystemTime,
) -> Result<Vec<(KeyRole, Subkey)>> {
    let policy = StandardPolicy::new();
    let valid = cert.with_policy(&policy, Some(at))?;
    roles
        .iter()
        .map(|&role| {
            let subkey = valid
                .keys()
                .subkeys()
                .find(|k| k.key_flags().is_some_and(|flags| role.matches(&flags)))
                .ok_or_else(|| anyhow!("{:?} key not found in cert", role.key_type()))?;
            Ok((role, subkey.key().clone()))
        })
        .collect()
}

/// A subkey's fingerprint as the card stores it
pub(super) fn fingerprint_bytes(subkey: &Subkey) -> Result<[u8; 20]> {
    subkey
        .fingerprint()
        .as_bytes()
        .try_into()
        .map_err(|_| anyhow!("Unexpected fingerprint length"))
}
