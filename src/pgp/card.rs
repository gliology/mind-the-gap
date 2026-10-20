//! Everything that talks to a card: status, check, configuration and the key upload.

use super::{
    CardSettings, P384_REFUSED, SeededSmartcard, SignPinValidity, SubkeyRole, import::RawEccKey,
    import::RawRsaKey,
};
use crate::common;
use crate::policy::Touch;
use crate::readers;
use crate::seed::Algorithm;
use crate::target::CardTarget;

use std::ffi::CString;
use std::time::SystemTime;

use anyhow::{Result, anyhow, bail};

use zeroize::Zeroizing;

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

use openpgp_card::ocard::algorithm::AlgorithmAttributes;
use openpgp_card::ocard::data::{
    ApplicationIdentifier, Fingerprint as CardFingerprint, KeyGenerationTime, TouchPolicy,
    UserInteractionFlag,
};
use openpgp_card::state::{Open, Transaction};

/// Print list of currently available OpenPGP cards
pub fn status() -> Result<()> {
    println!("Available OpenPGP cards:");

    let cards = summaries()?;
    if cards.is_empty() {
        println!(" - None");
        println!();
    }

    for card in cards {
        println!(" - Card {}", card.aid.ident());
        println!("   Reader: {}", common::printable(&card.reader.to_string_lossy()));

        if !card.name.is_empty() {
            println!("   Cardholder: {}", common::printable(&card.name));
        }

        for (kt, fingerprint) in SubkeyRole::ALL
            .map(SubkeyRole::key_type)
            .iter()
            .zip(card.keys)
        {
            if let Some(fingerprint) = fingerprint {
                println!("   {:?} key: {}", kt, fingerprint.to_spaced_hex());
            }
        }

        println!();
    }

    Ok(())
}

/// What `status` and the card choice show of one OpenPGP card
struct Summary {
    reader: CString,
    aid: ApplicationIdentifier,
    name: String,
    /// Signing, decryption and authentication fingerprint, `None` for an empty slot
    keys: [Option<CardFingerprint>; 3],
}

/// The OpenPGP cards attached, read over plain PC/SC and left as they were
///
/// Opening each card through `openpgp-card` would reset every one of them when it is
/// dropped, throwing off any other program using a card, a parallel test run included.
fn summaries() -> Result<Vec<Summary>> {
    let (context, readers) = readers::list()?;
    let mut cards = Vec::new();
    for reader in readers {
        // An empty reader, or a card another program holds exclusively, has nothing to show
        let Ok(Some((aid, name, keys))) = readers::ask(&context, &reader, read_summary) else {
            continue;
        };
        cards.push(Summary { reader, aid, name, keys });
    }
    Ok(cards)
}

type SummaryData = (ApplicationIdentifier, String, [Option<CardFingerprint>; 3]);

/// AID, cardholder name and fingerprints of the card in a transaction, `None` without an
/// OpenPGP application
fn read_summary(transaction: &pcsc::Transaction<'_>) -> Option<SummaryData> {
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
    Some((aid, name, keys))
}

/// The OpenPGP application, as SELECT names it
const OPENPGP_AID: [u8; 6] = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
/// GET DATA of the application identifier (4F)
const GET_DATA_AID: [u8; 5] = [0x00, 0xCA, 0x00, 0x4F, 0x00];
/// GET DATA of the cardholder related data (65), where the name is
const GET_DATA_CARDHOLDER: [u8; 5] = [0x00, 0xCA, 0x00, 0x65, 0x00];
/// GET DATA of the application related data (6E), where the fingerprints are
const GET_DATA_APPLICATION_RELATED: [u8; 5] = [0x00, 0xCA, 0x00, 0x6E, 0x00];

// Determine smartcard to which to connect based on optional target string
fn open_card(target: Option<CardTarget>) -> Result<Card<Open>> {
    let reader = match target {
        Some(CardTarget::Ident(ident)) => reader_of(&ident)?.ok_or_else(|| {
            CardError::NotFound(format!(
                "Card '{ident}' not found; `pgp status` lists the attached ones"
            ))
        })?,
        Some(CardTarget::Reader(name)) => CString::new(name)?,
        Some(CardTarget::Serial(serial)) => bail!(
            "--card {serial} is a PIV serial number; name an OpenPGP card by its identifier \
             (MMMM:SSSSSSSS) or its reader, as `pgp status` shows them"
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

    let context = pcsc::Context::establish(pcsc::Scope::User)?;
    let backend = PcscBackend::from_pcsc_reader(&context, &reader, None).map_err(|err| {
        anyhow!(
            "Cannot open the card in reader '{}': {err}; `pgp status` lists the attached ones",
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
/// The admin pin is derived per subkey id, so a wrong `-k` costs a try even when the
/// fingerprints match (every subkey `--shared`), and three lock the card for good. With one
/// try left, the next mistake is that lock; only `upload`, which resets the card, may go on.
fn guard_admin_tries(card: &mut Card<Transaction<'_>>) -> Result<()> {
    match card.pw_status_bytes()?.err_count_pw3() {
        0 => bail!("The card's admin pin is blocked; only `pgp upload` can recover the card"),
        1 => bail!(
            "The card's admin pin has one try left, and a wrong subkey id would block it; \
             check -k and --shared, or reprovision with `pgp upload`"
        ),
        2 => log::warn!("The card's admin pin has two tries left: an earlier attempt failed"),
        _ => {}
    }
    Ok(())
}

/// The card as the confirmation and the logs name it: manufacturer and ident
fn describe(card: &Card<Transaction<'_>>) -> Result<String> {
    let aid = card.application_identifier()?;
    Ok(format!("{} OpenPGP card {}", aid.manufacturer_name(), aid.ident()))
}

impl SeededSmartcard {
    /// Give one freshly imported key the policy's touch requirement, advisorily: no card must
    /// lose its keys over a touch flag, and `pgp configure --touch` can set whatever the card
    /// supports afterwards
    fn set_policy_touch(&self, admin: &mut Card<openpgp_card::state::Admin<'_, '_>>, kt: KeyType) {
        let fixed = self.fixed_touch;
        let (wanted, fallback) = match (self.policy.pgp_touch(), fixed) {
            // A reset leaves every key's touch off already, and writing it would only risk a
            // refusal on cards without the flag; there is no fixed variant of off
            (Touch::Never, _) => {
                if fixed {
                    log::info!("No touch to fix for the {kt:?} key: the policy asks for none");
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
                 set a supported one with `pgp configure --touch`"
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
             set a supported one with `pgp configure --touch`"
        );
    }
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
    pub fn check(&self, target: Option<CardTarget>) -> Result<()> {
        // Fingerprints first: comparing them costs no pin retries, so a wrong seed, subkey id
        // or scheme fails here without consuming one of the card's three admin attempts --
        // three mistaken checks would otherwise lock the admin pin.
        //
        // The primary has to be *signed*: `check_subkeys` evaluates the certificate under the
        // standard policy, and a bare primary key packet carries no binding signature at all,
        // so an unsigned one fails with "No binding signature" before any card is consulted.
        // The direct key signature does not affect the subkey fingerprints being compared.
        let mut cert = self.primary_cert(true)?;
        cert = self.append_subkeys(cert)?;

        let mut card = open_card(target)?;
        let mut transaction = card.transaction()?;
        log::info!("Connected to {}", describe(&transaction)?);
        self.check_subkeys(&cert, &mut transaction)?;

        // Only now check that the card is managed by the derived admin pin
        self.check_admin_pin(&mut transaction)?;

        // And that the supplied user pin, if any, actually opens the card
        self.check_user_pin(&mut transaction)?;

        // Advisory, like PIV's policy lines: say what the card's touch policies are,
        // since upload and config both shape them and nothing else surfaces them
        report_touch_policies(&mut transaction);

        Ok(())
    }

    /// Adjust a provisioned card's settings under the derived admin pin.
    ///
    /// The counterpart to `upload`'s defaults: provisioning writes the keys with sensible
    /// policies, and this changes them to the user's liking afterwards without wiping
    /// anything. Fingerprints are compared first -- that costs no pin retries, so a wrong
    /// seed, subkey id or scheme fails here without spending one of the card's three admin
    /// attempts.
    pub fn configure(&self, target: Option<CardTarget>, settings: CardSettings) -> Result<()> {
        let mut cert = self.primary_cert(true)?;
        cert = self.append_subkeys(cert)?;

        let mut card = open_card(target)?;
        let mut transaction = card.transaction()?;
        log::info!("Connected to {}", describe(&transaction)?);
        self.check_subkeys(&cert, &mut transaction)?;
        guard_admin_tries(&mut transaction)?;

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
    pub fn upload(&self, target: Option<CardTarget>) -> Result<Cert> {
        let mut cert = self.primary_cert(false)?;

        cert = self.append_uids(cert)?;
        cert = self.append_subkeys(cert)?;

        self.upload_subkeys(&cert, target)?;

        Ok(cert)
    }

    /// Open the card `upload` would wipe, refuse it if it cannot hold the keys, and name it
    ///
    /// Meant for the confirmation: the question can name the card, and a card that would be
    /// wiped for nothing is refused while it is still intact. `upload` repeats the check on
    /// the card it opens itself.
    pub fn preflight(&self, target: Option<CardTarget>) -> Result<String> {
        let mut card = open_card(target)?;
        let mut transaction = card.transaction()?;
        self.refuse_unfit(&mut transaction)?;
        describe(&transaction)
    }

    /// Refuse a card that cannot take what `upload` installs, before anything on it changes
    ///
    /// `upload` resets the card, then changes both pins, then imports one key at a time: a
    /// card that fails any of those half way is left wiped, with pins of our choosing and
    /// without the keys. Everything that decides those steps is readable without a pin.
    fn refuse_unfit(&self, card: &mut Card<Transaction<'_>>) -> Result<()> {
        let status = card.pw_status_bytes()?;
        let pin = self.pin.as_ref().map_or(6, |pin| pin.map(|p| p.len()));
        if pin > usize::from(status.pw1_max_len()) {
            bail!(
                "The card takes user pins of up to {} characters, this one has {pin}; \
                 the card was not touched",
                status.pw1_max_len()
            );
        }
        let admin = self.admin_pin().len();
        if admin > usize::from(status.pw3_max_len()) {
            bail!(
                "The card takes admin pins of up to {} characters, the derived one has {admin}; \
                 the card was not touched",
                status.pw3_max_len()
            );
        }

        let aid = card.application_identifier()?;
        let changeable = card.extended_capabilities()?.algo_attrs_changeable();
        // A card without the list may refuse the request rather than answer it empty, as a
        // YubiKey 4 does with 6B00; the version is no guide, since Gnuk has the list and
        // calls itself 2.0
        let information = match card.algorithm_information() {
            Err(CardError::CardStatus(_)) => None,
            information => information?,
        };
        for role in SubkeyRole::ALL {
            let kt = role.key_type();
            let fits = |attributes: &AlgorithmAttributes| match attributes {
                AlgorithmAttributes::Rsa(rsa) => {
                    self.algorithm.rsa_bits() == Some(u32::from(rsa.len_n()))
                }
                AlgorithmAttributes::Ecc(ecc) => self
                    .card_curve(role.is_encryption())
                    .is_ok_and(|(oid, _)| ecc.oid() == oid),
                AlgorithmAttributes::Unknown(_) => false,
            };
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

    /// The name for the card's cardholder data object, when the card can store it
    ///
    /// Cosmetic, unlike the user id: no card needs it to work, and refusing a name over it
    /// would turn away every non-ASCII name.
    fn cardholder_name(&self) -> Option<&str> {
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

    /// Check that smartcard can be accessed with derived admin pin
    fn check_admin_pin(&self, transaction: &mut Card<Transaction<'_>>) -> Result<()> {
        guard_admin_tries(transaction)?;
        let admin_pin = self.admin_pin();
        transaction.verify_admin_pin(SecretString::from(admin_pin.as_str().to_owned()))?;

        Ok(())
    }

    /// Check that the supplied user pin opens the smartcard
    fn check_user_pin(&self, transaction: &mut Card<Transaction<'_>>) -> Result<()> {
        let Some(pin) = self.pin.as_ref() else {
            return Ok(());
        };

        // A valid UTF-8 pin borrows through `from_utf8_lossy`, and the `String` moves into
        // `SecretString`, which zeroizes it -- no unwiped copy is left behind
        let pin_str = pin.map(|p| String::from_utf8_lossy(p).to_string());
        transaction.verify_user_pin(SecretString::from(pin_str))?;

        log::info!("User pin verified");

        Ok(())
    }

    /// Check that subkey fingerprints of certificate matches those on smartcard
    fn check_subkeys(&self, cert: &Cert, transaction: &mut Card<Transaction<'_>>) -> Result<()> {
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

        crate::common::report_mismatches("certificate", &mismatches)
    }

    /// Upload subkeys to a smartcard and reset and lock smartcard in the process
    fn upload_subkeys(&self, cert: &Cert, target: Option<CardTarget>) -> Result<()> {
        let mut card = open_card(target)?;

        let mut transaction = card.transaction()?;
        log::info!("Connected to {}", describe(&transaction)?);

        self.refuse_unfit(&mut transaction)?;

        transaction.factory_reset()?;

        // Set new admin pin derived from subseed
        let admin_pin = self.admin_pin();
        transaction.change_admin_pin(
            SecretString::from(common::FACTORY_ADMIN_PIN.to_string()),
            SecretString::from(admin_pin.as_str().to_owned()),
        )?;

        // Authenticate as admin (combines verify + elevation in one step)
        let mut admin =
            transaction.as_admin_card(SecretString::from(admin_pin.as_str().to_owned()))?;

        if let Some(name) = self.cardholder_name() {
            admin.set_cardholder_name(name)?;
        }
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

            let fp_bytes: [u8; 20] = subkey
                .key()
                .fingerprint()
                .as_bytes()
                .try_into()
                .map_err(|_| anyhow!("Unexpected fingerprint length"))?;

            let ts = subkey
                .key()
                .creation_time()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|e| anyhow!("Key creation time error: {}", e))?
                .as_secs();
            // OpenPGP stores creation times in 32 bits, which run out in 2106
            let ts = u32::try_from(ts)
                .map_err(|_| anyhow!("Key creation time lies beyond what OpenPGP can store"))?;

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

                let (oid, ecc_type) = self.card_curve(agreement)?;

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

            self.set_policy_touch(&mut admin, kt);
        }

        // Explicit rather than the card's default, which differs between cards (a YubiKey
        // asks once per session, opcard before every signature); advisory, like the touch
        let forced = self.policy.pgp_signing_pin_forced();
        if let Err(err) = admin.set_user_pin_signing_validity(forced) {
            log::warn!(
                "Card refused to set how long a signing pin entry lasts ({err}); \
                 set it with `pgp configure --sign-pin`"
            );
        }

        // The user pin last, once the keys are in: Gnuk wraps the keys it holds under the
        // user pin and refuses to change it while it holds none, and while no admin pin is
        // set it holds a new user pin to the admin pin's minimum length of eight
        if let Some(pin) = self.pin.as_ref() {
            let new_pin: Zeroizing<String> =
                pin.map(|p| String::from_utf8_lossy(p).to_string()).into();
            admin.as_transaction().change_user_pin(
                SecretString::from(common::FACTORY_USER_PIN.to_string()),
                SecretString::from(AsRef::<str>::as_ref(&*new_pin).to_owned()),
            )?;
        }
        // The missing-pin case was already warned about at the command layer, once

        Ok(())
    }
}
