//! On-card tests for the OpenPGP backend.
//!
//! The counterpart to `tests/piv_hardware/`, gated on the same two features -- see the feature
//! comments in `Cargo.toml` for why the second one exists.
//!
//! **Running this wipes the card's OpenPGP applet.** `upload` factory-resets it. Note that it
//! resets *only* that applet: a card provisioned by `tests/piv_hardware/` keeps its PIV keys, so
//! the two suites can share a token, just not at the same time.
//!
//! ```text
//! MTG_HARDWARE_TEST_CARD=0006:20381784 \
//!   cargo test --features destructive-hardware-tests --test pgp_hardware -- --nocapture
//! ```
//!
//! Provisioning needs no touch, the applet being set up through the admin pin, but `upload`
//! leaves the keys at the `relaxed` policy's cached touch, so on a YubiKey the steps that use
//! the keys (sign, authenticate, decrypt, and gpg doing the same) blink for a touch each.
//!
//! The card is addressed by its OpenPGP *application identifier* (`0006:20381784`), not the
//! bare serial the PIV suite wants -- that is what `openpgp-card` matches on. `mind-the-gap
//! pgp status` prints it.

#![cfg(all(
    feature = "destructive-hardware-tests",
    not(feature = "no-destructive-hardware-tests")
))]

use mind_the_gap::pgp::{
    CardSettings, CertificateKind, SeededSmartcard, SubkeyRole, TouchPolicyArg,
};
use mind_the_gap::policy::Policy;
use mind_the_gap::seed::{Algorithm, Seed256};

use sequoia_openpgp::cert::Cert;
use sequoia_openpgp::policy::StandardPolicy;

use card_backend_pcsc::PcscBackend;
use openpgp_card::Card;
use openpgp_card::ocard::KeyType;
use openpgp_card::ocard::crypto::{Cryptogram, HashAlgo, SigningAlgo};
use openpgp_card::state::Transaction;

use sequoia_openpgp::crypto::mpi;
use sequoia_openpgp::types::Curve as PgpCurve;

use zeroize::Zeroizing;

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

const TEST_PIN: &str = "471120";
const TEST_NAME: &str = "Hardware Test";
const TEST_EMAIL: &str = "hardware-test@example.com";

#[path = "common/readers.rs"]
mod readers;

/// Application identifier of the card under test.
///
/// Required, and required to be explicit, for the same reason as the PIV suite's serial: the
/// feature flag says "run destructive tests", this says "against *that* card".
fn target() -> String {
    match std::env::var("MTG_HARDWARE_TEST_CARD") {
        Ok(ident) if !ident.trim().is_empty() => ident.trim().to_string(),
        _ => panic!(
            "MTG_HARDWARE_TEST_CARD is not set.\n\
             \n\
             This test factory-resets the OpenPGP applet of the card it runs against, so it\n\
             will not pick one for you. Print the identifier with `mind-the-gap pgp status`\n\
             and pass it explicitly:\n\
             \n\
             \tMTG_HARDWARE_TEST_CARD=<ident> cargo test --features destructive-hardware-tests --test pgp_hardware\n"
        ),
    }
}

/// Whether this run turns the touch policies off, for a host that runs it unattended
///
/// `MTG_HARDWARE_TEST_TOUCH=never` provisions with the `never-touch` policy, as in the PIV
/// suite: a script cannot touch a YubiKey, so this is how the suite runs without a person,
/// proving everything except that touch is enforced, which the default run does.
fn touch_free() -> bool {
    match std::env::var("MTG_HARDWARE_TEST_TOUCH") {
        Err(_) => false,
        Ok(touch) if touch == "never" => true,
        Ok(other) => panic!("MTG_HARDWARE_TEST_TOUCH is `never` or unset, not `{other}`"),
    }
}

/// Seed for the provisioned test identity, from the identifier of the card under test.
///
/// Deliberately different from the PIV suite's, so a crossed wire between the two backends
/// cannot pass by coincidence, and different per card: gpg-agent signs on whichever attached
/// card holds the key it looks up, so with one identity on several cards, as on a test host,
/// it can sign on another card and wait there for a touch.
fn test_seed() -> Seed256 {
    use sha2::{Digest, Sha256};
    Sha256::new()
        .chain_update([0xa7])
        .chain_update(target().to_ascii_uppercase())
        .finalize()
        .into()
}

fn subject() -> SeededSmartcard {
    let subject = SeededSmartcard::new(&test_seed(), None, TEST_NAME.into())
        .add_email(TEST_EMAIL)
        .unwrap()
        .with_pin(Zeroizing::new(TEST_PIN.to_string()))
        .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        .with_subkey_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1));
    if touch_free() {
        subject.with_policy(Policy::NeverTouch)
    } else {
        subject
    }
}

/// Open the card under test directly, bypassing the crate, with the serial number gpg knows
/// it by (its application identifier).
///
/// The assertions below have to be independent of the code they are checking, so they read the
/// card through `openpgp-card` rather than through `SeededSmartcard::check`. The cards are
/// told apart over plain PC/SC and every other one is left as it was: dropping an
/// `openpgp-card` connection resets the card, which would break a suite running on it.
fn open() -> (Card<openpgp_card::state::Open>, String) {
    let ident = target();
    let context = pcsc::Context::establish(pcsc::Scope::User).expect("cannot open a PC/SC context");
    let mut names = vec![
        0;
        context
            .list_readers_len()
            .expect("cannot list PC/SC readers")
    ];
    let readers: Vec<std::ffi::CString> = context
        .list_readers(&mut names)
        .expect("cannot list PC/SC readers")
        .map(std::ffi::CStr::to_owned)
        .collect();

    for reader in readers {
        let Ok(mut probe) = context.connect(&reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
        else {
            continue;
        };
        let found = probe_ident(&mut probe).is_some_and(|id| id.eq_ignore_ascii_case(&ident));
        let _ = probe.disconnect(pcsc::Disposition::LeaveCard);
        if !found {
            continue;
        }

        let backend = PcscBackend::from_pcsc_reader(&context, &reader, None)
            .expect("cannot connect to the card under test");
        let mut card = Card::new(backend).expect("cannot open card");
        let aid = {
            let tx = card.transaction().expect("cannot start card transaction");
            tx.application_identifier()
                .expect("cannot read application identifier")
        };
        let serialno = aid.to_string().replace(' ', "");
        return (card, serialno);
    }

    panic!("no OpenPGP card with identifier '{ident}'; `mind-the-gap pgp status` lists them")
}

/// A card's OpenPGP identifier, MANUFACTURER:SERIAL, read with two plain APDUs
fn probe_ident(card: &mut pcsc::Card) -> Option<String> {
    const SELECT: [u8; 12] = [
        0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x00,
    ];
    const GET_AID: [u8; 5] = [0x00, 0xCA, 0x00, 0x4F, 0x00];
    let transaction = card.transaction().ok()?;
    let mut buffer = [0; pcsc::MAX_BUFFER_SIZE];
    let reply = transaction.transmit(&SELECT, &mut buffer).ok()?;
    if !matches!(reply, [.., 0x90, 0x00] | [.., 0x61, _]) {
        return None;
    }
    let reply = transaction.transmit(&GET_AID, &mut buffer).ok()?;
    let [aid @ .., 0x90, 0x00] = reply else {
        return None;
    };
    let [_, _, _, _, _, _, _, _, m1, m2, s1, s2, s3, s4, ..] = *aid else {
        return None;
    };
    Some(format!("{m1:02X}{m2:02X}:{s1:02X}{s2:02X}{s3:02X}{s4:02X}"))
}

/// Fingerprints of the three subkeys, in `SubkeyRole::ALL` order.
fn derived_fingerprints(cert: &Cert) -> Vec<(KeyType, [u8; 20])> {
    let policy = StandardPolicy::new();
    let valid = cert
        .with_policy(&policy, None)
        .expect("derived certificate is not valid under the standard policy");

    SubkeyRole::ALL
        .iter()
        .map(|role| {
            let kind = role.key_type();
            let subkey = valid
                .keys()
                .subkeys()
                .find(|key| key.key_flags().is_some_and(|flags| role.matches(&flags)))
                .unwrap_or_else(|| panic!("derived certificate has no {kind:?} subkey"));

            let fingerprint: [u8; 20] = subkey
                .key()
                .fingerprint()
                .as_bytes()
                .try_into()
                .expect("fingerprint is not 20 bytes");

            (kind, fingerprint)
        })
        .collect()
}

/// Stops any `scdaemon` this test started, however the test ends.
///
/// Asking gpg to talk to a card leaves an scdaemon holding it exclusively, which would break
/// every later card test in the same `cargo test` run. `Drop` rather than a call at the end of
/// the test, so that it also runs when an assertion panics.
struct ScdaemonGuard {
    home: std::path::PathBuf,
}

impl Drop for ScdaemonGuard {
    fn drop(&mut self) {
        let _ = std::process::Command::new("gpgconf")
            .env("GNUPGHOME", &self.home)
            .args(["--kill", "scdaemon"])
            .output();
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

/// The one card every test here factory-resets, held for each test's whole run
///
/// The harness runs tests in parallel, and two of them provisioning the same card at once
/// interleave their commands: on hardware that showed as protocol errors and as keys wiped
/// halfway through another test's checks. Each run resets the applet first, so the order
/// the tests take the card in is immaterial.
static CARD: Mutex<()> = Mutex::new(());

/// Take the card for the calling test
///
/// A test that failed while holding it poisons the lock, but leaves nothing the next
/// test's own factory reset does not clear, so the poison is ignored rather than spread.
fn exclusive_card() -> MutexGuard<'static, ()> {
    CARD.lock().unwrap_or_else(PoisonError::into_inner)
}

#[test]
fn provision_and_verify_card() {
    let _card = exclusive_card();
    provision_and_verify(subject());
}

/// The same checklist with `--algorithm p256`: ECDSA signing and authentication keys and an
/// ECDH decryption key, which a YubiKey 5 imports as readily as Curve25519 ones.
#[test]
fn provision_and_verify_p256_card() {
    let _card = exclusive_card();
    provision_and_verify(
        subject()
            .with_algorithm(Algorithm::P256)
            .expect("the current scheme takes any algorithm"),
    );
}

/// The same checklist with RSA keys, at each size: every YubiKey 5 imports RSA up to 4096
/// bits into its OpenPGP applet, and the larger keys are the ones whose import needs more
/// than one short APDU.
#[test]
fn provision_and_verify_rsa_cards() {
    let _card = exclusive_card();
    for algorithm in [Algorithm::Rsa2048, Algorithm::Rsa3072, Algorithm::Rsa4096] {
        eprintln!("--- {algorithm:?}");
        provision_and_verify(
            subject()
                .with_algorithm(algorithm)
                .expect("the current scheme takes any algorithm"),
        );
    }
}

/// The card refuses every key's operation while nobody touches it, and performs it again
/// once someone does.
///
/// `upload` leaves each key requiring a touch, so the other tests only show that a touch,
/// when given, unlocks the keys. This one needs a card whose user presence the test decides,
/// which only a virtual card has: the virtual OpenPGP check runs it with
/// `MTG_TEST_USER_PRESENCE_FILE` naming the file the card reads, where `deny` refuses every
/// touch request. A refused request waits out the card's timeout, as on a token nobody
/// touches.
#[test]
#[ignore = "needs a card whose user presence the test decides, which the virtual OpenPGP check provides"]
fn touch_is_enforced() {
    let _card = exclusive_card();
    let presence = std::env::var("MTG_TEST_USER_PRESENCE_FILE").expect(
        "MTG_TEST_USER_PRESENCE_FILE is not set: this test needs a card it can refuse touches \
         for, which a real token is not",
    );
    let decide = |answer: &str| {
        std::fs::write(&presence, answer).expect("cannot write the user presence file");
    };

    let subject = subject();
    let offline = subject
        .certify(CertificateKind::Full)
        .expect("offline certify failed");
    decide("grant");
    subject
        .upload(Some(target()))
        .expect("upload to card failed");

    let (mut card, _) = open();
    let mut transaction = card.transaction().expect("cannot start card transaction");
    keys_work_on_card(&mut transaction, &offline);

    decide("deny");
    keys_refuse_on_card(&mut transaction, &offline);

    decide("grant");
    keys_work_on_card(&mut transaction, &offline);
}

/// The counterpart of [`keys_work_on_card`]: with no touch, each key's operation fails
fn keys_refuse_on_card(transaction: &mut Card<Transaction<'_>>, cert: &Cert) {
    let pin = || secrecy::SecretString::from(TEST_PIN.to_string());

    let public = public_mpis(cert, SubkeyRole::Signing);
    let (algo, input) = signing_input(&public, b"no touch");
    transaction
        .verify_user_signing_pin(pin())
        .expect("card rejected the signing pin");
    assert!(
        transaction.card().signature_for_hash(algo, &input).is_err(),
        "the signing key signed without the touch it demands",
    );

    let public = public_mpis(cert, SubkeyRole::Authentication);
    let (algo, input) = signing_input(&public, b"no touch");
    transaction
        .verify_user_pin(pin())
        .expect("card rejected the user pin");
    assert!(
        transaction
            .card()
            .authenticate_for_hash(algo, &input)
            .is_err(),
        "the authentication key authenticated without the touch it demands",
    );

    let mpi::PublicKey::ECDH { curve: PgpCurve::Cv25519, .. } =
        public_mpis(cert, SubkeyRole::Decryption)
    else {
        panic!("the touch test provisions the default Curve25519 keys");
    };
    let point = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([0x2bu8; 32]));
    assert!(
        transaction
            .card()
            .decipher(Cryptogram::ECDH(point.as_bytes()))
            .is_err(),
        "the decryption key agreed without the touch it demands",
    );
}

fn provision_and_verify(subject: SeededSmartcard) {
    let ident = target();
    let readers = readers::shared();

    // -- Provision -----------------------------------------------------------------------
    eprintln!("[1/7] deriving the certificate offline");
    let offline = subject
        .certify(CertificateKind::Full)
        .expect("offline certify failed");

    eprintln!("[2/7] uploading to card {ident} (no touch needed)");
    let uploaded = subject
        .upload(Some(ident.clone()))
        .expect("upload to card failed");

    assert_eq!(
        uploaded.fingerprint(),
        offline.fingerprint(),
        "upload and certify produced different primary keys",
    );

    // -- The crate's own check agrees ----------------------------------------------------
    eprintln!("[3/7] running check");
    subject
        .check(Some(ident.clone()))
        .expect("check disagreed with the card");

    // -- Independent verification --------------------------------------------------------
    //
    // `check` is the thing under test, so read the card directly rather than taking its word.
    eprintln!("[4/7] asserting card contents independently");
    let expected = derived_fingerprints(&offline);

    let (mut card, serialno) = open();
    let mut transaction = card.transaction().expect("cannot start card transaction");

    for (kind, want) in &expected {
        let on_card = transaction
            .fingerprint(*kind)
            .unwrap_or_else(|e| panic!("cannot read {kind:?} fingerprint: {e}"))
            .unwrap_or_else(|| panic!("no {kind:?} key on card"));

        assert_eq!(on_card.as_bytes(), want, "{kind:?} key on card is not the derived one",);
    }

    let cardholder = transaction
        .cardholder_name()
        .expect("cannot read cardholder name");
    assert_eq!(cardholder.trim(), TEST_NAME, "cardholder name was not set from the identity",);

    // The user pin we asked for has to be the one in force, and the factory default must not
    // be. Checked in this order so a card that accepts everything still fails.
    transaction
        .verify_user_pin(secrecy::SecretString::from(TEST_PIN.to_string()))
        .expect("card rejected the pin we provisioned it with");
    assert!(
        transaction
            .verify_user_pin(secrecy::SecretString::from("123456".to_string()))
            .is_err(),
        "card still accepts the factory user pin",
    );

    // -- Every key works on the card ------------------------------------------------------
    //
    // A matching fingerprint only says the right public key was recorded. Here each key
    // does its job and the result is checked against the certificate off the card: the
    // signing and authentication keys sign, the decryption key decrypts (RSA) or agrees
    // (ECDH). The X25519 agreement is the one that settles the scalar byte order, since the
    // card computes with the bytes it was sent and the certificate holds the public key
    // derived from them here.
    eprintln!("[5/7] each key signs, authenticates or decrypts -- TOUCH if the card blinks");
    keys_work_on_card(&mut transaction, &offline);

    drop(transaction);
    drop(card);

    // scdaemon takes every reader, so this step waits for the other suites to let go of
    // theirs, and they wait for it until it has stopped scdaemon again
    eprintln!("[6/7] gpg sees the card and uses its keys -- TOUCH if the card blinks");
    drop(readers);
    let gpg = readers::exclusive();
    gpg_sees_the_keys(&expected, &offline, &serialno);
    drop(gpg);
    let _readers = readers::shared();

    // -- Post-provisioning configuration ---------------------------------------------------
    //
    // `configure` adjusts the card under the derived admin pin without reprovisioning; a
    // later factory reset by the next run reverts everything, so nothing here persists.
    eprintln!("[7/7] configure adjusts the provisioned card");
    subject
        .configure(
            Some(ident.clone()),
            CardSettings {
                touch: vec![(SubkeyRole::Authentication, TouchPolicyArg::Always)],
                lang: vec![*b"en", *b"de"],
                url: Some("https://example.com/alice.asc".to_string()),
                login: Some("alice".to_string()),
                sign_pin: None,
            },
        )
        .expect("configure failed against the provisioned card");

    // Read back independently of the crate
    let (mut card, _) = open();
    let mut transaction = card.transaction().expect("cannot start card transaction");
    assert_eq!(
        transaction.url().expect("cannot read url"),
        "https://example.com/alice.asc",
        "configure did not store the url",
    );
    assert_eq!(
        transaction.login_data().expect("cannot read login data"),
        b"alice",
        "configure did not store the login data",
    );
}

/// A subkey's public key material, as the certificate carries it
fn public_mpis(cert: &Cert, role: SubkeyRole) -> mpi::PublicKey {
    let policy = StandardPolicy::new();
    let valid = cert
        .with_policy(&policy, None)
        .expect("derived certificate is not valid under the standard policy");
    valid
        .keys()
        .subkeys()
        .find(|key| key.key_flags().is_some_and(|flags| role.matches(&flags)))
        .unwrap_or_else(|| panic!("derived certificate has no {role:?} subkey"))
        .key()
        .mpis()
        .clone()
}

fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).to_vec()
}

/// The RSA public key in a certificate's key material
fn rsa_public(e: &mpi::MPI, n: &mpi::MPI) -> rsa::RsaPublicKey {
    rsa::RsaPublicKey::new(
        crypto_bigint::BoxedUint::from_be_slice_vartime(n.value()),
        crypto_bigint::BoxedUint::from_be_slice_vartime(e.value()),
    )
    .expect("certificate carries an invalid RSA key")
}

/// What the card signs for `message`: RSA wraps a SHA-256 digest in a DigestInfo, ECDSA takes
/// the digest bare, and EdDSA signs the bytes it is given, here the same digest
fn signing_input(public: &mpi::PublicKey, message: &[u8]) -> (SigningAlgo, Vec<u8>) {
    match public {
        mpi::PublicKey::RSA { .. } => (SigningAlgo::RSA(HashAlgo::SHA256), sha256(message)),
        _ => (SigningAlgo::ECC, sha256(message)),
    }
}

/// Check a card signature over `message` against the certificate's public key
fn verify_card_signature(public: &mpi::PublicKey, message: &[u8], signature: &[u8], what: &str) {
    match public {
        mpi::PublicKey::RSA { e, n } => {
            use rsa::signature::Verifier;
            let key = rsa::pkcs1v15::VerifyingKey::<rsa::sha2::Sha256>::new(rsa_public(e, n));
            let signature = rsa::pkcs1v15::Signature::try_from(signature)
                .unwrap_or_else(|e| panic!("{what} is not an RSA signature: {e}"));
            key.verify(message, &signature)
                .unwrap_or_else(|e| panic!("{what} does not verify under the certificate: {e}"));
        }
        mpi::PublicKey::EdDSA { q, .. } => {
            use ed25519_dalek::Verifier;
            // OpenPGP prefixes the native point with 0x40
            let point: [u8; 32] = q.value()[1..].try_into().expect("not an Ed25519 point");
            let key = ed25519_dalek::VerifyingKey::from_bytes(&point).expect("not an Ed25519 key");
            let signature = ed25519_dalek::Signature::from_slice(signature)
                .unwrap_or_else(|e| panic!("{what} is not an Ed25519 signature: {e}"));
            key.verify(&sha256(message), &signature)
                .unwrap_or_else(|e| panic!("{what} does not verify under the certificate: {e}"));
        }
        mpi::PublicKey::ECDSA { q, .. } => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            let key =
                p256::ecdsa::VerifyingKey::from_sec1_bytes(q.value()).expect("not a P-256 point");
            let signature = p256::ecdsa::Signature::from_slice(signature)
                .unwrap_or_else(|e| panic!("{what} is not an ECDSA signature: {e}"));
            key.verify_prehash(&sha256(message), &signature)
                .unwrap_or_else(|e| panic!("{what} does not verify under the certificate: {e}"));
        }
        other => panic!("{what}: unexpected signing key {other:?}"),
    }
}

/// Encipher `message` to an RSA key with PKCS#1 v1.5 padding (RFC 8017 section 7.2.1)
///
/// The padding string is fixed rather than random: the card's private key is what is under
/// test, and a constant keeps the test deterministic.
fn rsa_encipher(e: &mpi::MPI, n: &mpi::MPI, message: &[u8]) -> Vec<u8> {
    use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
    use crypto_bigint::{BoxedUint, Odd};

    let size = n.value().len();
    let mut block = vec![0x5a; size];
    block[0] = 0x00;
    block[1] = 0x02;
    block[size - message.len() - 1] = 0x00;
    block[size - message.len()..].copy_from_slice(message);

    let modulus = BoxedUint::from_be_slice_vartime(n.value());
    let bits = modulus.bits_precision();
    let params = BoxedMontyParams::new(Odd::new(modulus).expect("RSA modulus is odd"));
    let block = BoxedUint::from_be_slice(&block, bits).expect("block fits the modulus");
    let exponent = BoxedUint::from_be_slice_vartime(e.value());
    let cipher = BoxedMontyForm::new(block, &params)
        .pow(&exponent)
        .retrieve();

    let bytes = cipher.to_be_bytes();
    bytes[bytes.len() - size..].to_vec()
}

/// The three keys at work on the card, each result checked off the card
fn keys_work_on_card(transaction: &mut Card<Transaction<'_>>, cert: &Cert) {
    let pin = || secrecy::SecretString::from(TEST_PIN.to_string());

    // Signing key: PW1 in signing mode, the one the card resets after every signature
    let public = public_mpis(cert, SubkeyRole::Signing);
    let message = b"openpgp signing key";
    let (algo, input) = signing_input(&public, message);
    transaction
        .verify_user_signing_pin(pin())
        .expect("card rejected the signing pin");
    let signature = transaction
        .card()
        .signature_for_hash(algo, &input)
        .expect("signing key refused to sign");
    verify_card_signature(&public, message, &signature, "signing key signature");

    // Authentication key: INTERNAL AUTHENTICATE, PW1 in user mode
    let public = public_mpis(cert, SubkeyRole::Authentication);
    let message = b"openpgp authentication key";
    let (algo, input) = signing_input(&public, message);
    transaction
        .verify_user_pin(pin())
        .expect("card rejected the user pin");
    let signature = transaction
        .card()
        .authenticate_for_hash(algo, &input)
        .expect("authentication key refused to authenticate");
    verify_card_signature(&public, message, &signature, "authentication key signature");

    // Decryption key: RSA decrypts, ECDH returns the shared secret
    let public = public_mpis(cert, SubkeyRole::Decryption);
    match &public {
        mpi::PublicKey::RSA { e, n } => {
            let message = b"openpgp decryption key";
            let cipher = rsa_encipher(e, n, message);
            let plain = transaction
                .card()
                .decipher(Cryptogram::RSA(&cipher))
                .expect("decryption key refused to decrypt");
            assert_eq!(plain, message, "decryption key decrypted to something else");
        }
        mpi::PublicKey::ECDH { curve: PgpCurve::Cv25519, q, .. } => {
            let card: [u8; 32] = q.value()[1..].try_into().expect("not an X25519 point");
            let ephemeral = x25519_dalek::StaticSecret::from([0x2bu8; 32]);
            let point = x25519_dalek::PublicKey::from(&ephemeral);
            let on_card = transaction
                .card()
                .decipher(Cryptogram::ECDH(point.as_bytes()))
                .expect("decryption key refused to agree");
            let off_card = ephemeral.diffie_hellman(&x25519_dalek::PublicKey::from(card));
            assert_eq!(
                on_card,
                off_card.as_bytes(),
                "the card's X25519 key is not the one in the certificate",
            );
        }
        mpi::PublicKey::ECDH { curve: PgpCurve::NistP256, q, .. } => {
            let card = p256::PublicKey::from_sec1_bytes(q.value()).expect("not a P-256 point");
            let ephemeral = p256::SecretKey::from_slice(&[0x2bu8; 32]).expect("invalid scalar");
            let point = ephemeral.public_key().to_sec1_bytes();
            let on_card = transaction
                .card()
                .decipher(Cryptogram::ECDH(&point))
                .expect("decryption key refused to agree");
            let off_card =
                p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), card.as_affine());
            assert_eq!(
                on_card,
                off_card.raw_secret_bytes().as_slice(),
                "the card's P-256 decryption key is not the one in the certificate",
            );
        }
        other => panic!("unexpected decryption key {other:?}"),
    }
}

/// Confirm gpg itself finds the three keys, and clean up the scdaemon that costs.
///
/// Uses a throwaway GNUPGHOME so the caller's keyring and agent are untouched, and forces
/// scdaemon through PC/SC -- its internal CCID driver claims the USB interface directly and
/// fails with "No such device" whenever pcscd already holds the reader.
///
/// The card is named by its serial number throughout, because scdaemon otherwise takes
/// whichever OpenPGP card it likes when several are attached, as on a test host, and the
/// test identity is the same on all of them.
#[cfg(has_gpg)]
fn gpg_sees_the_keys(expected: &[(KeyType, [u8; 20])], cert: &Cert, serialno: &str) {
    // tempfile gives an unpredictable path, so nothing can pre-place a directory or
    // symlink there; into_path hands ownership to the ScdaemonGuard below
    let home = tempfile::tempdir()
        .expect("cannot create throwaway GNUPGHOME")
        .keep();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))
            .expect("cannot restrict GNUPGHOME permissions");
    }

    std::fs::write(home.join("scdaemon.conf"), "disable-ccid\n")
        .expect("cannot write scdaemon.conf");

    // Armed before gpg runs, so the daemon is stopped even if an assertion below panics
    let _guard = ScdaemonGuard { home: home.clone() };

    // scdaemon names a card after its AID but may zero the version field (it does for every
    // YubiKey), so find ours among the cards it sees by manufacturer and serial number
    let cards = std::process::Command::new("gpg-card")
        .env("GNUPGHOME", &home)
        .args(["--no-history", "list", "--cards"])
        .output()
        .expect("cannot run gpg-card");
    let cards = String::from_utf8_lossy(&cards.stdout);
    let serialno = cards
        .split_whitespace()
        .find(|word| word.len() == 32 && word.get(16..28) == serialno.get(16..28))
        .unwrap_or_else(|| panic!("gpg sees no card with serial number {serialno}:\n{cards}"));

    // Make the card current and have the agent learn its keys: the key stubs it writes record
    // this serial number, so the signing and decryption below go to this card and no other
    let learned = std::process::Command::new("gpg-connect-agent")
        .env("GNUPGHOME", &home)
        .args([
            &format!("scd switchcard {serialno}"),
            "learn --force",
            "/bye",
        ])
        .output()
        .expect("cannot run gpg-connect-agent");
    let replies = String::from_utf8_lossy(&learned.stdout);
    assert!(
        learned.status.success() && !replies.lines().any(|line| line.starts_with("ERR")),
        "gpg-agent cannot learn card {serialno}:\n{replies}\n{}",
        String::from_utf8_lossy(&learned.stderr),
    );

    // `gpg --card-status` asks for no card in particular; gpg-card lists the one named
    let output = std::process::Command::new("gpg-card")
        .env("GNUPGHOME", &home)
        .args(["--no-history", "list", serialno])
        .output()
        .expect("cannot run gpg-card");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "gpg-card list failed:\n{}\n{}",
        stdout,
        String::from_utf8_lossy(&output.stderr),
    );

    // gpg prints fingerprints spaced in four-character groups, so compare on a normalised copy
    let normalised: String = stdout.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let normalised = normalised.to_uppercase();

    for (kind, fingerprint) in expected {
        let hex = fingerprint
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>();

        assert!(
            normalised.contains(&hex),
            "gpg does not report the {kind:?} key ({hex}):\n{stdout}",
        );
    }

    gpg_uses_the_keys(&home, cert);
}

/// gpg signs and decrypts with the card, end to end, the way a mail client would.
///
/// The low-level checks above prove the keys; this proves the whole client path around them,
/// the ECDH key derivation and session key unwrapping included, which only a real client does.
#[cfg(has_gpg)]
fn gpg_uses_the_keys(home: &std::path::Path, cert: &Cert) {
    use sequoia_openpgp::serialize::SerializeInto;
    use std::io::Write;

    let gpg = |args: &[&str], input: &[u8]| -> std::process::Output {
        let mut child = std::process::Command::new("gpg")
            .env("GNUPGHOME", home)
            .args([
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                TEST_PIN,
            ])
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("cannot run gpg");
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().expect("gpg did not finish")
    };
    let ok = |output: std::process::Output, what: &str| -> Vec<u8> {
        assert!(
            output.status.success(),
            "gpg {what} failed:\n{}",
            String::from_utf8_lossy(&output.stderr),
        );
        output.stdout
    };

    // The public certificate turns the card status stubs into usable keys
    ok(gpg(&["--import"], &cert.armored().to_vec().unwrap()), "--import");
    let fingerprint = cert.fingerprint().to_hex();

    let message = b"signed and sealed on the card";
    let signed = ok(gpg(&["--local-user", &fingerprint, "--sign"], message), "--sign");
    let verified = ok(gpg(&["--decrypt"], &signed), "--verify of a card signature");
    assert_eq!(verified, message, "gpg verified a different message");

    let sealed = ok(
        gpg(
            &[
                "--trust-model",
                "always",
                "--recipient",
                &fingerprint,
                "--encrypt",
            ],
            message,
        ),
        "--encrypt",
    );
    let opened = ok(gpg(&["--decrypt"], &sealed), "--decrypt on the card");
    assert_eq!(opened, message, "gpg decrypted to a different message");
}

#[cfg(not(has_gpg))]
fn gpg_sees_the_keys(_expected: &[(KeyType, [u8; 20])], _cert: &Cert, _serialno: &str) {
    // A destructive run that cannot finish its last assertion must say so in the result,
    // not in a line of buffered output: a pass with a skipped step is not a pass. The card
    // itself is fine -- provisioning succeeded before this step.
    panic!(
        "gpg is not in PATH, so the final cross-check cannot run; the card is provisioned \
         fine -- install gpg (or enter the dev shell) and rerun to complete the suite"
    );
}
