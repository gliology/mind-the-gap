//! On-card tests for the PIV backend.
//!
//! These are the automatable half of `docs/piv-hardware-testing.md`. Everything here talks to
//! a real card, so the whole file is compiled out unless the `destructive-hardware-tests`
//! feature is on *and* the `no-destructive-hardware-tests` interlock is off -- see the feature
//! comments in `Cargo.toml` for why the second flag exists.
//!
//! **Running this wipes the card.** `upload` exhausts the PIN and PUK counters and resets the
//! device. Point it at a spare:
//!
//! ```text
//! MTG_HARDWARE_TEST_SERIAL=12345678 cargo test --features destructive-hardware-tests
//! ```
//!
//! Expect to touch the token three times: once for `check`, which authenticates against the
//! management key, and once each for the 9A signature and the 9D key agreement. `upload` needs
//! none -- it installs the management key touch-free and only switches the requirement on once
//! provisioning has succeeded. The run blocks on each prompt until you press the button, and
//! the token's own timeout is about fifteen seconds, so watch for it.
//!
//! What is deliberately *not* here: the browser, Thunderbird and OpenSSL-engine steps of
//! section 5. Those exercise third-party software against the certificate profile rather than
//! the card, they need interactive GUI setup or a non-default OpenSSL engine configuration,
//! and the profile itself is already covered offline by `tests/piv.rs`.

#![cfg(all(
    feature = "destructive-hardware-tests",
    not(feature = "no-destructive-hardware-tests")
))]

use mind_the_gap::piv::{CertificateKind, SeededSmartcard};
use mind_the_gap::seed::Seed256;

use p256::ecdh;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, VerifyingKey};
use p256::{PublicKey, SecretKey};

use x509_cert::Certificate;
use x509_cert::der::Encode;

use yubikey::piv::{self, AlgorithmId, SlotId};
use yubikey::{CccId, ChuId, MsRoots, PinPolicy, Serial, TouchPolicy, YubiKey};

use zeroize::Zeroizing;

use std::str::FromStr;
use std::time::{Duration, SystemTime};

/// Seed for the provisioned test identity. Any fixed value works; it must not be a seed
/// anyone would use for real, since this card is wiped and re-provisioned at will.
const TEST_SEED: Seed256 = [0x5au8; 32];

const TEST_PIN: &str = "471120";

/// The per-slot policy table from `docs/piv-hardware-testing.md` section 2.
///
/// Spelled out here on purpose rather than read back from `SeededSmartcard::policies_for`: the
/// point is to pin the *specification*, so that changing the implementation's table fails this
/// test instead of silently agreeing with itself.
const EXPECTED_POLICIES: [(SlotId, PinPolicy, TouchPolicy); 4] = [
    (SlotId::Authentication, PinPolicy::Once, TouchPolicy::Cached),
    (SlotId::Signature, PinPolicy::Always, TouchPolicy::Always),
    (SlotId::KeyManagement, PinPolicy::Once, TouchPolicy::Cached),
    (SlotId::CardAuthentication, PinPolicy::Never, TouchPolicy::Never),
];

/// Serial of the card under test.
///
/// Required, and required to be explicit: the feature flag says "I want to run destructive
/// tests", this says "against *that* card". Without it a stray `--features` would reset
/// whichever token happened to be plugged in.
fn target() -> String {
    match std::env::var("MTG_HARDWARE_TEST_SERIAL") {
        Ok(serial) if !serial.trim().is_empty() => serial.trim().to_string(),
        _ => panic!(
            "MTG_HARDWARE_TEST_SERIAL is not set.\n\
             \n\
             These tests reset the card they run against, so they will not pick one for you.\n\
             Find the serial with `ykman list` and pass it explicitly:\n\
             \n\
             \tMTG_HARDWARE_TEST_SERIAL=<serial> cargo test --features destructive-hardware-tests\n"
        ),
    }
}

fn subject() -> SeededSmartcard {
    SeededSmartcard::new(&TEST_SEED, None, "Hardware Test".into())
        .add_email("hardware-test@example.com")
        .unwrap()
        .with_pin(Zeroizing::new(TEST_PIN.to_string()))
        .with_creation_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        .with_validity_duration(Duration::from_secs(10 * 365 * 24 * 60 * 60))
}

fn open() -> YubiKey {
    YubiKey::open_by_serial(Serial::from_str(&target()).expect("serial is not a number"))
        .expect("cannot open the card named by MTG_HARDWARE_TEST_SERIAL")
}

/// The P-256 public key a certificate carries
fn verifying_key(cert: &Certificate) -> VerifyingKey {
    VerifyingKey::from_sec1_bytes(
        cert.tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
            .raw_bytes(),
    )
    .expect("slot certificate does not carry a P-256 point")
}

fn leaf(chain: &mind_the_gap::piv::CertChain, slot: SlotId) -> &Certificate {
    &chain
        .leaves
        .iter()
        .find(|(id, _)| *id == slot)
        .unwrap_or_else(|| panic!("chain has no {slot:?} leaf"))
        .1
}

/// Turn the failure everyone hits into an actionable message.
///
/// GnuPG's `scdaemon` claims the whole card exclusively as soon as anything asks gpg to talk
/// to a card, and it lingers afterwards. PC/SC then refuses every further connection with a
/// message that never names the culprit. It is usually already running from ordinary gpg use
/// rather than from anything in this repository -- the OpenPGP tests here only call
/// `gpg --show-keys`, which does not touch a card.
fn on_card<T>(what: &str, result: anyhow::Result<T>) -> T {
    match result {
        Ok(value) => value,
        Err(error) if error.to_string().contains("other connections outstanding") => panic!(
            "{what} could not reach the card: {error}\n\
             \n\
             Something else holds an exclusive PC/SC connection, almost always GnuPG's\n\
             scdaemon. Release it and re-run:\n\
             \n\
             \tgpgconf --kill scdaemon\n\
             \n\
             It is usually left over from ordinary gpg use. Sharing the card between gpg\n\
             and PIV at the same time is possible but unreliable -- see the scdaemon section\n\
             of docs/piv-hardware-testing.md.\n"
        ),
        Err(error) => panic!("{what} failed: {error}"),
    }
}

/// The whole card-level checklist, in order, as a single test.
///
/// One test rather than several on purpose. The harness runs tests in parallel and in
/// arbitrary order, but these share one physical card and every later step depends on the
/// state `upload` leaves behind, so they have to be sequenced by construction.
#[test]
fn provision_and_verify_card() {
    let subject = subject();
    let serial = target();

    // -- Section 1: provision ------------------------------------------------------------
    //
    // Build the chain offline first. If this disagrees with what `upload` returns, the card
    // path has diverged from the reproducible one.
    eprintln!("[1/7] deriving the chain offline");
    let offline = subject
        .certify(CertificateKind::Chain)
        .expect("offline certify failed");

    // No touch here: `upload` installs the management key touch-free and only switches the
    // requirement on once provisioning has succeeded
    eprintln!("[2/7] uploading to card {serial}");
    let uploaded = on_card("upload", subject.upload(Some(serial.clone())));

    assert_eq!(
        uploaded
            .to_pem(CertificateKind::Chain)
            .expect("uploaded chain does not encode"),
        offline
            .to_pem(CertificateKind::Chain)
            .expect("offline chain does not encode"),
        "upload and certify produced different chains",
    );

    eprintln!("[3/7] running check -- TOUCH THE TOKEN when it blinks");
    on_card("check", subject.check(Some(serial.clone())));

    // -- Section 2: what actually landed -------------------------------------------------
    //
    // `check` reports policy and msroots mismatches as warnings rather than failures, so
    // neither is actually asserted by the call above. Do it here, where a regression fails.
    eprintln!("[4/7] asserting slot policies and certificates");
    let mut token = open();

    for (slot, pin_policy, touch_policy) in EXPECTED_POLICIES {
        let metadata = piv::metadata(&mut token, slot)
            .unwrap_or_else(|e| panic!("cannot read {slot:?} metadata: {e}"));

        assert_eq!(
            metadata.policy,
            Some((pin_policy, touch_policy)),
            "{slot:?} policy is not {pin_policy:?}/{touch_policy:?}",
        );

        // Byte-identical, not merely "a certificate is present"
        let on_card = yubikey::certificate::Certificate::read(&mut token, slot)
            .unwrap_or_else(|e| panic!("cannot read {slot:?} certificate: {e}"));
        assert_eq!(
            on_card.cert.to_der().expect("card cert does not encode"),
            leaf(&offline, slot).to_der().expect("leaf does not encode"),
            "{slot:?} certificate on card differs from the derived one",
        );
    }

    // -- Section 4: msroots --------------------------------------------------------------
    //
    // Checked before the signing steps because it needs no PIN and no touch.
    eprintln!("[5/7] asserting msroots");
    let expected = cms::content_info::ContentInfo::try_from(offline.cas())
        .expect("authorities do not form a PKCS#7")
        .to_der()
        .expect("PKCS#7 does not encode");
    let roots = MsRoots::read(&mut token)
        .expect("cannot read msroots")
        .expect("no authorities stored in msroots");
    assert_eq!(
        AsRef::<[u8]>::as_ref(&roots),
        expected.as_slice(),
        "msroots does not hold the derived certificate authorities",
    );

    // -- Card identifiers ----------------------------------------------------------------
    //
    // Windows smartcard logon and much middleware refuse a card carrying neither, and a
    // freshly reset YubiKey has neither, so their presence is entirely down to `upload`.
    eprintln!("[6/7] asserting CHUID and CCC");
    let chuid = ChuId::get(&mut token).expect("no CHUID on card, Windows logon needs one");
    assert_ne!(
        chuid.uuid().as_bytes(),
        &[0u8; 16],
        "CHUID carries a zero Card UUID, so the template was written without our identifier",
    );

    let ccc = CccId::get(&mut token).expect("no CCC on card");
    assert_ne!(
        ccc.card_id().expect("CCC card identifier unreadable").0,
        [0u8; 14],
        "CCC carries a zero card identifier",
    );

    // -- Section 3: on-card signing ------------------------------------------------------
    eprintln!("[7/7] on-card signing and key agreement");
    card_authentication_needs_no_pin(&mut token, &offline);
    signature_slot_refuses_without_pin(&mut token);
    authentication_slot_signs(&mut token, &offline);
    key_management_slot_agrees(&mut token, &offline);
}

/// Slot 9E signs with no PIN and no touch.
///
/// The NIST SP 800-73-4 requirement behind the per-slot policy table, and the item most
/// likely to regress. Note this cannot be checked through PKCS#11: OpenSC advertises a
/// token-level "login required" flag, so `pkcs11-tool` logs in whether or not it is asked to,
/// which tests OpenSC's policy rather than the card's. Going straight at the card is
/// unambiguous.
fn card_authentication_needs_no_pin(token: &mut YubiKey, chain: &mind_the_gap::piv::CertChain) {
    let message = b"card authentication";

    let signature =
        piv::sign_data(token, &sha256(message), AlgorithmId::EccP256, SlotId::CardAuthentication)
            .expect("9E refused to sign without a PIN, but its policy is PinPolicy::Never");

    verify(&signature, message, leaf(chain, SlotId::CardAuthentication), "9E");
}

/// Slot 9C refuses to sign until the PIN is presented, every time.
///
/// The negative half of `PinPolicy::Always`: the slot metadata merely *records* the policy,
/// this proves the card enforces it. Cheap to run -- the card rejects on the PIN check,
/// before it ever waits for a touch.
fn signature_slot_refuses_without_pin(token: &mut YubiKey) {
    let result =
        piv::sign_data(token, &sha256(b"signature slot"), AlgorithmId::EccP256, SlotId::Signature);

    assert!(result.is_err(), "9C signed without a PIN, but its policy is PinPolicy::Always",);
}

/// Slot 9A signs once the PIN is presented, and the signature verifies under its certificate.
fn authentication_slot_signs(token: &mut YubiKey, chain: &mind_the_gap::piv::CertChain) {
    token
        .verify_pin(TEST_PIN.as_bytes())
        .expect("card rejected the PIN we provisioned it with");

    let message = b"authentication slot";

    eprintln!("      9A signing -- TOUCH THE TOKEN when it blinks");
    let signature =
        piv::sign_data(token, &sha256(message), AlgorithmId::EccP256, SlotId::Authentication)
            .expect("9A refused to sign after a PIN and a touch");

    verify(&signature, message, leaf(chain, SlotId::Authentication), "9A");
}

/// Slot 9D performs ECDH on the card, and agrees with the same computation done off it.
///
/// This is the hardware half of the `keyAgreement` decision. The offline suite asserts that
/// `openssl cms -encrypt` accepts the certificate; only the card can show that the key
/// actually derives the same shared secret. Done as raw ECDH rather than a CMS round trip so
/// that it needs no OpenSSL engine configuration.
fn key_management_slot_agrees(token: &mut YubiKey, chain: &mind_the_gap::piv::CertChain) {
    let cert = leaf(chain, SlotId::KeyManagement);
    let card_public = PublicKey::from_sec1_bytes(
        cert.tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
            .raw_bytes(),
    )
    .expect("9D certificate does not carry a P-256 point");

    // Fixed rather than random: the card's key is what is under test, our side only has to
    // be a valid scalar, and a constant keeps the test deterministic.
    let ephemeral = SecretKey::from_slice(&[0x2bu8; 32]).expect("ephemeral scalar is invalid");

    // PIV key agreement takes the peer point uncompressed (0x04 || X || Y). NistP256 sets
    // COMPRESS_POINTS = false so `to_sec1_bytes` already gives that; assert it rather than
    // trust it, since a compressed point would fail on the card for a non-obvious reason.
    let point = ephemeral.public_key().to_sec1_bytes();
    assert_eq!(point.len(), 65, "ephemeral point is not uncompressed SEC1");
    assert_eq!(point[0], 0x04, "ephemeral point is not uncompressed SEC1");

    eprintln!("      9D key agreement -- TOUCH THE TOKEN when it blinks");
    let on_card = piv::decrypt_data(token, &point, AlgorithmId::EccP256, SlotId::KeyManagement)
        .expect("9D refused to perform key agreement");

    let off_card = ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), card_public.as_affine());

    assert_eq!(
        on_card.as_slice(),
        off_card.raw_secret_bytes().as_slice(),
        "9D derived a different shared secret than the same key does off the card",
    );
}

fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).to_vec()
}

/// `signature` is checked over `message`, not over its digest: the card signs a pre-computed
/// hash, while `Verifier::verify` hashes what it is given, so handing it the digest would
/// hash the hash.
fn verify(signature: &[u8], message: &[u8], cert: &Certificate, slot: &str) {
    let signature = DerSignature::from_bytes(signature)
        .unwrap_or_else(|e| panic!("{slot} signature is not DER: {e}"));

    verifying_key(cert)
        .verify(message, &signature)
        .unwrap_or_else(|e| panic!("{slot} signature does not verify under its certificate: {e}"));
}
