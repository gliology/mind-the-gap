//! On-card tests for the PIV backend.
//!
//! These are the automatable half of `docs/piv-hardware-tests.md`. Everything here talks to
//! a real card, so the whole file is compiled out unless the `destructive-hardware-tests`
//! feature is on *and* the `no-destructive-hardware-tests` interlock is off -- see the feature
//! comments in `Cargo.toml` for why the second flag exists.
//!
//! **Running this wipes the card.** `upload` exhausts the PIN and PUK counters and resets the
//! device. Point it at a spare:
//!
//! ```text
//! MTG_HARDWARE_TEST_SERIAL=12345678 cargo test --features destructive-hardware-tests --test piv_hardware
//! ```
//!
//! Watch the token: several steps blink for a touch and block until you press it, and the
//! token's own timeout is about fifteen seconds. Touches come at `check` (management key),
//! the native 9A signature and 9D agreement, then the end-use steps -- the 9A TLS
//! handshake, the 9C S/MIME signature, the 9D PKCS#11 key agreement, and the 9A SSH login.
//! `upload` needs none: it installs the management key touch-free and only arms the
//! requirement afterwards.
//!
//! The checklist runs on P-256, the default chain. Its card-level half is also available
//! on its own, for either algorithm, as ignored tests (`cargo test ... -- --ignored`): the
//! virtual PIV check runs those against the trussed card in a VM, and on real hardware
//! the Curve25519 one needs a token importing Ed25519 and X25519 PIV keys, which is
//! YubiKey firmware 5.7 or later.
//!
//! The end use of section 5 runs here too, driven headless against the tools real clients
//! are built on: a TLS client-auth handshake over 9A, S/MIME signing over 9C, 9D key
//! agreement through the standard PKCS#11 interface, SSH authentication with 9A against a
//! throwaway sshd, and NSS -- the Firefox/Thunderbird/Chrome stack -- recognising the card,
//! its keys and the derived chain. On-card *decryption* is the one flow not asserted: it is
//! blocked in OpenSSL by bug #24698 and in NSS by the external-token login path, neither a
//! fault of the card, whose ECDH is proven by the native and PKCS#11 agreement steps.

#![cfg(all(
    feature = "destructive-hardware-tests",
    not(feature = "no-destructive-hardware-tests")
))]

use mind_the_gap::piv::{CertChain, CertificateKind, SeededSmartcard};
use mind_the_gap::seed::{Algorithm, Seed256};

use p256::ecdh;

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, VerifyingKey};
use p256::{PublicKey, SecretKey};
use rsa::traits::PublicKeyParts;

use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use x509_cert::Certificate;
use x509_cert::der::Encode;
use x509_cert::der::EncodePem;

use yubikey::piv::{self, AlgorithmId, SlotId};
use yubikey::{CccId, ChuId, MsRoots, PinPolicy, Serial, TouchPolicy, YubiKey};

use zeroize::Zeroizing;

use std::str::FromStr;
use std::time::{Duration, SystemTime};

mod end_use;

use end_use::{
    key_agreement_through_pkcs11, nss_recognises_card, openssl_conf, pkcs11_paths, smime_signs,
    ssh_authenticates, tls_client_authenticates,
};

/// Seed for the provisioned test identity. Any fixed value works; it must not be a seed
/// anyone would use for real, since this card is wiped and re-provisioned at will.
const TEST_SEED: Seed256 = [0x5au8; 32];

const TEST_PIN: &str = "471120";

/// The per-slot policy table from `docs/piv-hardware-tests.md` section 2.
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
             \tMTG_HARDWARE_TEST_SERIAL=<serial> cargo test --features destructive-hardware-tests --test piv_hardware\n"
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

/// The algorithm a slot holds its key under, read off its certificate's SPKI
fn slot_algorithm(cert: &Certificate) -> AlgorithmId {
    match cert
        .tbs_certificate()
        .subject_public_key_info()
        .algorithm
        .oid
        .to_string()
        .as_str()
    {
        // Both curves share id-ecPublicKey; the uncompressed point's length tells them apart
        "1.2.840.10045.2.1" => match public_key_bytes(cert).len() {
            65 => AlgorithmId::EccP256,
            97 => AlgorithmId::EccP384,
            len => panic!("slot certificate carries an EC point of {len} bytes"),
        },
        "1.3.101.112" => AlgorithmId::Ed25519,
        "1.3.101.110" => AlgorithmId::X25519,
        "1.2.840.113549.1.1.1" => match rsa_public_key(cert).n().bits() {
            2048 => AlgorithmId::Rsa2048,
            3072 => AlgorithmId::Rsa3072,
            4096 => AlgorithmId::Rsa4096,
            bits => panic!("slot certificate carries an RSA key of {bits} bits"),
        },
        other => panic!("slot certificate carries an unexpected key algorithm: {other}"),
    }
}

/// The RSA public key a certificate carries
fn rsa_public_key(cert: &Certificate) -> rsa::RsaPublicKey {
    use rsa::pkcs8::DecodePublicKey;
    let spki = cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .unwrap();
    rsa::RsaPublicKey::from_public_key_der(&spki).expect("slot certificate has no RSA key")
}

/// `message` hashed and padded into the block a raw RSA private key operation signs:
/// EMSA-PKCS1-v1_5 with SHA-256 (RFC 8017 section 9.2), the card doing no padding itself
fn pkcs1_sha256_block(message: &[u8], cert: &Certificate) -> Vec<u8> {
    const DIGEST_INFO: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    let size = rsa_public_key(cert).size();
    let digest = sha256(message);
    let mut block = vec![0xff; size];
    block[0] = 0x00;
    block[1] = 0x01;
    let tail = DIGEST_INFO.len() + digest.len();
    block[size - tail - 1] = 0x00;
    block[size - tail..size - digest.len()].copy_from_slice(&DIGEST_INFO);
    block[size - digest.len()..].copy_from_slice(&digest);
    block
}

/// The raw subject public key a certificate carries
fn public_key_bytes(cert: &Certificate) -> &[u8] {
    cert.tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes()
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
             of docs/piv-hardware-tests.md.\n"
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

    let (offline, token) = provision_and_verify(&subject, &serial, 12);

    // -- Section 5: end use through PKCS#11 ----------------------------------------------
    //
    // The flows a browser or a mail client would run, driven headless: the TLS handshake
    // below is exactly a browser's client-certificate authentication, and the CMS round
    // trip is the S/MIME mechanics without a mail account. The card is released first --
    // the PKCS#11 stack opens its own sessions through pcscd.
    drop(token);

    let (module, provider) = pkcs11_paths();
    let dir = tempfile::tempdir().expect("cannot create scratch directory");
    let conf = openssl_conf(dir.path(), &provider, &module);
    let pem = |name: &str, cert: &Certificate| -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, cert.to_pem(x509_cert::der::pem::LineEnding::LF).unwrap()).unwrap();
        path
    };
    let root = pem("root.pem", &offline.root);
    let nine_a = pem("9a.pem", leaf(&offline, SlotId::Authentication));
    let nine_c = pem("9c.pem", leaf(&offline, SlotId::Signature));

    eprintln!("[8/12] TLS client authentication over 9A -- TOUCH if it blinks");
    tls_client_authenticates(dir.path(), &conf, &root, &nine_a);

    eprintln!("[9/12] S/MIME signing over 9C -- TOUCH for the signature");
    smime_signs(dir.path(), &conf, &root, &nine_c);

    eprintln!("[10/12] key agreement over 9D through PKCS#11 -- TOUCH if it blinks");
    key_agreement_through_pkcs11(dir.path(), &module, leaf(&offline, SlotId::KeyManagement));

    eprintln!("[11/12] SSH authentication with the 9A key -- TOUCH when it blinks");
    ssh_authenticates(dir.path(), &module);

    eprintln!("[12/12] NSS recognises the card, its keys and the chain (no touch)");
    nss_recognises_card(dir.path(), &module, &root);
}

/// The card-level half of the checklist on P-256, without the PKCS#11 end use.
///
/// What the virtual PIV check runs against the trussed card, where no PKCS#11 stack is
/// configured around it. Ignored so that `cargo test` on a real token runs the full
/// checklist above once rather than provisioning the card twice.
#[test]
#[ignore = "the card-level half of the checklist above, run by the virtual PIV check"]
fn provision_and_verify_p256_card() {
    provision_and_verify(&subject(), &target(), 7);
}

/// The card-level half of the checklist on Curve25519: Ed25519 slot keys and authorities,
/// an X25519 key management key, and the card signing and agreeing with each of them.
///
/// The virtual PIV check runs it against the trussed card. On real hardware it needs a
/// token that imports both algorithms, which is YubiKey firmware 5.7 or later, hence
/// ignored. The end-use steps through PKCS#11 stay with the P-256 run: OpenSC's PIV
/// driver does not drive these slots yet.
#[test]
#[ignore = "needs a card that imports Ed25519 (0xE0) and X25519 (0xE1) PIV keys"]
fn provision_and_verify_curve25519_card() {
    let subject = subject().with_algorithm(Algorithm::Curve25519);
    let serial = target();

    provision_and_verify(&subject, &serial, 7);
}

/// The card-level half of the checklist on P-384: ECDSA P-384 authorities and slot keys
/// signing SHA-384 digests, and ECDH P-384 in 9D. Every YubiKey 5 imports it, and so does
/// a YubiKey 4.
#[test]
#[ignore = "the card-level half of the checklist on P-384"]
fn provision_and_verify_p384_card() {
    let subject = subject().with_algorithm(Algorithm::P384);
    let serial = target();

    provision_and_verify(&subject, &serial, 7);
}

/// The card-level half of the checklist on RSA-2048: every slot key and authority in RSA,
/// the card signing with each and decrypting with 9D.
///
/// The virtual PIV check runs it against the trussed card. RSA-2048 import works on every
/// YubiKey 5, but the PKCS#11 end use stays with the P-256 run, so this stays ignored like
/// the other card-level halves.
#[test]
#[ignore = "the card-level half of the checklist on RSA-2048, run by the virtual PIV check"]
fn provision_and_verify_rsa2048_card() {
    let subject = subject().with_algorithm(Algorithm::Rsa2048);
    let serial = target();

    provision_and_verify(&subject, &serial, 7);
}

/// The same on RSA-3072, which a YubiKey imports into PIV from firmware 5.7 on.
#[test]
#[ignore = "needs a card that imports RSA-3072 PIV keys, YubiKey firmware 5.7 or later"]
fn provision_and_verify_rsa3072_card() {
    let subject = subject().with_algorithm(Algorithm::Rsa3072);
    let serial = target();

    provision_and_verify(&subject, &serial, 7);
}

/// The same on RSA-4096, from firmware 5.7 on as well. Also needs a yubikey crate that
/// fits the larger key into its import command, which the pinned revision does not yet.
#[test]
#[ignore = "needs RSA-4096 PIV import, YubiKey firmware 5.7 or later and a yubikey crate with room for it"]
fn provision_and_verify_rsa4096_card() {
    let subject = subject().with_algorithm(Algorithm::Rsa4096);
    let serial = target();

    provision_and_verify(&subject, &serial, 7);
}

/// Sections 1 to 4 of the checklist: provision, then assert what landed on the card and
/// that the card signs and agrees with it. Returns the chain and the open token for the
/// steps that follow; `total` is only for the step counter in the progress lines.
fn provision_and_verify(
    subject: &SeededSmartcard,
    serial: &str,
    total: usize,
) -> (CertChain, YubiKey) {
    // -- Section 1: provision ------------------------------------------------------------
    //
    // Build the chain offline first. If this disagrees with what `upload` returns, the card
    // path has diverged from the reproducible one.
    eprintln!("[1/{total}] deriving the chain offline");
    let offline = subject
        .certify(CertificateKind::Chain)
        .expect("offline certify failed");

    // No touch here: `upload` installs the management key touch-free and only switches the
    // requirement on once provisioning has succeeded
    eprintln!("[2/{total}] uploading to card {serial}");
    let uploaded = on_card("upload", subject.upload(Some(serial.to_string())));

    assert_eq!(
        uploaded
            .to_pem(CertificateKind::Chain)
            .expect("uploaded chain does not encode"),
        offline
            .to_pem(CertificateKind::Chain)
            .expect("offline chain does not encode"),
        "upload and certify produced different chains",
    );

    eprintln!("[3/{total}] running check -- TOUCH THE TOKEN when it blinks");
    on_card("check", subject.check(Some(serial.to_string())));

    // -- Section 2: what actually landed -------------------------------------------------
    //
    // `check` reports policy and msroots mismatches as warnings rather than failures, so
    // neither is actually asserted by the call above. Do it here, where a regression fails.
    eprintln!("[4/{total}] asserting slot policies and certificates");
    let mut token = open();

    // GET METADATA arrived with YubiKey firmware 5.3; before it the policies cannot be read
    // back, and what proves the keys there is the certificate comparison below and the
    // card using every key in section 3
    let version = token.version();
    let has_metadata = (version.major, version.minor) >= (5, 3);
    if !has_metadata {
        eprintln!("      firmware {version} has no GET METADATA, slot policies are not readable");
    }

    for (slot, pin_policy, touch_policy) in EXPECTED_POLICIES {
        if has_metadata {
            let metadata = piv::metadata(&mut token, slot)
                .unwrap_or_else(|e| panic!("cannot read {slot:?} metadata: {e}"));

            assert_eq!(
                metadata.policy,
                Some((pin_policy, touch_policy)),
                "{slot:?} policy is not {pin_policy:?}/{touch_policy:?}",
            );
        }

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
    eprintln!("[5/{total}] asserting msroots");
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
    eprintln!("[6/{total}] asserting CHUID and CCC");
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
    eprintln!("[7/{total}] on-card signing and key agreement");
    card_authentication_needs_no_pin(&mut token, &offline);
    signature_slot_refuses_without_pin(&mut token, &offline);
    authentication_slot_signs(&mut token, &offline);
    signature_slot_signs(&mut token, &offline);
    key_management_slot_agrees(&mut token, &offline);

    (offline, token)
}

/// Slot 9E signs with no PIN and no touch.
///
/// The NIST SP 800-73-4 requirement behind the per-slot policy table, and the item most
/// likely to regress. Note this cannot be checked through PKCS#11: OpenSC advertises a
/// token-level "login required" flag, so `pkcs11-tool` logs in whether or not it is asked to,
/// which tests OpenSC's policy rather than the card's. Going straight at the card is
/// unambiguous.
fn card_authentication_needs_no_pin(token: &mut YubiKey, chain: &CertChain) {
    let message = b"card authentication";
    let cert = leaf(chain, SlotId::CardAuthentication);

    let signature = sign(token, message, cert, SlotId::CardAuthentication)
        .expect("9E refused to sign without a PIN, but its policy is PinPolicy::Never");

    verify(&signature, message, cert, "9E");
}

/// Slot 9C refuses to sign until the PIN is presented, every time.
///
/// The negative half of `PinPolicy::Always`: the slot metadata merely *records* the policy,
/// this proves the card enforces it. Cheap to run -- the card rejects on the PIN check,
/// before it ever waits for a touch.
fn signature_slot_refuses_without_pin(token: &mut YubiKey, chain: &CertChain) {
    let result = sign(token, b"signature slot", leaf(chain, SlotId::Signature), SlotId::Signature);

    assert!(result.is_err(), "9C signed without a PIN, but its policy is PinPolicy::Always",);
}

/// Slot 9A signs once the PIN is presented, and the signature verifies under its certificate.
fn authentication_slot_signs(token: &mut YubiKey, chain: &CertChain) {
    token
        .verify_pin(TEST_PIN.as_bytes())
        .expect("card rejected the PIN we provisioned it with");

    let message = b"authentication slot";
    let cert = leaf(chain, SlotId::Authentication);

    eprintln!("      9A signing -- TOUCH THE TOKEN when it blinks");
    let signature = sign(token, message, cert, SlotId::Authentication)
        .expect("9A refused to sign after a PIN and a touch");

    verify(&signature, message, cert, "9A");
}

/// Slot 9C signs once the PIN is presented right before, and the signature verifies.
///
/// The positive half of `PinPolicy::Always`, so that every algorithm's run proves the
/// signature key works rather than only that it is guarded; the full checklist's S/MIME step
/// covers the same slot through PKCS#11, on P-256 only.
fn signature_slot_signs(token: &mut YubiKey, chain: &CertChain) {
    token
        .verify_pin(TEST_PIN.as_bytes())
        .expect("card rejected the PIN we provisioned it with");

    let message = b"signature slot";
    let cert = leaf(chain, SlotId::Signature);

    eprintln!("      9C signing -- TOUCH THE TOKEN when it blinks");
    let signature = sign(token, message, cert, SlotId::Signature)
        .expect("9C refused to sign right after a PIN and a touch");

    verify(&signature, message, cert, "9C");
}

/// Slot 9D performs ECDH on the card, and agrees with the same computation done off it.
///
/// This is the hardware half of the `keyAgreement` decision. The offline suite asserts that
/// `openssl cms -encrypt` accepts the certificate; only the card can show that the key
/// actually derives the same shared secret. Done as raw ECDH rather than a CMS round trip so
/// that it needs no OpenSSL engine configuration.
fn key_management_slot_agrees(token: &mut YubiKey, chain: &CertChain) {
    let cert = leaf(chain, SlotId::KeyManagement);

    match slot_algorithm(cert) {
        AlgorithmId::X25519 => return x25519_key_management_slot_agrees(token, cert),
        algorithm @ (AlgorithmId::Rsa2048 | AlgorithmId::Rsa3072 | AlgorithmId::Rsa4096) => {
            return rsa_key_management_slot_decrypts(token, cert, algorithm);
        }
        AlgorithmId::EccP384 => return p384_key_management_slot_agrees(token, cert),
        _ => {}
    }

    let card_public = PublicKey::from_sec1_bytes(public_key_bytes(cert))
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

/// The X25519 twin of the P-256 agreement above: the card takes the peer's raw 32-byte
/// point and returns the raw shared secret, which `x25519-dalek` has to reproduce.
fn x25519_key_management_slot_agrees(token: &mut YubiKey, cert: &Certificate) {
    let card_public: [u8; 32] = public_key_bytes(cert)
        .try_into()
        .expect("9D certificate does not carry an X25519 point");
    let ephemeral = StaticSecret::from([0x2bu8; 32]);
    let point = X25519PublicKey::from(&ephemeral);

    eprintln!("      9D key agreement -- TOUCH THE TOKEN when it blinks");
    let on_card =
        piv::decrypt_data(token, point.as_bytes(), AlgorithmId::X25519, SlotId::KeyManagement)
            .expect("9D refused to perform key agreement");

    let off_card = ephemeral.diffie_hellman(&X25519PublicKey::from(card_public));

    assert_eq!(
        on_card.as_slice(),
        off_card.as_bytes(),
        "9D derived a different shared secret than the same key does off the card",
    );
}

/// An RSA key management key decrypts rather than agrees: the card applies the raw private
/// key operation, which is the same for decryption and signing. Fed a PKCS#1 v1.5
/// signature block, it has to return a signature the certificate's public key accepts,
/// which proves the 9D key on the card is the derived one without any padding oracle.
fn rsa_key_management_slot_decrypts(
    token: &mut YubiKey,
    cert: &Certificate,
    algorithm: AlgorithmId,
) {
    let message = b"key management slot";

    eprintln!("      9D private key operation -- TOUCH THE TOKEN when it blinks");
    let result = piv::decrypt_data(
        token,
        &pkcs1_sha256_block(message, cert),
        algorithm,
        SlotId::KeyManagement,
    )
    .expect("9D refused the private key operation");

    verify(&result, message, cert, "9D");
}

/// The P-384 twin of the P-256 agreement: the card takes the peer's uncompressed point and
/// returns the shared x coordinate, which the same computation off the card has to match.
fn p384_key_management_slot_agrees(token: &mut YubiKey, cert: &Certificate) {
    let card_public = p384::PublicKey::from_sec1_bytes(public_key_bytes(cert))
        .expect("9D certificate does not carry a P-384 point");
    let ephemeral =
        p384::SecretKey::from_slice(&[0x2bu8; 48]).expect("ephemeral scalar is invalid");
    let point = ephemeral.public_key().to_sec1_bytes();

    eprintln!("      9D key agreement -- TOUCH THE TOKEN when it blinks");
    let on_card = piv::decrypt_data(token, &point, AlgorithmId::EccP384, SlotId::KeyManagement)
        .expect("9D refused to perform key agreement");
    let off_card =
        p384::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), card_public.as_affine());

    assert_eq!(
        on_card.as_slice(),
        off_card.raw_secret_bytes().as_slice(),
        "9D derived a different shared secret than the same key does off the card",
    );
}

fn sha384(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha384};
    Sha384::digest(data).to_vec()
}

fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).to_vec()
}

/// Sign `message` in `slot`, the way its algorithm wants it: ECDSA takes the digest, the
/// card never hashing for it, pure Ed25519 hashes internally and takes the message, and
/// RSA takes the whole padded block.
fn sign(
    token: &mut YubiKey,
    message: &[u8],
    cert: &Certificate,
    slot: SlotId,
) -> yubikey::Result<yubikey::Buffer> {
    match slot_algorithm(cert) {
        AlgorithmId::Ed25519 => piv::sign_data(token, message, AlgorithmId::Ed25519, slot),
        algorithm @ (AlgorithmId::Rsa2048 | AlgorithmId::Rsa3072 | AlgorithmId::Rsa4096) => {
            piv::sign_data(token, &pkcs1_sha256_block(message, cert), algorithm, slot)
        }
        // ECDSA on P-384 signs a SHA-384 digest, the hash its strength calls for
        AlgorithmId::EccP384 => piv::sign_data(token, &sha384(message), AlgorithmId::EccP384, slot),
        algorithm => piv::sign_data(token, &sha256(message), algorithm, slot),
    }
}

/// `signature` is checked over `message`, not over its digest: the card signs a pre-computed
/// hash for ECDSA, while `Verifier::verify` hashes what it is given, so handing it the digest
/// would hash the hash.
fn verify(signature: &[u8], message: &[u8], cert: &Certificate, slot: &str) {
    match slot_algorithm(cert) {
        AlgorithmId::Ed25519 => {
            let key = ed25519_dalek::VerifyingKey::from_bytes(
                public_key_bytes(cert)
                    .try_into()
                    .expect("slot certificate does not carry an Ed25519 point"),
            )
            .expect("slot certificate does not carry an Ed25519 point");
            let signature = ed25519_dalek::Signature::from_slice(signature)
                .unwrap_or_else(|e| panic!("{slot} signature is not an Ed25519 signature: {e}"));
            key.verify(message, &signature).unwrap_or_else(|e| {
                panic!("{slot} signature does not verify under its certificate: {e}")
            });
        }
        AlgorithmId::Rsa2048 | AlgorithmId::Rsa3072 | AlgorithmId::Rsa4096 => {
            let key = rsa::pkcs1v15::VerifyingKey::<rsa::sha2::Sha256>::new(rsa_public_key(cert));
            let signature = rsa::pkcs1v15::Signature::try_from(signature)
                .unwrap_or_else(|e| panic!("{slot} result is not an RSA signature: {e}"));
            rsa::signature::Verifier::verify(&key, message, &signature).unwrap_or_else(|e| {
                panic!("{slot} signature does not verify under its certificate: {e}")
            });
        }
        AlgorithmId::EccP384 => {
            use p384::ecdsa::signature::Verifier as _;
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key_bytes(cert))
                .expect("slot certificate does not carry a P-384 point");
            let signature = p384::ecdsa::DerSignature::from_bytes(signature)
                .unwrap_or_else(|e| panic!("{slot} signature is not DER: {e}"));
            key.verify(message, &signature).unwrap_or_else(|e| {
                panic!("{slot} signature does not verify under its certificate: {e}")
            });
        }
        _ => {
            let key = VerifyingKey::from_sec1_bytes(public_key_bytes(cert))
                .expect("slot certificate does not carry a P-256 point");
            let signature = DerSignature::from_bytes(signature)
                .unwrap_or_else(|e| panic!("{slot} signature is not DER: {e}"));
            key.verify(message, &signature).unwrap_or_else(|e| {
                panic!("{slot} signature does not verify under its certificate: {e}")
            });
        }
    }
}
