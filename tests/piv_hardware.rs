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

use mind_the_gap::piv::{CertificateKind, SeededSmartcard};
use mind_the_gap::seed::Seed256;

use p256::ecdh;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, VerifyingKey};
use p256::{PublicKey, SecretKey};

use x509_cert::Certificate;
use x509_cert::der::Encode;
use x509_cert::der::EncodePem;

use yubikey::piv::{self, AlgorithmId, SlotId};
use yubikey::{CccId, ChuId, MsRoots, PinPolicy, Serial, TouchPolicy, YubiKey};

use zeroize::Zeroizing;

use std::str::FromStr;
use std::time::{Duration, SystemTime};

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

    // -- Section 1: provision ------------------------------------------------------------
    //
    // Build the chain offline first. If this disagrees with what `upload` returns, the card
    // path has diverged from the reproducible one.
    eprintln!("[1/12] deriving the chain offline");
    let offline = subject
        .certify(CertificateKind::Chain)
        .expect("offline certify failed");

    // No touch here: `upload` installs the management key touch-free and only switches the
    // requirement on once provisioning has succeeded
    eprintln!("[2/12] uploading to card {serial}");
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

    eprintln!("[3/12] running check -- TOUCH THE TOKEN when it blinks");
    on_card("check", subject.check(Some(serial.clone())));

    // -- Section 2: what actually landed -------------------------------------------------
    //
    // `check` reports policy and msroots mismatches as warnings rather than failures, so
    // neither is actually asserted by the call above. Do it here, where a regression fails.
    eprintln!("[4/12] asserting slot policies and certificates");
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
    eprintln!("[5/12] asserting msroots");
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
    eprintln!("[6/12] asserting CHUID and CCC");
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
    eprintln!("[7/12] on-card signing and key agreement");
    card_authentication_needs_no_pin(&mut token, &offline);
    signature_slot_refuses_without_pin(&mut token);
    authentication_slot_signs(&mut token, &offline);
    key_management_slot_agrees(&mut token, &offline);

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

/// The OpenSC PKCS#11 module and OpenSSL's pkcs11 provider, exported by the dev shell.
fn pkcs11_paths() -> (String, String) {
    let module = std::env::var("PKCS11_MODULE")
        .expect("PKCS11_MODULE is not set; enter the dev shell (nix develop), which exports it");
    let provider = std::env::var("OPENSSL_PKCS11_PROVIDER")
        .expect("OPENSSL_PKCS11_PROVIDER is not set; enter the dev shell (nix develop)");
    (module, provider)
}

/// A PKCS#11 URI for one of the card's private keys, with the test pin attached.
///
/// OpenSC numbers the PIV objects 01 (9A), 02 (9C), 03 (9D), 04 (9E). The pin travels in
/// the URI because these runs are headless; it is the fixed test pin, never a real one.
fn pkcs11_key(id: u8) -> String {
    format!("pkcs11:id=%{id:02};type=private?pin-value={TEST_PIN}")
}

/// Write an OpenSSL config that loads the pkcs11 provider next to the default one.
///
/// The key line is `default_properties = ?provider=default` in the algorithm section: it
/// biases *every* fetch in the library context -- including the ones libssl makes deep
/// inside the handshake to generate the ephemeral key-exchange key -- toward the default
/// provider. Without it the pkcs11 provider claims that ephemeral EC/ML-KEM keygen and
/// fails, because a smart card generates no throwaway session keys. The `?` keeps it a
/// preference, so the card's own private key -- which only pkcs11 can load from its URI --
/// still signs through pkcs11.
fn openssl_conf(dir: &std::path::Path, provider: &str, module: &str) -> std::path::PathBuf {
    let provider_dir = std::path::Path::new(provider)
        .parent()
        .expect("provider path has no directory");
    let conf = dir.join("openssl-pkcs11.cnf");
    std::fs::write(
        &conf,
        format!(
            "openssl_conf = openssl_init\n\
             [openssl_init]\n\
             providers = prov\n\
             alg_section = algs\n\
             [algs]\n\
             default_properties = ?provider=default\n\
             [prov]\n\
             default = default_sect\n\
             pkcs11 = pkcs11_sect\n\
             [default_sect]\n\
             activate = 1\n\
             [pkcs11_sect]\n\
             activate = 1\n\
             module = {provider}\n\
             pkcs11-module-path = {module}\n",
        ),
    )
    .expect("cannot write openssl config");
    // OPENSSL_MODULES lets the config's bare `default`/`pkcs11` resolve the provider .so
    unsafe { std::env::set_var("OPENSSL_MODULES", provider_dir) };
    conf
}

/// Run openssl under the pkcs11-enabled config.
fn openssl_pkcs11(conf: &std::path::Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new("openssl")
        .args(args)
        .env("OPENSSL_CONF", conf)
        .output()
        .expect("cannot run openssl")
}

/// Run openssl under the pkcs11 config, feeding `stdin` (a PIN) on standard input.
///
/// The 9C slot is `PIN always` (`CKA_ALWAYS_AUTHENTICATE`): the card demands the PIN again
/// immediately before the signature itself, a context-specific login that the `pin-value=`
/// in the key URI does not satisfy, so openssl prompts for it. With no tty the prompt has
/// to be answered on stdin. 9A and 9D are `PIN once`, so their URI pin is enough.
fn openssl_pkcs11_pin(conf: &std::path::Path, pin: &str, args: &[&str]) -> std::process::Output {
    use std::io::Write;
    let mut child = std::process::Command::new("openssl")
        .args(args)
        .env("OPENSSL_CONF", conf)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("cannot run openssl");
    // The prompt may fire more than once; a couple of lines cover it without blocking
    let feed = format!("{pin}\n{pin}\n");
    child.stdin.take().unwrap().write_all(feed.as_bytes()).ok();
    child.wait_with_output().expect("openssl did not exit")
}

/// A TLS 1.3 handshake authenticates the client with the 9A key on the card.
///
/// `openssl s_server` demands and verifies a client certificate against the derived root
/// (`-Verify 2 -verify_return_error`, so a bad chain aborts the connection); the client
/// signs the handshake with the 9A key through PKCS#11. This is what a browser does with
/// the module loaded as a security device, minus the browser.
fn tls_client_authenticates(
    dir: &std::path::Path,
    conf: &std::path::Path,
    root: &std::path::Path,
    nine_a: &std::path::Path,
) {
    use std::process::{Command, Stdio};

    // Self-signed server identity; the assertion is about the *client* certificate
    let server_key = dir.join("server.key");
    let server_cert = dir.join("server.pem");
    let generated = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
        ])
        .args(["-nodes", "-days", "2", "-subj", "/CN=localhost"])
        .args(["-keyout", server_key.to_str().unwrap()])
        .args(["-out", server_cert.to_str().unwrap()])
        .output()
        .expect("cannot run openssl");
    assert!(generated.status.success(), "cannot mint a server certificate");

    let port = 14000 + (std::process::id() % 2000);
    let mut server = Command::new("openssl")
        // -www, not interactive: an interactive s_server multiplexes its own stdin into
        // the accept loop and never completes the handshake when stdin is not a tty (as
        // here), so it must serve a page and move on instead. -4 because it otherwise
        // binds IPv6 while the loopback client connects over IPv4.
        .args([
            "s_server",
            "-www",
            "-4",
            "-accept",
            &port.to_string(),
            "-naccept",
            "1",
        ])
        // A plain P-256 key exchange: the default X25519MLKEM768 hybrid drives the pkcs11
        // provider down an ephemeral-keygen path it cannot serve, and the group is
        // irrelevant to what this test proves (that the 9A card key authenticates)
        .args(["-groups", "P-256"])
        .args(["-cert", server_cert.to_str().unwrap()])
        .args(["-key", server_key.to_str().unwrap()])
        .args(["-CAfile", root.to_str().unwrap()])
        // -no_check_time: this step tests that the 9A key authenticates and its chain
        // builds to the trusted root, not wall-clock validity -- the test fixture derives
        // certificates at the Unix epoch for reproducibility, so a finite validity window
        // is long "expired" in real time. notBefore/notAfter are covered offline.
        .args(["-Verify", "2", "-verify_return_error", "-no_check_time"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("cannot start s_server");

    // Wait for s_server's own "ACCEPT" line before connecting. A TCP probe is no good --
    // s_server counts any accepted socket against -naccept 1 and would be spent before the
    // real handshake -- and a blind retry loop races the same way. Reading its readiness
    // banner is the one signal that does not consume the single accept slot.
    use std::io::{BufRead, Read};
    let mut server_out = std::io::BufReader::new(server.stdout.take().expect("server stdout"));
    let mut server_log = String::new();
    loop {
        let mut line = String::new();
        if server_out
            .read_line(&mut line)
            .expect("reading s_server stdout")
            == 0
        {
            let _ = server.kill();
            panic!("s_server exited before listening:\n{server_log}");
        }
        server_log.push_str(&line);
        if line.contains("ACCEPT") {
            break;
        }
    }

    let addr = format!("127.0.0.1:{port}");
    let client = openssl_pkcs11(
        conf,
        &[
            "s_client",
            "-4",
            "-connect",
            &addr,
            "-groups",
            "P-256",
            "-cert",
            nine_a.to_str().unwrap(),
            "-key",
            &pkcs11_key(1),
        ],
    );

    // The banners are small, so s_server never blocked on a full pipe while we were not
    // reading; collect the rest now that the handshake is over
    server_out.read_to_string(&mut server_log).ok();
    let mut server_err = String::new();
    server
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut server_err)
        .ok();
    let _ = server.wait();
    server_log.push_str(&server_err);
    let client_log = format!(
        "{}{}",
        String::from_utf8_lossy(&client.stdout),
        String::from_utf8_lossy(&client.stderr)
    );

    assert!(
        client.status.success(),
        "TLS client failed:\nclient: {client_log}\nserver: {server_log}",
    );
    // The server completed the handshake and verified the client's 9A chain: `depth=0`
    // is the leaf it walked to, and one SSL_accept means the mutually-authenticated
    // session actually established rather than aborting at the certificate request.
    assert!(
        server_log.contains("depth=0"),
        "server never verified the 9A client certificate:\n{server_log}",
    );
    assert!(
        server_log.contains("1 server accept"),
        "the mutually-authenticated handshake did not complete:\n{server_log}",
    );
    assert!(!server_log.contains("verify error"), "server rejected the 9A chain:\n{server_log}",);
}

/// S/MIME signing with the 9C key through PKCS#11, verified against the derived root.
///
/// This is the signing half of S/MIME end use: `openssl cms -sign` drives the 9C key on
/// the card, and `-verify` walks the signature to the root. 9C is `PIN always`, so the
/// signature needs the pin fed on stdin -- see `openssl_pkcs11_pin`.
///
/// The *decryption* half is deliberately not here. On-card CMS decryption to 9D fails in
/// this toolchain -- not because of the card or this crate, but because of OpenSSL bug
/// <https://github.com/openssl/openssl/issues/24698>: `fix_ecdh_cofactor()` asserts a
/// non-NONE action type that the PKCS#11 parameter-translation path never sets, so the
/// X9.63 KDF gets a bad SharedInfo and the AES key-unwrap fails
/// (`aes_wrap_cipher_internal: cipher operation failed`). The only known fix is patching
/// OpenSSL. That the card's ECDH itself is correct is proven two other ways that do not
/// go through the broken bridge: `key_management_slot_agrees` (native, via the yubikey
/// crate) and `key_agreement_through_pkcs11` (the standard PKCS#11 `CKM_ECDH1_DERIVE`, the
/// operation a real client's own module performs). If a future OpenSSL fixes #24698, the
/// commented block below is the decrypt half to restore.
fn smime_signs(
    dir: &std::path::Path,
    conf: &std::path::Path,
    root: &std::path::Path,
    nine_c: &std::path::Path,
) {
    use std::process::Command;

    let message = dir.join("msg.txt");
    std::fs::write(&message, b"mind the gap\n").unwrap();
    let signed = dir.join("msg.p7s");

    let sign = openssl_pkcs11_pin(
        conf,
        TEST_PIN,
        &[
            "cms",
            "-sign",
            "-signer",
            nine_c.to_str().unwrap(),
            "-inkey",
            &pkcs11_key(2),
            "-in",
            message.to_str().unwrap(),
            "-out",
            signed.to_str().unwrap(),
            "-md",
            "sha256",
        ],
    );
    assert!(sign.status.success(), "9C signing failed:\n{}", String::from_utf8_lossy(&sign.stderr),);

    let verify = Command::new("openssl")
        .args(["cms", "-verify", "-in", signed.to_str().unwrap()])
        .args(["-CAfile", root.to_str().unwrap()])
        // See the TLS step: the epoch-derived fixture certs are "expired" in real time
        .args([
            "-purpose",
            "smimesign",
            "-no_check_time",
            "-out",
            "/dev/null",
        ])
        .output()
        .expect("cannot run openssl");
    assert!(
        verify.status.success(),
        "signature does not verify:\n{}",
        String::from_utf8_lossy(&verify.stderr),
    );

    // Restore once OpenSSL #24698 is fixed (encrypt to 9D, then decrypt on the card):
    //
    //   let enveloped = dir.join("msg.p7m");
    //   let recovered = dir.join("msg.out");
    //   let encrypt = Command::new("openssl")
    //       .args(["cms", "-encrypt", "-aes256"])
    //       .args(["-in", message.to_str().unwrap()])
    //       .args(["-out", enveloped.to_str().unwrap()])
    //       .arg(nine_d.to_str().unwrap())
    //       .output()
    //       .expect("cannot run openssl");
    //   assert!(encrypt.status.success(), "encryption to 9D failed");
    //   let decrypt = openssl_pkcs11(conf, &[
    //       "cms", "-decrypt", "-in", enveloped.to_str().unwrap(),
    //       "-recip", nine_d.to_str().unwrap(), "-inkey", &pkcs11_key(3),
    //       "-out", recovered.to_str().unwrap(),
    //   ]);
    //   assert!(decrypt.status.success(), "on-card decryption failed");
    //   assert_eq!(std::fs::read(&recovered).unwrap(), b"mind the gap\n");
}

/// On-card key agreement over 9D through the standard PKCS#11 interface.
///
/// The operation a real S/MIME client's own PKCS#11 module performs to decrypt to the
/// card: `CKM_ECDH1_DERIVE`. Driven with `pkcs11-tool` rather than OpenSSL's pkcs11
/// provider, which cannot (OpenSSL #24698, see `smime_signs`). The card derives the
/// shared secret from an offline-generated peer key; the same secret computed in software
/// must match, which proves the 9D key does ECDH correctly through the interface clients
/// actually use.
fn key_agreement_through_pkcs11(dir: &std::path::Path, module: &str, nine_d: &Certificate) {
    use p256::pkcs8::EncodePublicKey;

    // A fixed, valid peer scalar: deterministic, so no RNG is pulled into the test
    let peer = SecretKey::from_bytes(&[0x11u8; 32].into()).expect("0x11.. is a valid P-256 scalar");
    let peer_public = peer.public_key();

    // pkcs11-tool wants the peer key as a DER SubjectPublicKeyInfo
    let peer_spki = dir.join("peer.spki.der");
    std::fs::write(&peer_spki, peer_public.to_public_key_der().unwrap().as_bytes()).unwrap();

    let derived = dir.join("p11.secret");
    let out = std::process::Command::new("pkcs11-tool")
        .args(["--module", module, "--login", "--pin", TEST_PIN])
        .args(["--derive", "--id", "03", "--mechanism", "ECDH1-DERIVE"])
        .args(["--input-file", peer_spki.to_str().unwrap()])
        .args(["--output-file", derived.to_str().unwrap()])
        .output()
        .expect("cannot run pkcs11-tool; enter the dev shell (nix develop)");
    assert!(
        out.status.success(),
        "pkcs11-tool ECDH derive failed:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    let card_secret = std::fs::read(&derived).expect("no derived secret written");

    // The same ECDH computed in software: peer private key against the 9D public key
    let nine_d_public = PublicKey::from_sec1_bytes(
        nine_d
            .tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
            .raw_bytes(),
    )
    .expect("9D certificate does not carry a P-256 point");
    let expected = ecdh::diffie_hellman(peer.to_nonzero_scalar(), nine_d_public.as_affine());

    assert_eq!(
        card_secret.as_slice(),
        expected.raw_secret_bytes().as_slice(),
        "the card's ECDH shared secret does not match the software derivation",
    );
}

/// Resolve an executable to its absolute path by searching `$PATH`.
fn which(program: &str) -> Option<std::path::PathBuf> {
    std::env::var_os("PATH")?
        .to_str()?
        .split(':')
        .map(|dir| std::path::Path::new(dir).join(program))
        .find(|candidate| candidate.is_file())
}

/// SSH public-key authentication with the 9A key, end to end against a throwaway sshd.
///
/// `ssh-keygen -D` first lists the four card keys as SSH public keys (labelled by OpenSC:
/// PIV AUTH is 9A). A local sshd is authorised for that one key, and a client connects
/// through the PKCS#11 module: the card signs the SSH authentication challenge, so a
/// successful login is proof the 9A key authenticates the way an SSH server sees it.
///
/// Two card facts shape the plumbing. 9A is `PIN once`, and `ssh` has no flag for the pin,
/// so it comes through `SSH_ASKPASS` (forced, since the child has no tty). And 9A is
/// `touch cached`, so the signature blinks for a touch -- a missed touch surfaces as
/// `C_Sign failed: 257` (`CKR_USER_NOT_LOGGED_IN`), the same symptom as the `check` step.
fn ssh_authenticates(dir: &std::path::Path, module: &str) {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let keys = Command::new("ssh-keygen")
        .args(["-D", module])
        .output()
        .expect("cannot run ssh-keygen; enter the dev shell (nix develop)");
    assert!(
        keys.status.success(),
        "ssh-keygen -D failed:\n{}",
        String::from_utf8_lossy(&keys.stderr)
    );
    let listed = String::from_utf8_lossy(&keys.stdout);
    let count = listed
        .lines()
        .filter(|l| l.starts_with("ecdsa-sha2-nistp256"))
        .count();
    assert_eq!(count, 4, "expected the four card keys, ssh-keygen listed:\n{listed}");

    // Authorise only 9A ("PIV AUTH"), so a successful login pins the auth to that key
    let ninea_line = listed
        .lines()
        .find(|l| l.contains("PIV AUTH"))
        .expect("ssh-keygen did not label a PIV AUTH (9A) key");
    let ninea_key = ninea_line
        .rsplit_once(' ')
        .map(|(k, _)| k)
        .unwrap_or(ninea_line);
    let authorized = dir.join("authorized_keys");
    std::fs::write(&authorized, format!("{ninea_key}\n")).unwrap();

    let host_key = dir.join("host_key");
    assert!(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&host_key)
            .status()
            .expect("cannot run ssh-keygen")
            .success(),
        "generating the host key failed",
    );

    let askpass = dir.join("askpass.sh");
    std::fs::write(&askpass, format!("#!/bin/sh\necho {TEST_PIN}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let port = 17000 + (std::process::id() % 2000);
    let pid_file = dir.join("sshd.pid");
    let sshd_log = dir.join("sshd.log");
    let config = dir.join("sshd_config");
    std::fs::write(
        &config,
        format!(
            "Port {port}\n\
             HostKey {host}\n\
             AuthorizedKeysFile {authorized}\n\
             PubkeyAuthentication yes\n\
             PasswordAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             UsePAM no\n\
             StrictModes no\n\
             PidFile {pid}\n\
             LogLevel VERBOSE\n",
            host = host_key.display(),
            authorized = authorized.display(),
            pid = pid_file.display(),
        ),
    )
    .unwrap();

    // sshd re-executes itself for each connection and refuses a relative argv[0]
    // ("sshd requires execution with an absolute path"), so resolve it on PATH first
    let sshd_path = which("sshd").expect("sshd not found on PATH; enter the dev shell");

    // -D keeps sshd in the foreground, so the spawned child is the listener and can be
    // killed directly rather than chasing the daemonised process
    let mut sshd = Command::new(&sshd_path)
        .arg("-D")
        .arg("-f")
        .arg(&config)
        .arg("-E")
        .arg(&sshd_log)
        .spawn()
        .expect("cannot start sshd; enter the dev shell (nix develop)");
    for _ in 0..100 {
        if pid_file.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let client = Command::new("ssh")
        .args(["-F", "/dev/null"])
        .args(["-o", "StrictHostKeyChecking=no"])
        .args(["-o", "UserKnownHostsFile=/dev/null"])
        .args(["-o", "PreferredAuthentications=publickey"])
        .args(["-I", module])
        .args(["-p", &port.to_string()])
        .arg(format!("{user}@127.0.0.1"))
        .arg("echo AUTH_OK_FROM_CARD")
        .env("SSH_ASKPASS", &askpass)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", ":0")
        .stdin(Stdio::null())
        .output()
        .expect("cannot run ssh");

    // Stop sshd before asserting, so a failure never leaves it listening
    let _ = sshd.kill();
    let _ = sshd.wait();

    let stdout = String::from_utf8_lossy(&client.stdout);
    let stderr = String::from_utf8_lossy(&client.stderr);
    assert!(
        client.status.success() && stdout.contains("AUTH_OK_FROM_CARD"),
        "SSH auth with the 9A key failed (a missed touch shows as C_Sign 257):\n{stderr}",
    );

    let _ = std::io::stderr().flush();
}

/// The real Firefox/Thunderbird/Chrome crypto stack recognises the card, its keys and chain.
///
/// NSS is what those clients use, so loading the OpenSC module into an NSS database and
/// seeing every slot certificate -- each with its private key, under a trusted derived root
/// -- is the compatibility statement that matters. This half needs no touch and no token
/// login: `certutil -L` reads the certificate objects the module exposes.
///
/// The remaining half, on-card *decryption* through NSS's `cmsutil`, is not asserted -- the
/// commented block at the end of this function is the code we would want, with the exact
/// invocation and the observed `SEC_ERROR_INVALID_KEY`. Unlike the OpenSSL path (a filed
/// bug, #24698), this NSS behaviour is not tied to a known upstream report, so it is
/// flagged there for reproduction rather than cited. The 9D key's ECDH is proven either
/// way by `key_agreement_through_pkcs11` and `key_management_slot_agrees`, and the chain's
/// usage validation is covered offline in `tests/piv.rs` (against non-expiring certs, since
/// this fixture's 10-year window is long past).
fn nss_recognises_card(dir: &std::path::Path, module: &str, root: &std::path::Path) {
    use std::process::Command;

    let db = format!("sql:{}", dir.display());
    let run = |program: &str, args: &[&str]| {
        Command::new(program)
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("cannot run {program}: {e}"))
    };

    assert!(
        run("certutil", &["-N", "-d", &db, "--empty-password"])
            .status
            .success(),
        "cannot create the scratch NSS database",
    );
    assert!(
        run(
            "certutil",
            &[
                "-A",
                "-n",
                "mtg-root",
                "-t",
                "CT,C,C",
                "-d",
                &db,
                "-i",
                root.to_str().unwrap()
            ]
        )
        .status
        .success(),
        "cannot import the derived root into NSS",
    );
    assert!(
        run(
            "modutil",
            &[
                "-add", "opensc", "-libfile", module, "-dbdir", &db, "-force"
            ]
        )
        .status
        .success(),
        "cannot load the OpenSC PKCS#11 module into NSS",
    );

    let listed = run("certutil", &["-L", "-d", &db, "-h", "all"]);
    let certs = String::from_utf8_lossy(&listed.stdout);
    assert!(
        listed.status.success(),
        "certutil -L failed:\n{}",
        String::from_utf8_lossy(&listed.stderr)
    );

    // The four PIV slot certificates, by the nicknames OpenSC gives them
    for expected in [
        "Certificate for PIV Authentication",
        "Certificate for Digital Signature",
        "Certificate for Key Management",
        "Certificate for Card Authentication",
    ] {
        assert!(certs.contains(expected), "NSS does not see the {expected:?} card cert:\n{certs}");
    }
    // A `u` trust flag marks a cert NSS holds a matching private key for
    assert!(
        certs.contains("u,u,u"),
        "NSS does not report a private key for any card cert:\n{certs}"
    );

    // On-card CMS decryption to 9D -- the flow Thunderbird runs -- is the code we would
    // want here, but it does not work through NSS and the ECDH is already proven by steps
    // 7 and 10, so it stays commented rather than asserted. The token login needs
    // `-f <pinfile>` (the token pin), NOT `-D`'s `-p` (only the NSS database password);
    // with that fixed the decrypt still fails:
    //
    //     SEC_ERROR_INVALID_KEY: The key does not support the requested operation.
    //
    // even though the 9D key advertises `CKA_DERIVE` and `pkcs11-tool` performs the
    // identical `CKM_ECDH1_DERIVE` against it (see `key_agreement_through_pkcs11`). This is
    // NOT tied to a filed upstream bug: a search turned up only moz#1241446, which is about
    // ECDSA *signature* verification with software keys, not ECDH decryption on a token.
    // It wants minimal-reproduction and an NSS report before it can be cited the way the
    // OpenSSL path cites #24698. To reproduce (needs a 9D touch):
    //
    //   let pin = dir.join("pin"); std::fs::write(&pin, format!("{TEST_PIN}\n")).unwrap();
    //   let msg = dir.join("msg"); std::fs::write(&msg, b"mind the gap\n").unwrap();
    //   let env = dir.join("env.p7m");
    //   run("cmsutil", &["-E", "-d", &db, "-r", "Hardware Test:Certificate for Key Management",
    //                    "-i", msg.to_str().unwrap(), "-o", env.to_str().unwrap()]);
    //   let out = dir.join("out");
    //   let d = run("cmsutil", &["-D", "-d", &db, "-f", pin.to_str().unwrap(),
    //                            "-i", env.to_str().unwrap(), "-o", out.to_str().unwrap()]);
    //   assert!(d.status.success(), "NSS on-card decrypt failed");
    //   assert_eq!(std::fs::read(&out).unwrap(), b"mind the gap\n");
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
