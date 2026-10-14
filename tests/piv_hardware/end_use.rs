//! End use through the standard stacks: PKCS#11, TLS, S/MIME, SSH and NSS.

use crate::TEST_PIN;

use p256::ecdh;

use p256::{PublicKey, SecretKey};

use x509_cert::Certificate;

/// The OpenSC PKCS#11 module and OpenSSL's pkcs11 provider, exported by the dev shell.
pub(super) fn pkcs11_paths() -> (String, String) {
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
pub(super) fn openssl_conf(
    dir: &std::path::Path,
    provider: &str,
    module: &str,
) -> std::path::PathBuf {
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
pub(super) fn tls_client_authenticates(
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
pub(super) fn smime_signs(
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
pub(super) fn key_agreement_through_pkcs11(
    dir: &std::path::Path,
    module: &str,
    nine_d: &Certificate,
) {
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
pub(super) fn ssh_authenticates(dir: &std::path::Path, module: &str) {
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
/// usage validation is covered offline in `tests/piv/external.rs` (against non-expiring certs, since
/// this fixture's 10-year window is long past).
pub(super) fn nss_recognises_card(dir: &std::path::Path, module: &str, root: &std::path::Path) {
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
