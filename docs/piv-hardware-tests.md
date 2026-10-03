# PIV hardware test checklist

The PIV certificate chain is fully covered by `cargo test --test piv` *except* for everything
that needs a physical card. This document is the remaining manual checklist.

Sections 1 to 5 have been automated as `tests/piv_hardware.rs`; see *Automated card tests*
immediately below. The manual steps are kept because they are what the test was derived from,
and because they are still how you diagnose a failure. Nothing on the list needs GUI
software: the TLS handshake and the S/MIME round trip that a browser or mail client would
perform run headless in the suite, and NSS chain validation runs offline in `cargo test`.

Reference rig the checklist was written against:

| | |
|---|---|
| Token | YubiKey 5C NFC, firmware 5.4.3 |
| Tooling | OpenSC 0.27.1, OpenSSL 3.6.2, ykman 5.8.0, NSS 3.112.5, libp11 0.4.13 |
| Inputs | `-d 2026-01-01 -v 10y`, PIN `123456`, no `--intermediate` (two-tier chain) |
| Seed | the public BIP39 test mnemonic `abandon … art` |

> Use a **throwaway seed** for this checklist: the card it leaves behind holds test keys and
> its CA is derivable by anyone. Never install that root as a trust anchor, add its 9A key to
> an `authorized_keys`, or leave the card in service. Re-run `piv upload` with a real seed to
> provision a card for actual use.

> **`piv upload` is destructive.** It deliberately exhausts the PIN and PUK retry counters and
> then calls `reset_device`, wiping every key, certificate and object on the card. Use a spare
> YubiKey, not your daily driver.

## Automated card tests

Most of sections 1 to 4 now run as a real test, `tests/hardware.rs`, so the manual walk below
is for the parts that need a human or a GUI. The automated test asserts the same things this
document does, and a few the checklist could only eyeball:

| | |
|---|---|
| Section 1 | `upload` and `certify` produce the same chain; `check` agrees with the card |
| Section 2 | every slot's PIN and touch policy, and each certificate byte-for-byte |
| Section 3 | 9E signs with no PIN; 9C *refuses* without one; 9A signs and verifies |
| Section 4 | `msroots` holds exactly the derived authorities |
| extra | 9D performs ECDH on the card and agrees with the same computation done off it |

Two of those are assertions the tool itself will not make: `check` downgrades a policy or
`msroots` mismatch to a `log::warn`, so neither actually fails the command. The test asserts
both. The policy table is also spelled out in the test rather than read back from
`SeededSmartcard::policies_for`, so that changing the implementation's table fails the test
instead of silently agreeing with itself.

There is a sibling suite for the OpenPGP backend in `tests/pgp_hardware.rs`, gated on the same
two features. It resets only the OpenPGP applet, so one token can carry both.

### Running them

The tests are destructive, so they are gated on a feature *and* on naming the card:

Read the serial off the card first (`ykman list`) and type it -- substituting a
`$(ykman list --serials)` picks whatever token happens to be plugged in, which is exactly
the accident the requirement exists to prevent:

```
gpgconf --kill scdaemon        # see below
MTG_HARDWARE_TEST_SERIAL=12345678 \
  cargo test --features destructive-hardware-tests --test piv_hardware -- --nocapture
```

Expect to touch the token three times: `check`, the 9A signature and the 9D key agreement.
`upload` needs none. Each prompt blocks until you press the button, and the token's own touch
timeout is about fifteen seconds, so a prompt missed is a step failed. `--nocapture` is what
makes the prompts visible; without it they are buffered until the test ends.

Without `MTG_HARDWARE_TEST_SERIAL` the test fails immediately and touches nothing. That is
deliberate: the feature flag says "run destructive tests", the variable says "against *that*
card", and neither alone is enough to reset a token.

### The two feature flags

```toml
destructive-hardware-tests = []      # opt in
no-destructive-hardware-tests = []   # safety interlock -- never enable by hand
```

`tests/hardware.rs` compiles only when the first is on and the second is off. The second
exists because `--all-features` turns on *every* feature, so without it a routine
`cargo test --all-features` -- in CI, or from a habit -- would silently wipe whatever card
happened to be plugged in. Enabling both, which is exactly what `--all-features` does,
compiles the tests out instead. Verified in all three configurations:

| invocation | tests in `piv_hardware` binary |
|---|---|
| `cargo test` | 0 |
| `cargo test --all-features` | 0 |
| `cargo test --features destructive-hardware-tests --test piv_hardware` | 1 |

### scdaemon will hold the card

GnuPG's `scdaemon` takes an exclusive PC/SC connection to the *whole token* as soon as
anything asks gpg to talk to a card, and it lingers afterwards. Every later PIV access then
fails with `The smart card cannot be accessed because of other connections outstanding`, which
names nothing. Release it before running the hardware tests:

```
gpgconf --kill scdaemon
```

The test recognises this specific failure and says so rather than leaving you to guess.

It is normally left over from ordinary gpg use, **not** from anything in this repository: the
OpenPGP suite here only calls `gpg --show-keys`, which parses a file and never touches a card.
Verified by killing scdaemon, running `cargo test --test pgp gpg_accepts_exported_cert`, and
confirming none was started. A GPG *hardware* test does start one, and has to stop it again on
teardown.

### Can gpg and PIV share the card?

Partly, and not reliably enough to depend on.

The `yubikey` crate already connects with `pcsc::ShareMode::Shared`, so this side cooperates.
scdaemon is the obstacle, in two separate ways:

1. It defaults to its **internal CCID driver**, which claims the USB interface directly and
   fails with `selecting card failed: No such device` whenever `pcscd` already holds it --
   even with nothing else touching the card. `disable-ccid` routes it through PC/SC instead.
2. Through PC/SC it still asks for an **exclusive** connection. `pcsc-shared` relaxes that,
   which GnuPG's own manpage calls "somewhat dangerous… Scdaemon assumes exclusive access and
   for example caches certain information from the card".

With both set in `~/.gnupg/scdaemon.conf`:

```
disable-ccid
pcsc-shared
```

gpg reads the OpenPGP applet while PIV keeps working -- but the cache warning is not
theoretical. Six interleaved rounds of `gpg --card-status` and `mind-the-gap piv status`, with
a single scdaemon, alternated exactly:

| round | 1 | 2 | 3 | 4 | 5 | 6 |
|---|---|---|---|---|---|---|
| gpg | FAIL | OK | FAIL | OK | FAIL | OK |
| piv | OK | OK | OK | OK | OK | OK |

Every PIV access invalidates scdaemon's cached state, and the next gpg operation fails before
recovering on the one after. PIV is unaffected throughout. So the two *can* coexist, but gpg
needs a retry to be dependable -- which is why the tests stop scdaemon rather than share with
it.

## Prerequisites

A YubiKey 5 series (or any PIV token supporting AES-256 management keys and P-256 import), a
CCID reader, and a running `pcscd` (a socket-activated `pcscd.socket` is enough).

All of the tooling is in the project's dev shell, so just:

```
nix develop
```

That provides `openssl`, `opensc` (`pkcs11-tool`, `pkcs15-tool`, `opensc-tool`),
`yubikey-manager` (`ykman`) and `nss.tools` (`certutil`, `modutil`), alongside the `sq` and
`gpg` the OpenPGP tests use.

> **Note.** Every step below uses `ykman` rather than `yubico-piv-tool`, which is *not* in
> the dev shell. `ykman` is the CLI Yubico develops most actively and covers everything this
> checklist needs. The only `yubico-piv-tool` features without a `ykman` equivalent are
> `-a test-signature` and `-a test-decipher`, and they add no coverage here: sections 3 and 5
> already exercise the same card operations through real clients.

Tests that shell out to an external tool are marked `#[ignore]` when that tool is absent, via
the probe in `build.rs`, so they are reported as ignored rather than quietly passing. Inside
the dev shell nothing should be ignored:

```
cargo test        # expect 0 ignored
```

If you see `N ignored`, a tool is missing and those checks did **not** run.

- [x] `cargo test` green with 0 ignored — 53 passed across 10 binaries (piv 21, pgp 17,
      seed 6, mnemonic 5, completion 2, argon 1, cli 1)

Throughout, `$PKCS11` is the `opensc-pkcs11.so` from the dev shell:

```
export PKCS11=$(dirname $(dirname $(command -v pkcs11-tool)))/lib/opensc-pkcs11.so
```

## 1. Provision the card

```
export MIND_THE_SEED="<24 words>"
export MIND_THE_NAME="Your Name"
export MIND_THE_EMAILS="you@example.com"

# Offline first: this must succeed before any card is touched
mind-the-gap piv -d 2026-01-01 -v 10y certify --kind chain -o chain.pem
mind-the-gap piv -d 2026-01-01 certify --kind root -o root.pem

# DESTRUCTIVE: resets the card
mind-the-gap piv -d 2026-01-01 -v 10y upload -i <6-8 digit pin> -o uploaded.pem
```

`upload` prompts for confirmation on stdin. Pass `-y` / `--yes` to skip the prompt when
scripting; without a terminal and without `--yes` it now aborts rather than hanging.

Expect **one** touch prompt during upload, when the management key is authenticated
(`[Please touch device to authenticate management access!]`).

- [x] `cmp chain.pem uploaded.pem` -- upload and certify produce the same chain
- [x] `mind-the-gap piv check` reports all four slots matching (this also needs a touch,
      because the management key is installed with require-touch)
- [x] `mind-the-gap piv status` lists four keys with the expected subjects

`piv status` also lists the Yubico attestation cert.

## 2. Confirm what actually landed on the card

```
pkcs11-tool --module $PKCS11 -O --login --pin <pin>
ykman piv info
for s in 9a 9c 9d 9e; do ykman piv keys info $s; done
```

- [x] Four private keys and four certificates, all `EC` / `P-256`
- [x] Per-slot policies match: 9A `PIN once / touch cached`, 9C `PIN always / touch always`,
      9D `PIN once / touch cached`, 9E `PIN never / touch never`
- [x] `ykman piv info` shows `Management key algorithm: AES256` (a freshly reset card reports
      `TDES`, so this confirms the key was replaced) and every slot issued by the root CA
      rather than self-signed
- [x] Certificates read back byte-identical to the offline ones. Map ids by label from the
      `-O` listing rather than assuming. The conventional OpenSC mapping 01=9A, 02=9C, 03=9D,
      04=9E was **confirmed** on the tested card, but keep checking it:

```
for id in 01 02 03 04; do
  pkcs11-tool --module $PKCS11 -r --type cert --id $id -o card-$id.der
  openssl x509 -inform der -in card-$id.der -noout -subject -fingerprint -sha256
done
```

Two observations that are expected, not faults:

- `PUK is blocked` / `PUK tries remaining: 0/3`. `upload` blocks the PUK on purpose after
  provisioning (`src/piv.rs`, `token.block_puk()`); there is no PUK recovery path by design,
  since the keys are re-derivable from the seed.
- `WARNING: Using default PIN!` appears only when the PIN passed to `-i` is the PIV default
  `123456`.

## 3. On-card signing

```
echo hello > msg.txt
pkcs11-tool --module $PKCS11 --login --pin <pin> --id 01 --sign \
            --mechanism ECDSA-SHA256 -i msg.txt -o sig.bin
```

`pkcs11-tool` emits a raw `r||s` pair; wrap it in DER before checking it with
`openssl dgst -verify` against the matching slot certificate.

- [x] 9A signs after a PIN and a touch, and the signature verifies against the 9A certificate
- [x] 9C demands a *fresh* PIN and touch for every single signature (`PinPolicy::Always`).
      Verified positively (two signatures, two touches, both verifying) **and** negatively:
      a third attempt with no touch fails after exactly the YubiKey's 15-second touch
      timeout, which is the proof that the policy is enforced rather than merely recorded in
      the slot metadata.
- [x] **9E signs with no PIN at all** -- the NIST SP 800-73-4 requirement that motivated the
      per-slot policy table, and the one most likely to regress

> **Note.** The 9E check cannot be made with `pkcs11-tool`. OpenSC's PIV
> emulation advertises a *token-level* `login required` flag, so `pkcs11-tool` performs a
> `C_Login` for any private-key operation whether or not `--login` is passed — it prompts for
> a PIN and, given none, aborts. That exercises OpenSC's policy, not the card's. Test the
> card directly instead, which is unambiguous:
>
> ```
> HASH=$(openssl dgst -sha256 -binary msg.txt | od -An -tx1 | tr -d ' \n')
> opensc-tool -s "00:A4:04:00:0B:A0:00:00:03:08:00:00:10:00:01:00" \
>             -s "00:87:11:9E:26:7C:24:82:00:81:20:$(echo $HASH | sed 's/../&:/g; s/:$//')"
> ```
>
> A `SW1=0x90 SW2=0x00` response carrying a `7C … 82 <len> 30 …` DER signature, with no
> preceding `VERIFY` APDU and no touch, is the pass condition. Extract the inner `30 …`
> signature and confirm it against the 9E certificate with `openssl dgst -sha256 -verify`.

## 4. msroots

```
ykman piv objects export 0x5fff11 msroots.der
```

The object is wrapped in a `0x82` TLV, so strip the header before OpenSSL will parse it —
for a 490-byte object that is the first 4 bytes:

```
python3 -c "
d=open('msroots.der','rb').read(); assert d[0]==0x82
n=d[1]&0x7f; ln=int.from_bytes(d[2:2+n],'big'); i=2+n
open('msroots-inner.der','wb').write(d[i:i+ln])"
openssl pkcs7 -inform der -in msroots-inner.der -print_certs -noout
```

- [x] The root CA (and the issuing CA when `--intermediate` was used) is listed, with a
      SHA-256 fingerprint equal to the offline `root.pem`
- [x] `mind-the-gap piv check` reports the msroots contents as matching

This is the only part of the upload path that is allowed to fail without aborting: a write
error is logged as a warning, since `msroots` is Windows-specific. Verify it actually
succeeded rather than trusting a clean exit.

## 5. End use

For the OpenSSL steps the dev shell has no PKCS#11 *provider*, only the libp11 *engine*, and
it is not registered by default. Point OpenSSL at it explicitly:

```
cat > openssl-pkcs11.cnf <<EOF
openssl_conf = openssl_init
[openssl_init]
engines = engine_section
[engine_section]
pkcs11 = pkcs11_section
[pkcs11_section]
engine_id = pkcs11
dynamic_path = $(find /nix/store -maxdepth 4 -name pkcs11.so -path '*engines*' | head -1)
MODULE_PATH = $PKCS11
init = 0
EOF
export OPENSSL_CONF=$PWD/openssl-pkcs11.cnf
```

The engine prompts for the token PIN, and for slots with `PIN always` (9C) a second,
key-level PIN as well — that is `CKA_ALWAYS_AUTHENTICATE`, and libp11 will not take it from a
`pin-value=` in the URI. Feed both on stdin when scripting.

### SSH

```
ssh-keygen -D $PKCS11
ssh -I $PKCS11 user@host
```

- [x] Four `ecdsa-sha2-nistp256` keys listed
- [x] **the 9A key authenticates.** Automated as step 11 of the suite: a throwaway sshd is
      authorised for only the 9A key, and the client logs in through the PKCS#11 module, so
      a successful session is the card carrying the login. The pin is fed via `SSH_ASKPASS`
      (ssh has no pin flag), and the 9A touch blinks during the challenge signature.

Two traps cost real time here, both worth knowing before you debug a failure:

- `IdentitiesOnly=yes` filters PKCS#11 identities out before they are ever offered, so the
  card key is never tried and the failure looks like a server-side rejection.
- **The touch is easy to miss.** 9A is `touch cached`, and if you do not press the button the
  signing step fails with `C_Sign failed: 257` (`CKR_USER_NOT_LOGGED_IN`) on the direct route
  or `agent refused operation` via `ssh-agent` -- neither of which mentions the touch. Watch
  the token, not the terminal.

If you route through an agent rather than `ssh -I`, note that `ssh-agent` refuses a provider
outside its built-in allowlist, so a Nix store path needs
`ssh-agent -P '/nix/store/*/lib/*.so'`.

### TLS client authentication

```
openssl s_server -accept 4433 -cert server.pem -key server.key \
                 -CAfile root.pem -Verify 2 -verify_return_error
```

- [x] A TLS 1.3 handshake completes using the 9A certificate. Driven with `openssl s_client
      -cert 9a.pem -key "pkcs11:id=%01;type=private" -keyform ENGINE -engine pkcs11`; the
      server logs `depth=1` (root CA) then `depth=0` (9A leaf) and `1 server accepts that
      finished`, under `-Verify 2 -verify_return_error` so a verification failure would have
      aborted the connection.

The handshake above *is* a browser's client-certificate authentication -- the TLS stack
neither knows nor cares what drives it -- so no separate browser run is kept on the list.
The automated suite performs the same handshake as step 8.

### S/MIME

```
# sign with 9C
openssl cms -sign -signer 9c.pem -inkey "pkcs11:id=%02;type=private" \
            -keyform ENGINE -engine pkcs11 -in msg.txt -out msg.p7s -md sha256
openssl cms -verify -in msg.p7s -CAfile root.pem -purpose smimesign -out /dev/null

# encrypt to 9D, decrypt on card
openssl cms -encrypt -aes256 -in msg.txt -out msg.p7m 9d.pem
openssl cms -decrypt -in msg.p7m -recip 9d.pem \
            -inkey "pkcs11:id=%03;type=private" -keyform ENGINE -engine pkcs11
```

- [x] Signing and verification round-trip, with `ecdsa-with-SHA256` on the signerInfo.
      Automated as step 9 of the suite (`openssl cms -sign` drives 9C through PKCS#11).
- [x] **Decryption on card succeeds** -- the real test of the `keyAgreement` decision (see the
      caveat below), and it cannot be checked offline.

> **On-card CMS decryption via OpenSSL's pkcs11 provider does not work, and the cause is
> upstream.** `openssl cms -decrypt` against 9D fails at the AES key-unwrap
> (`aes_wrap_cipher_internal: cipher operation failed`) because of OpenSSL bug
> [#24698](https://github.com/openssl/openssl/issues/24698): `fix_ecdh_cofactor()` asserts a
> non-NONE action type that the PKCS#11 parameter-translation path never sets, so the X9.63
> KDF is fed a bad SharedInfo and derives the wrong key-encryption-key. The only known fix is
> to patch OpenSSL. The 9D key's ECDH is nonetheless proven correct two ways that avoid the
> broken bridge, both automated: the native derivation (step 7, via the `yubikey` crate) and
> the standard PKCS#11 `CKM_ECDH1_DERIVE` (step 10, via `pkcs11-tool`, the operation a real
> client's own module performs). A client that does its own ECDH+KDF -- Thunderbird through
> NSS, say -- is unaffected by the OpenSSL bug. To reproduce the failure by hand, use the
> `openssl cms` invocation above.

### NSS / Thunderbird

```
certutil -A -n "MTG PIV Root" -t "CT,C,C" -d sql:$HOME/.pki/nssdb -i root.pem
modutil -dbdir sql:$HOME/.pki/nssdb -add opensc -libfile $PKCS11
certutil -L -d sql:$HOME/.pki/nssdb -h all
```

When testing with a throwaway seed, point `-d` at a scratch database instead of
`$HOME/.pki/nssdb`; adding a root whose key anyone can derive to your real profile makes
every browser on the machine trust it.

- [x] A complete chain is shown, with no "unknown issuer". `certutil -O` prints
      `MTG PIV Root` above the 9A certificate, all four card certs list as `u,u,u`, and
      `certutil -V -u C` (9A, client auth) and `-u S` (9C, e-mail signing) both report
      `certificate is valid`

NSS is the crypto stack Firefox, Chrome and Thunderbird share, so its recognising the card
is the compatibility statement that matters. Step 12 of the suite automates the touch-free
half: it loads the OpenSC module into a scratch NSS database and asserts all four slot
certificates appear, each with a private key, under the trusted derived root. Two things
stay manual. `certutil -V` usage validation runs offline in `tests/piv.rs` instead, against
non-expiring certs -- this fixture's ten-year window is long past, so a real-time NSS
validation would fail on expiry, not trust. And on-card *decryption* through NSS's
`cmsutil` is not asserted. Its token login does work once you know the flag -- `cmsutil -f
<pinfile>`, not `-p` (which sets only the NSS database password) -- but the decrypt then
fails with `SEC_ERROR_INVALID_KEY`: NSS will not run the CMS ECDH on the 9D token key even
though the key advertises `CKA_DERIVE` and `pkcs11-tool` performs the identical
`CKM_ECDH1_DERIVE` against it. Unlike the OpenSSL path, this is **not** matched to a filed
upstream bug -- the nearest, [moz#1241446](https://bugzilla.mozilla.org/show_bug.cgi?id=1241446),
is about ECDSA *signature* verification with software keys, not ECDH on a token -- so it
wants a minimal reproduction and an NSS report before it can be cited. Either way the
card's ECDH is proven correct by steps 7 and 10. To reproduce by hand:
`cmsutil -E -d sql:DB -r "<Key Management nickname>" -i msg -o env` then
`cmsutil -D -d sql:DB -f pinfile -i env -o out`.

## Known caveats -- do not "fix" these

**`openssl verify -purpose smimeencrypt` fails for slot 9D, and that is correct.** OpenSSL's
`check_purpose_smime_encrypt` requires `keyEncipherment`, which RFC 8813 *forbids* on EC keys;
it is an RSA-era check that was never updated for ECDH. The certificate carries `keyAgreement`,
as it must. The meaningful check is `openssl cms -encrypt`, which succeeds and negotiates
`dhSinglePass-stdDH` + `aes256-wrap`. This is asserted by
`openssl_encrypts_to_key_management_cert` in `tests/piv.rs`, and was confirmed on hardware.

**`openssl cms -encrypt` defaults to a SHA-1 based ECDH KDF** (`dhSinglePass-stdDH-sha1kdf`).
That is an OpenSSL default, not something the certificate selects, and is unrelated to the
`ecdsa-with-SHA256` signatures on the chain itself. On hardware this negotiates exactly
`dhSinglePass-stdDH-sha1kdf-scheme` + `id-aes256-wrap` + `aes-256-cbc`.

**The management key is installed with require-touch**, so `piv check` needs a touch too. If
that turns out to be too awkward in practice, a `--no-touch-mgm` escape hatch is the intended
fix rather than dropping the touch requirement.

## If something fails

Everything up to step 1 is reproducible offline without a card, so start by confirming
`cargo test --test piv` is green with **0 ignored**. A mismatch reported by `piv check`
between the derived and on-card public key points at the derivation or the import path; a
mismatch in the certificate digest alone points at encoding or at the `--date` /
DN flags differing between the `upload` and `check` invocations -- all of them must be passed
identically, since the chain is regenerated from scratch each time.
