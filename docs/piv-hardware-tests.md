# PIV diagnostic checklist

The PIV certificate chain is fully covered by `cargo test --test piv` *except* for everything
that needs a physical card. This checklist is that remainder, as a blank procedure for a walk
by hand: its boxes are for whoever walks it, and none is ticked here. Testing a card is the
destructive PIV suite's job, `tests/piv_hardware/`, which runs sections 1 to 5 as its twelve
numbered steps in every official run on a real card ([test results](test-results.md),
[hardware tests](hardware-tests.md)). The manual walk is kept because it is what the suite was
derived from, and because it is still how you diagnose a failure. Nothing on it needs GUI
software: the TLS handshake and the S/MIME round trip that a browser or mail client would
perform run headless in the suite, and NSS chain validation runs offline in `cargo test`.

Reference rig the checklist was first walked on:

| | |
|---|---|
| Token | YubiKey 5C NFC, firmware 5.4.3 |
| Tooling | OpenSC 0.27.1, OpenSSL 3.6.2 with libp11 0.4.13, ykman 5.8.0, NSS 3.112.5 |
| Inputs | `-d 2026-01-01 --validity 10y`, pin `123456`, no `--intermediate` (two-tier chain) |
| Seed | the public BIP-39 test mnemonic `abandon … art` |

The OpenSSL steps have since moved from libp11 to pkcs11-provider, the provider the dev shell
ships and the suite drives. The last manual walk, on that YubiKey 5C NFC (firmware 5.4.3),
passed every item the checklist then had; its on-card decryption item has since become the
key agreement item of section 5, for the reason given there.

> Use a **throwaway seed** for this checklist: the card it leaves behind holds test keys and
> its root authority is derivable by anyone. Never install that root as a trust anchor, add its
> 9A key to an `authorized_keys`, or leave the card in service. `init` and `upload` with a real
> seed provision a card for actual use.

> **`init` is destructive.** It deliberately exhausts the pin and puk retry counters and then
> resets the applet, wiping every key, certificate and object on it. Use a spare YubiKey, not
> your daily driver.

## What the suite automates

The plain run of the PIV suite, `provision_and_verify_card`, walks the sections below in order
as twelve numbered steps, and asserts a few things the checklist could only eyeball:

| | |
|---|---|
| Section 1 | `upload` and `publish` produce the same chain; `check` agrees with the card |
| Section 2 | every slot's pin and touch policy, and each certificate byte for byte |
| Section 3 | 9E signs with no pin; 9C *refuses* without one; 9A and 9C sign and verify |
| Section 4 | `msroots` holds exactly the derived authorities |
| Section 5 | steps 8 to 12: TLS over 9A, S/MIME signing over 9C, 9D key agreement through PKCS#11, SSH with 9A, NSS recognising the card |
| extra | 9D performs ECDH on the card and agrees with the same computation done off it |

Two of those are assertions the tool itself will not make: `check` downgrades a policy or
`msroots` mismatch to a warning, so neither fails the command. The suite asserts both. The
policy table is also spelled out in the test rather than read back from the implementation, so
that changing the implementation's table fails the test instead of silently agreeing with
itself.

## Prerequisites

A YubiKey 5 series (or any PIV token supporting AES-256 management keys and P-256 import), a
CCID reader, and a running `pcscd` (a socket-activated `pcscd.socket` is enough). The checklist
is P-256; the suite's runs of the other algorithms, and the cards each needs, are in [running
a suite directly](hardware-tests.md#running-a-suite-directly). All of the tooling is in the
project's dev shell:

```
nix develop
```

That provides `openssl` with pkcs11-provider, `opensc` (`pkcs11-tool`, `pkcs15-tool`,
`opensc-tool`), `yubikey-manager` (`ykman`) and `nss.tools` (`certutil`, `modutil`), alongside
the `sq` and `gpg` the OpenPGP tests use. Throughout, `$PKCS11_MODULE` is the
`opensc-pkcs11.so` and `$OPENSSL_PKCS11_PROVIDER` the provider the dev shell exports.

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

- [ ] `cargo test` green with 0 ignored

Stop gpg's scdaemon before touching the card (`gpgconf --kill scdaemon`): it holds every reader
exclusively, and every PIV access then fails with ["other connections
outstanding"](troubleshooting.md#the-smart-card-cannot-be-accessed-because-of-other-connections-outstanding).

## 1. Provision the card

```
export MIND_THE_SEED="<24 words>"
export MIND_THE_NAME="Your Name"
export MIND_THE_EMAILS="you@example.com"

# Offline first: this must succeed before any card is touched
mind-the-gap publish --app piv -d 2026-01-01 --validity 10y --to chain.pem
mind-the-gap publish --app piv -d 2026-01-01 --part identity --to root.pem

# DESTRUCTIVE: resets the card
mind-the-gap init --app piv --pin <6-8 digit pin>
mind-the-gap upload --app piv -d 2026-01-01 --validity 10y
```

`init` first opens the card and refuses one that cannot hold what is asked of it (a YubiKey by
its firmware version, another card by the algorithms its SELECT response lists, where it lists
any), then asks for confirmation on the terminal, naming the card it is about to wipe. `upload`
lists what it is about to write and asks again. Pass `-y` / `--yes` to skip the questions when
scripting; without a terminal and without `--yes` they abort rather than hang.

Expect **no** touch prompt during `init`: the derived management key is installed without the
touch requirement, and the requirement is only switched on at the very end, while the session
is still authenticated. `upload` authenticates with the management key, so it asks for the first
touch.

- [ ] `mind-the-gap check --app piv -d 2026-01-01 --validity 10y` reports the card
      initialized by this card seed and every slot matching
- [ ] `mind-the-gap list` lists the three keys with the expected subjects, marked as this key
      seed's, and the 9E certificate
- [ ] the slot certificates on the card are the ones in `chain.pem` (see section 2)

`list` also shows the Yubico attestation certificate.

## 2. Confirm what actually landed on the card

```
pkcs11-tool --module $PKCS11_MODULE -O --login --pin <pin>
ykman piv info
for s in 9a 9c 9d 9e; do ykman piv keys info $s; done
```

- [ ] Four private keys and four certificates, all `EC` / `P-256`
- [ ] 9A, 9C and 9D issued by the root authority, 9E self-signed
- [ ] Per-slot policies match the default `relaxed` policy (see [pin and touch
      policies](policies.md)): 9A `PIN once / touch cached`, 9C `PIN always / touch always`,
      9D `PIN once / touch cached`, 9E `PIN never / touch never`
- [ ] `ykman piv info` shows `Management key algorithm: AES256` (a freshly reset card reports
      `TDES`, so this confirms the key was replaced)
- [ ] Certificates read back byte-identical to the offline ones. Map ids by label from the
      `-O` listing rather than assuming. The conventional OpenSC mapping 01=9A, 02=9C, 03=9D,
      04=9E was confirmed on the tested card, but keep checking it:

```
for id in 01 02 03 04; do
  pkcs11-tool --module $PKCS11_MODULE -r --type cert --id $id -o card-$id.der
  openssl x509 -inform der -in card-$id.der -noout -subject -fingerprint -sha256
done
```

Two observations that are expected, not faults:

- `PUK tries remaining: 3/3`, and no default puk warning: `init` replaces the factory puk with
  the one the card seed derives for this card, which `pin --reset` uses to set a forgotten pin.
- `WARNING: Using default PIN!` appears only when no pin was given to `init`, which keeps the
  PIV default `123456`.

## 3. On-card signing

```
echo hello > msg.txt
pkcs11-tool --module $PKCS11_MODULE --login --pin <pin> --id 01 --sign \
            --mechanism ECDSA-SHA256 -i msg.txt -o sig.bin
```

`pkcs11-tool` emits a raw `r||s` pair; wrap it in DER before checking it with
`openssl dgst -verify` against the matching slot certificate.

- [ ] 9A signs after a pin and a touch, and the signature verifies against the 9A certificate
- [ ] 9C demands a *fresh* pin and touch for every single signature (`PinPolicy::Always`),
      positively (two signatures, two touches, both verifying) **and** negatively: a third
      attempt with no touch fails after exactly the YubiKey's 15 second touch timeout, which
      proves the policy is enforced rather than merely recorded in the slot metadata
- [ ] **9E signs with no pin at all**: the NIST SP 800-73-4 requirement that motivated the
      per-slot policy table, and the one most likely to regress

> **Note.** The 9E check cannot be made with `pkcs11-tool`. OpenSC's PIV
> emulation advertises a *token-level* `login required` flag, so `pkcs11-tool` performs a
> `C_Login` for any private-key operation whether or not `--login` is passed: it prompts for
> a pin and, given none, aborts. That exercises OpenSC's policy, not the card's. Test the
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

The object is wrapped in a `0x82` TLV, so strip the header before OpenSSL will parse it; for
a 490-byte object that is the first 4 bytes:

```
python3 -c "
d=open('msroots.der','rb').read(); assert d[0]==0x82
n=d[1]&0x7f; ln=int.from_bytes(d[2:2+n],'big'); i=2+n
open('msroots-inner.der','wb').write(d[i:i+ln])"
openssl pkcs7 -inform der -in msroots-inner.der -print_certs -noout
```

- [ ] The root authority (and the issuing authority when `--intermediate` was used) is
      listed, with a SHA-256 fingerprint equal to the offline `root.pem`
- [ ] `mind-the-gap check --app piv` reports the msroots contents as matching

This is the only part of the upload path that is allowed to fail without aborting: a write
error is logged as a warning, since `msroots` is Windows-specific. Verify it actually
succeeded rather than trusting a clean exit.

## 5. End use

Walk the PIV half of [after the gap](after-the-gap.md#the-piv-keys-through-pkcs11) with the
throwaway chain: `root.pem` from section 1, and the slot certificates of `chain.pem` as
`9a.pem`, `9c.pem` and `9d.pem`, one file each. Point NSS at a scratch database rather than
`$HOME/.pki/nssdb`: adding a root whose key anyone can derive to your real profile makes every
browser on the machine trust it.

- [ ] **SSH:** `ssh-keygen -D` lists four `ecdsa-sha2-nistp256` keys, and the 9A key logs in
      to an sshd authorised for it alone, the touch blinking during the challenge signature
      (suite step 11)
- [ ] **TLS:** a TLS 1.3 handshake completes with the 9A certificate under `-Verify 2
      -verify_return_error`, the server logging `depth=1` (the root authority), then
      `depth=0` (the 9A leaf) and `1 server accepts that finished` (suite step 8)
- [ ] **S/MIME:** signing with 9C and verification round-trip, with `ecdsa-with-SHA256` on the
      signerInfo (suite step 9)
- [ ] **Key agreement:** the PKCS#11 `CKM_ECDH1_DERIVE` with 9D (`pkcs11-tool --derive`, given a
      peer's public key) agrees with the same ECDH computed off the card, which is the real test
      of the `keyAgreement` decision and cannot be checked offline (suite step 10); decryption
      on the card through OpenSSL or NSS is blocked upstream, as after the gap explains for
      [OpenSSL](after-the-gap.md#openssl) and [NSS](after-the-gap.md#nss-firefox-chrome-and-thunderbird)
- [ ] **NSS:** a complete chain, with no "unknown issuer": `certutil -O` prints the root above
      the 9A certificate, all four card certificates list as `u,u,u`, and `certutil -V -u C`
      (9A, client auth) and `-u S` (9C, e-mail signing) both report `certificate is valid`

The suite's step 12 automates the touch-free half of the NSS item: it loads the OpenSC module
into a scratch NSS database and asserts all four slot certificates appear, each with a private
key, under the trusted derived root. It leaves out `certutil -V`, since its fixture certificates
are dated at the epoch and long expired in real time; `tests/piv/external.rs` validates the
usages offline instead, against certificates that do not expire.

## Known caveats, not to be "fixed"

**`openssl verify -purpose smimeencrypt` fails for slot 9D, and that is correct.** OpenSSL's
`check_purpose_smime_encrypt` requires `keyEncipherment`, which RFC 8813 *forbids* on EC keys;
it is an RSA-era check that was never updated for ECDH. The certificate carries `keyAgreement`,
as it must. The meaningful check is `openssl cms -encrypt`, which succeeds and negotiates
`dhSinglePass-stdDH` + `aes256-wrap`. This is asserted by
`openssl_encrypts_to_key_management_cert` in `tests/piv/external.rs`, and was confirmed on
hardware.

**`openssl cms -encrypt` defaults to a SHA-1 based ECDH KDF** (`dhSinglePass-stdDH-sha1kdf`).
That is an OpenSSL default, not something the certificate selects, and is unrelated to the
`ecdsa-with-SHA256` signatures on the chain itself. On hardware this negotiates exactly
`dhSinglePass-stdDH-sha1kdf-scheme` + `id-aes256-wrap` + `aes-256-cbc`.

**Management access asks for a touch whenever the policy asks for one at all**, so `check`
and `upload` need a touch too under the default; the modes without touch (`never-touch`,
`once-pin` and the like) leave it without ([policies](policies.md)).

## If something fails

Everything up to section 1 is reproducible offline without a card, so start by confirming
`cargo test --test piv` is green with **0 ignored**. Then read what `check` reports: [what
`check` reports](troubleshooting.md#what-check-reports) says where each mismatch points, and
the rest of [troubleshooting](troubleshooting.md) explains the messages the tool and the card
stack give. With the seeds and the options right, a public key that still differs points at
the derivation or the import path, and a certificate digest at its encoding.
