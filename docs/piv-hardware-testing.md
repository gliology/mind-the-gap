# PIV hardware test checklist

The PIV certificate chain is fully covered by `cargo test --test piv` *except* for everything
that needs a physical card. This document is the remaining manual checklist.

**Status: not yet executed.** The chain itself (structure, extensions, signatures, path
building, determinism) has been verified offline with OpenSSL. The card layer -- `piv upload`,
`piv check`, key import, per-slot policies and the `msroots` object -- compiles and is
unit-tested as far as is possible without hardware, but has never been run against a card.

> **`piv upload` is destructive.** It deliberately exhausts the PIN and PUK retry counters and
> then calls `reset_device`, wiping every key, certificate and object on the card. Use a spare
> YubiKey, not your daily driver.

## Prerequisites

A YubiKey 5 series (or any PIV token supporting AES-256 management keys and P-256 import), a
CCID reader, and a running `pcscd`.

All of the tooling is in the project's dev shell, so just:

```
nix develop
```

That provides `openssl`, `opensc` (`pkcs11-tool`, `pkcs15-tool`), `yubikey-manager` (`ykman`)
and `nss.tools` (`certutil`, `modutil`), alongside the `sq` and `gpg` the OpenPGP tests use.

Tests that shell out to an external tool are marked `#[ignore]` when that tool is absent, via
the probe in `build.rs`, so they are reported as ignored rather than quietly passing. Inside
the dev shell nothing should be ignored:

```
cargo test        # expect 0 ignored
```

If you see `N ignored`, a tool is missing and those checks did **not** run.

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

Expect two touch prompts during upload (management key authentication before and after the
key is replaced). Then:

- [ ] `cmp chain.pem uploaded.pem` -- upload and certify produce the same chain
- [ ] `mind-the-gap piv check` reports all four slots matching (this also needs a touch,
      because the management key is installed with require-touch)
- [ ] `mind-the-gap piv status` lists four keys with the expected subjects

## 2. Confirm what actually landed on the card

```
pkcs11-tool --module $PKCS11 -O
yubico-piv-tool -a status
```

- [ ] Four private keys and four certificates, all `EC` / `P-256`
- [ ] Per-slot policies match: 9A `PIN once / touch cached`, 9C `PIN always / touch always`,
      9D `PIN once / touch cached`, 9E `PIN never / touch never`
- [ ] Certificates read back byte-identical to the offline ones. Map ids by label from the
      `-O` listing rather than assuming (OpenSC conventionally uses 01=9A, 02=9C, 03=9D,
      04=9E, but confirm before relying on it):

```
for id in 01 02 03 04; do
  pkcs11-tool --module $PKCS11 -r --type cert --id $id -o card-$id.der
  openssl x509 -inform der -in card-$id.der -noout -subject -fingerprint -sha256
done
```

## 3. On-card signing

```
echo hello > msg.txt
pkcs11-tool --module $PKCS11 --login --id 01 --sign --mechanism ECDSA-SHA256 \
            -i msg.txt -o sig.bin
```

- [ ] 9A signs after a PIN and a touch
- [ ] 9C demands a *fresh* PIN and touch for every single signature (`PinPolicy::Always`)
- [ ] **9E signs with no `--login` at all** -- this is the NIST SP 800-73-4 requirement that
      motivated the per-slot policy table, and the one most likely to regress

## 4. msroots

```
yubico-piv-tool -a read-object --object 0x5fff11 \
  | openssl pkcs7 -inform der -print_certs -noout
```

- [ ] The root CA (and the issuing CA when `--intermediate` was used) is listed
- [ ] `mind-the-gap piv check` reports the msroots contents as matching

This is the only part of the upload path that is allowed to fail without aborting: a write
error is logged as a warning, since `msroots` is Windows-specific. Verify it actually
succeeded rather than trusting a clean exit.

## 5. End use

### SSH

```
ssh-keygen -D $PKCS11
ssh -I $PKCS11 user@host
```

- [ ] Four `ecdsa-sha2-nistp256` keys listed; the 9A key authenticates

### TLS client authentication

```
openssl s_server -accept 4433 -cert server.pem -key server.key \
                 -CAfile root.pem -Verify 2 -verify_return_error
```

- [ ] A browser with `$PKCS11` loaded as a security device completes the handshake using the
      9A certificate

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

- [ ] Signing and verification round-trip
- [ ] **Decryption on card succeeds** -- this is the real test of the `keyAgreement` decision
      (see the caveat below), and cannot be checked offline

### NSS / Thunderbird

```
certutil -A -n "MTG PIV Root" -t "CT,C,C" -d sql:$HOME/.pki/nssdb -i root.pem
modutil -dbdir sql:$HOME/.pki/nssdb -add opensc -libfile $PKCS11
certutil -L -d sql:$HOME/.pki/nssdb -h all
```

- [ ] A complete chain is shown, with no "unknown issuer"
- [ ] Thunderbird can send a signed and encrypted mail to yourself and read it back

## Known caveats -- do not "fix" these

**`openssl verify -purpose smimeencrypt` fails for slot 9D, and that is correct.** OpenSSL's
`check_purpose_smime_encrypt` requires `keyEncipherment`, which RFC 8813 *forbids* on EC keys;
it is an RSA-era check that was never updated for ECDH. The certificate carries `keyAgreement`,
as it must. The meaningful check is `openssl cms -encrypt`, which succeeds and negotiates
`dhSinglePass-stdDH` + `aes256-wrap`. This is asserted by
`openssl_encrypts_to_key_management_cert` in `tests/piv.rs`.

**`openssl cms -encrypt` defaults to a SHA-1 based ECDH KDF** (`dhSinglePass-stdDH-sha1kdf`).
That is an OpenSSL default, not something the certificate selects, and is unrelated to the
`ecdsa-with-SHA256` signatures on the chain itself.

**The management key is installed with require-touch**, so `piv check` needs a touch too. If
that turns out to be too awkward in practice, a `--no-touch-mgm` escape hatch is the intended
fix rather than dropping the touch requirement.

## If something fails

Everything up to step 1 is reproducible offline without a card, so start by confirming
`cargo test --test piv` is green with **0 ignored**. A mismatch reported by `piv check`
between the derived and on-card public key points at the derivation or the import path; a
mismatch in the certificate digest alone points at encoding or at the `--date` / `--card-id` /
DN flags differing between the `upload` and `check` invocations -- all of them must be passed
identically, since the chain is regenerated from scratch each time.
