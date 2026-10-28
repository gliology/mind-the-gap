# Supported cards

Which card takes which algorithm, as far as it has been tried. The backends speak the standard
OpenPGP card and PIV protocols, so a card missing here may well work; the grids say what has
been verified against the device.

✓ tested on the device · ○ the device should take it, not run yet · ✗ the device cannot

**PIV**

| Token | P-256 | P-384 | Curve25519 | RSA-2048 | RSA-3072 | RSA-4096 |
|---|---|---|---|---|---|---|
| YubiKey 5, firmware 5.7 | ✓ in production | ○ | ✓ | ✓ | ✓ | ✓ |
| YubiKey 5, firmware 5.4 | ✓ in production | ○ | ✗ needs 5.7 | ○ | ✗ needs 5.7 | ✗ needs 5.7 |
| YubiKey 4, firmware 4.3 | ✓ | ✓ | ✗ | ✓ | ✗ | ✗ |
| Nitrokey 3, shipped firmware | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Solo 2, on the LPC55S69 dev kit | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

**OpenPGP** (P-384 is PIV only)

| Token | Curve25519 | P-256 | RSA-2048 | RSA-3072 | RSA-4096 |
|---|---|---|---|---|---|
| YubiKey 5, firmware 5.4 and 5.7 | ✓ in production | ✓ | ✓ | ✓ | ✓ |
| YubiKey 4, firmware 4.3 | ✗ | ✗ | ✓ | ✓ | ✓ |
| Nitrokey 3 | ✓ in production | ✓ in production | ○ | ○ | ○ |
| Solo 2, on the LPC55S69 dev kit | ✓ | ✓ | ✓ | ✓ | ✓ |
| Gnuk 2, emulated | ✓ | ✗ | ✗ | ✗ | ✗ |

"In production" means real cards provisioned from real seeds and used daily, not just a test
run. The official runs behind the grids, test by test with the firmware and the date, are in
[test results](test-results.md); where a card has no official run under the 1.0 commands yet,
the grid still holds what earlier runs found.

## What the grids leave out

- **YubiKey 5:** the full [PIV diagnostic checklist](piv-hardware-tests.md), PKCS#11 end use
  included, runs on P-256; the other algorithms run its card-level half. The OpenPGP suite
  signs, authenticates and decrypts on the card and has gpg use the keys end to end.
- **YubiKey 4:** also runs the [unattended host profile](unattended-host.md#yubikey-4): it
  took the derived 3DES management key, passed `check` with every slot key proven by a
  signature challenge (the card has no GET METADATA), and served unattended as a build server
  identity through OpenSC.
- **Nitrokey 3:** its shipped PIV applet lacks the ECC import, GET METADATA, RID selection and
  Curve25519 support that our pending [piv-authenticator
  PRs](https://github.com/trussed-dev/piv-authenticator/pulls) add. With them, the same applet
  runs every PIV algorithm in CI, as do the OpenPGP applet and a whole simulated Nitrokey 3
  (see [test results](test-results.md#simulated-cards)).
- **Solo 2:** the dev kit runs the same PIV and OpenPGP applets as CI, over real CCID, with
  the P-256 checklist and the card-level suites passed. With RSA and P-384 both applets fit in
  one image only without FIDO, which is what the dev kit ran. RSA-3072 and RSA-4096 PIV keys
  need a build whose volatile store holds an unsealed RSA key, which stock Solo 2 firmware
  does not have. A production Solo 2 is untested.
- **Gnuk:** the row is its GNU/Linux emulation in CI, built as a stock Gnuk 2, whose KDF data
  object `init` sets up. Gnuk has no PIV applet, Gnuk 2 holds Curve25519 only of what
  mind-the-gap derives, and `init` refuses the others before the reset.

## Choosing an algorithm per applet

`--algorithm` applies to both applets: OpenPGP derives on Curve25519 by default and on NIST
P-256 on request, PIV the other way round, PIV alone also takes NIST P-384, and either derives
RSA keys of 2048, 3072 or 4096 bits on request; the [derivation
chapter](derivation.md#the-algorithm-segment) says what each derives. With no algorithm set,
each applet takes its own default, P-256 for PIV and Curve25519 for OpenPGP. The YubiKey 5 and
the Solo 2 dev kit hold both; the YubiKey 4 holds the PIV default but not the OpenPGP one; the
Nitrokey 3 and Gnuk hold the OpenPGP default, and their PIV is out either way, the Nitrokey 3's
shipped PIV applet taking none of these keys and Gnuk having no PIV applet. A config file can
choose each applet's apart, `[pgp] algorithm = "rsa2048"` for a YubiKey 4 (see
[options](configuration.md#each-applets-own-defaults)). Every applet judges an algorithm
against what the card says it holds before anything on it changes, so a choice the card says
it cannot hold is refused with the card untouched; what a card says can overstate its build,
though, as the next section tells.

What the YubiKeys take, by firmware: every YubiKey 5 takes both curves and RSA up to 4096 bits
for OpenPGP, and P-256, P-384 and RSA-2048 for PIV; firmware 5.7 adds Ed25519, X25519,
RSA-3072 and RSA-4096 PIV keys. A YubiKey 4 takes P-256, P-384 and RSA-2048 for PIV and only
RSA for OpenPGP. P-384 exists for PIV consumers that insist on it, such as a binary cache
signing key (see [unattended hosts](unattended-host.md)).

## Cards that list more than their build holds

A YubiKey is judged by its firmware version. Any other PIV card is judged by the algorithms
its SELECT response lists, and an OpenPGP card by its algorithm information (data object FA),
or by its key attributes where it has none. Both lists can name algorithms the build lacks:

- piv-authenticator, the PIV applet of the Nitrokey 3 and the Solo 2, lists a fixed set of
  algorithms whatever its build carries. Its release 0.7.0, which the Nitrokey 3 firmware
  depends on, lists triple DES, AES-256, P-256, P-384 and RSA of every size, so a Solo 2 image
  built without its `rsa` or `p384` feature lists those all the same. It does not list
  Curve25519, which is therefore refused with the card untouched. On a Nitrokey 3 with the
  shipped applet the list passes P-256 and P-384 as well, although that applet lacks the ECC
  import (see above).
- opcard lists RSA in its algorithm information in a build without an RSA backend.

On such a build, PIV `init` with an algorithm the build lacks passes the check and resets the
card. It installs the card seed's management key and puk, the pin where one was given, the
CHUID and the CCC, and then fails importing 9E, its one key. The card is then this card seed's
with 9E empty: `init` again with an algorithm the build holds puts it right, and `wipe` resets
it. OpenPGP `init` imports no key, so it is not affected; `upload` is, and resets nothing: it
stops at the first key the card refuses (status 6A81, function not supported), with the keys
written before it on the card, and `upload` with an algorithm the build holds replaces them.
The refused import is the tell, right after a check that passed; the build's features say
which algorithms it holds.
