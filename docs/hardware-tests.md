# Hardware tests


Both backends have an on-card test suite. They are **destructive** -- the PIV one resets the
PIV applet, the OpenPGP one factory-resets the OpenPGP applet -- so they are gated behind a
feature *and* behind naming the card:

Naming the card means *typing* its identifier, read off first -- substituting a
`$(ykman list --serials)` picks whatever token happens to be plugged in, which is exactly
the accident the requirement exists to prevent, and with two tokens attached it does not
even parse:

```
gpgconf --kill scdaemon        # scdaemon holds the card exclusively

ykman list                     # note the serial of the SPARE card
MTG_HARDWARE_TEST_SERIAL=12345678 \
  cargo test --features destructive-hardware-tests --test piv_hardware -- --nocapture

mind-the-gap pgp status        # note the card identifier of the SPARE card
MTG_HARDWARE_TEST_CARD=0006:12345678 \
  cargo test --features destructive-hardware-tests --test pgp_hardware -- --nocapture
```

Each applet is reset independently, so one token can carry both suites -- just not at the same
time, since they contend for the reader. The PIV suite needs three touches (`check`, the 9A
signature, the 9D key agreement); the OpenPGP suite one for every key it uses on the card
and through gpg, about four per algorithm, since `upload` leaves each key at the cached touch
policy (always, on a card without it, such as the YubiKey 4).

For a host that runs the suites unattended, `MTG_HARDWARE_TEST_TOUCH=never` provisions both
applets without touch policies (every PIV slot and the management key at never, every
OpenPGP key's touch off after `upload`) and asserts those instead. Such a run proves
everything except that a touch is actually demanded, so the default stays the run that
counts; a script cannot press a YubiKey, and what would close the gap is hardware that sees
the key blink and touches its sensor.

Other cards can stay attached, so a test host can keep several plugged in. Each suite derives
its test identity from the card it names, so no two cards ever hold the same keys, and it
points the outside tools at that card alone: OpenSC sees only its reader, and gpg is handed
its serial number. Suites on different cards can run at the same time. The one step that
cannot share is the OpenPGP suite's gpg step, whose scdaemon takes every reader: it waits
until no other suite is talking to a card, and they wait for it, through a lock file in
`$XDG_RUNTIME_DIR` that every suite takes. A desktop's own scdaemon is outside that lock, so
stop it first with `gpgconf --kill scdaemon`.

The second feature, `no-destructive-hardware-tests`, is a safety interlock that must never be
enabled by hand. The tests compile only when `destructive-hardware-tests` is on and it is off,
so `cargo test --all-features` -- which turns on both -- compiles them out rather than wiping
whatever card is plugged in.

See [the PIV hardware checklist](./piv-hardware-tests.md) for what they assert and for
the manual checklist covering what cannot be automated.

## The virtual OpenPGP check

`nix flake check` provisions a **virtual OpenPGP card** on every run: the `virtual-pgp`
check boots a VM, presents Nitrokey's [opcard](https://github.com/Nitrokey/opcard-rs) --
the Nitrokey 3's OpenPGP card implementation -- as a PC/SC reader through vsmartcard's
`vpcd`, and drives the real binary through `pgp upload`, `pgp check` and `pgp config`
against it. The whole PC/SC path runs with no hardware and no USB: pcscd, the reader
driver, the APDUs and a complete card state machine, which happens to be the same code a
Nitrokey 3 runs.

It has already earned its keep: the first run showed that `upload` set the *cached* touch
policy fatally, although cached is a Yubico extension to the UIF data object that a
spec-conforming card refuses -- every key had imported cleanly and the provisioning died
on a nicety. The policy is advisory now.

What the virtual card cannot cover is exactly what the manual checklist and the
destructive suites exist for: real readers and their quirks, a human finger, and the
vendor extensions above.

## The virtual PIV check

Since the fork of trussed's
[piv-authenticator](https://github.com/FlorianFranzen/piv-authenticator/tree/mind-the-gap)
grew the missing Yubico surface -- ECC import into every slot, a real `GET METADATA`,
partial-AID selection, retry-counter semantics -- the same construction works for PIV:
the `virtual-piv` check presents the app (the Nitrokey 3's PIV implementation) behind
`vpcd` and drives `piv upload` and `piv check` against it, twice, plus a wrong-subkey
check that must fail. That exercises the whole provisioning conversation the YubiKey
suite performs: reset by pin exhaustion, the derived AES-256 management key with its
touch requirement, the user pin, four imported P-256 keys with their pin and touch
policies read back through metadata, the byte-for-byte certificate comparison, and the
certificate authorities in msroots -- the check asserts that none of the advisory
comparisons warn. The check runs once per algorithm: `virtual-piv` provisions the P-256
chain, `virtual-piv-p384` the P-384 one, `virtual-piv-curve25519` the Ed25519 and X25519
one, and `virtual-piv-rsa2048` an RSA-2048 chain imported in the Yubico layout. Each then
runs the
card-level half of the destructive PIV suite (`tests/piv_hardware/`, built as the
`piv-suite` binary) against the same card: its own provisioning, the policy and
certificate read-back, msroots and the card identifiers, and then the card signing in
9A, 9C and 9E under their pin policies and agreeing (or, for RSA, decrypting) in 9D,
each result compared with the same computation off the card. That is what `piv check`
cannot prove on its own, since it only reads public keys back. The OpenPGP check likewise
provisions both curves and RSA at 2048 and 4096 bits: opcard imports P-256 and RSA on every
slot, and the 4096-bit import is the one too large for a single short APDU. It then runs
the OpenPGP hardware suite (`tests/pgp_hardware.rs`, built as `pgp-suite`) against the same
card on every algorithm, which is where each key is seen at work: the card signs,
authenticates and decrypts or agrees, each result checked against the certificate off the
card, and gpg signs and decrypts through it end to end. That is the test that found the
X25519 decryption key landing on cards byte-reversed. Touch prompts go through trussed's user-presence request (the same
mechanism opcard uses for UIF). The virtual card grants it unless the file named by
`VPICC_USER_PRESENCE` says `deny`; a real device blinks and waits for the button. The check runs against the fork's `mind-the-gap`
branch until the PRs are merged: trussed-dev's main plus every pending PR, each as one
commit, rebuilt by a generator rather than by hand. `nix flake update piv-authenticator`
follows it, and the flake input pin says exactly which revision the claims hold for.

One more variant provisions the [build server profile](piv-build-server.md) on the same
card: P-384 throughout, pin once and touch never on 9A, 9C and 9D, and management access
without a touch. `virtual-piv-builder` reads the result back through yubikit, slot policies
and management key metadata included, and `virtual-piv-builder-tdes` does the same with
the triple DES management key a YubiKey 4 needs forced onto the card. The virtual card is only ever the app as it is: other
firmware is tested on the real thing, and a YubiKey 4 on firmware 4.3.7 has gone through the
same provisioning and check, see [the build server chapter](piv-build-server.md#yubikey-4).

## The simulated Nitrokey 3 check

The `usbip-nk3` check goes one layer further down. It builds Nitrokey's own firmware as
its [USB/IP runner](https://github.com/Nitrokey/nitrokey-3-firmware/blob/main/docs/usbip.md),
a complete Nitrokey 3 as a host process, and attaches it to the VM's kernel through
`vhci-hcd`. pcscd then finds a USB key by hotplug and talks to it through libccid, so the
check covers what the `vpcd` checks skip: the USB descriptors, CCID framing, the
firmware's APDU dispatcher choosing between its applications, and the backend wiring of
the real app set. It provisions PIV and runs the card-level half of the PIV suite on every
algorithm, then provisions OpenPGP and runs the OpenPGP suite on a fresh key. The firmware's PIV app is replaced by the
piv-authenticator input, so the PIV code is the same as in `virtual-piv`; OpenPGP is the
opcard release the firmware ships. The firmware is the `mind-the-gap` branch of its fork:
upstream's main, which gives PIV its software pin backend without the SE050 chip
(Nitrokey/nitrokey-3-firmware#723), plus the P-384 mechanism for PIV, which the firmware
leaves out although the app advertises the curve. The USB/IP
device emulation underneath comes from the `mind-the-gap` branch of its fork, upstream plus
Sawchord/usbip-device#10: without it a reply could answer the wrong request, which made the
kernel drop the key mid-enumeration.

## The Gnuk check

`usbip-gnuk` provisions [Gnuk](https://salsa.debian.org/gnuk-team/gnuk/gnuk), the OpenPGP
token firmware of the Free Software Initiative of Japan, through its GNU/Linux emulation: the
firmware compiled for the host, serving itself over USB/IP and attached through `vhci-hcd`
like the simulated Nitrokey 3. Gnuk is written independently of opcard, in C on its own
scheduler, so it checks mind-the-gap against a second reading of the OpenPGP card
specification rather than the same code twice. The check provisions and checks through the
command line, then runs the OpenPGP checklist on Curve25519, gpg end to end included. Gnuk
2 dropped NIST P-256 and RSA, so for those two the check asserts that `upload` refuses the
card while it is intact.

Two settings differ from a stock Gnuk build. The emulation is built with the KDF data object
optional: Gnuk 2 by default refuses every key import until one is set, which mind-the-gap
does not do yet (see TODO.md). And the button is pressed by a wrapper half a second after
Gnuk asks: the emulation drops a press that arrives while it is still telling the host to
wait, which a person at a keyboard never manages but a script answering at once does.

## What the simulations cover

Every row runs in `nix flake check`. ✓ runs in a check · ○ possible, not run yet · — not
offered (P-384 is PIV only; the build server profile is P-384 and touch-free) · refused: the
card lacks the algorithm, and the check asserts `upload` turns it away before the reset

| Check | Card | P-256 | P-384 | Curve25519 | RSA-2048 | RSA-3072 | RSA-4096 | Touch refused |
|---|---|---|---|---|---|---|---|---|
| `virtual-piv`, `-p384`, `-curve25519`, `-rsa2048`, `-rsa3072`, `-rsa4096` | piv-authenticator over vpcd | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (P-256) |
| `virtual-piv-builder`, `-tdes` | piv-authenticator over vpcd, build server profile | — | ✓ | — | — | — | — | — |
| `virtual-pgp` | opcard over vpcd | ✓ | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| `usbip-nk3`, PIV | Nitrokey 3 firmware over USB/IP | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ○ |
| `usbip-nk3`, OpenPGP | Nitrokey 3 firmware over USB/IP | ✓ | — | ✓ | ✓ | ✓ | ✓ | ○ |
| `usbip-gnuk` | Gnuk emulation over USB/IP | refused | — | ✓ | refused | refused | refused | ○ |

The PIV rows run the card-level half of the destructive PIV suite against the card (the
PKCS#11 end use needs a real token and OpenSC's driver); the OpenPGP rows run the whole
OpenPGP suite, three RSA sizes included.

Touch is checked both ways on the vpcd cards: `virtual-piv` (P-256) and `virtual-pgp` end
with `touch_is_enforced`, which refuses every touch through the cards' `VPICC_USER_PRESENCE`
file and asserts that what the policies gate is refused (PIV 9A, 9C and 9D and the management
key; every OpenPGP key) while 9E, which needs no touch, still signs, then grants touches
again and asserts it all works. A refused touch waits out the card's 15 second timeout, as
on a token nobody touches, which adds about a minute to each check. Real hardware cannot be
told to refuse, so the test runs only where `MTG_TEST_USER_PRESENCE_FILE` names that file. The simulated Nitrokey 3 carries the same two apps
as the vpcd checks behind the firmware's own dispatcher, backends and USB stack, and it runs
both suites on every algorithm. Its flash is kept in RAM and too small for PIV's four RSA-4096
keys and OpenPGP's three at once, so the check restarts the key between the two.

## What is not emulated, and why

[canokey-qemu](https://github.com/canokeys/canokey-qemu), a QEMU USB device implementing
PIV and OpenPGP, would add an independent PIV implementation, which Gnuk does not offer,
behind the same kind of USB transport the two USB/IP checks already cover. A Java Card
simulator (jCardSim + PivApplet) stays off the list: protocol gaps, plus a Java
toolchain in the closure.

