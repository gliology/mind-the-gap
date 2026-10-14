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
signature, the 9D key agreement); the OpenPGP suite needs none.

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
destructive suites exist for: real readers and their quirks, touch prompts, and the
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
mechanism opcard uses for UIF), which the virtual platform grants automatically; a real
device blinks and waits for the button. The check runs against the fork's `mind-the-gap`
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
the real app set. It provisions PIV on P-256, runs the card-level half of the PIV suite,
and provisions OpenPGP on the same key. The firmware's PIV app is replaced by the
piv-authenticator input, so the PIV code is the same as in `virtual-piv`; OpenPGP is the
opcard release the firmware ships. The firmware is upstream's main, which gives PIV its
software pin backend without the SE050 chip (Nitrokey/nitrokey-3-firmware#723). The USB/IP
device emulation underneath comes from the `mind-the-gap` branch of its fork, upstream plus
Sawchord/usbip-device#10: without it a reply could answer the wrong request, which made the
kernel drop the key mid-enumeration.

## What is not emulated, and why

[canokey-qemu](https://github.com/canokeys/canokey-qemu), a QEMU USB device implementing
PIV and OpenPGP, remains the alternative that would also cover the USB transport. A Java
Card simulator (jCardSim + PivApplet) stays off the list: protocol gaps, plus a Java
toolchain in the closure.

**Gnuk** remains open as a second OpenPGP target. Its emulation build
(`--target=GNU_LINUX`) speaks USB/IP rather than PC/SC, so running it means loading the
`vhci-hcd` kernel module and attaching the emulated device inside the test VM -- and the
nixpkgs `gnuk` package currently builds only the STM32 firmware (and is marked broken).
Packaging the emulation target plus the USB/IP plumbing is tracked in TODO.md; it would
buy coverage of the *transport* (a USB CCID device instead of a virtual reader), which is
the part opcard bypasses.
