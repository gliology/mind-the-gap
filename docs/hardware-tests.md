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

## The virtual card check

`nix flake check` provisions a **virtual OpenPGP card** on every run: the `virtual-card`
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

### A missed touch reads as a bad PIN

The OpenPGP card specification (3.4.1, §4.4.3.6) answers an operation whose touch never
came with status `6600`, which GnuPG reports as a timeout. opcard 1.11.0, the Nitrokey 3's
implementation, answers it with `6982`, security status not satisfied, after about 15
seconds (`src/command/pso.rs`, which carries a FIXME saying so, and the timeout in
`src/backend.rs`). GnuPG maps `6982` to `Bad PIN`. A missed touch on a Nitrokey 3
therefore looks like a wrong PIN, which a user or a script must not answer by trying the
PIN again.

The two are told apart by time and by the log, not by the message:

| scdaemon's log | after the request | meaning |
| --- | --- | --- |
| `verify CHV2 failed: Bad PIN` | at once | a wrong PIN, and a try is spent |
| `app_auth failed: Bad PIN` alone | about 15 s | the touch didn't come |
| `app_auth failed: Bad PIN` alone | at once | the card lost its verified PIN, for example after a reset; the next attempt sends a real VERIFY |

Only the first one costs a try. In the other two nothing was spent, and the user simply
touches or re-enters the PIN next time.

## The virtual PIV check

Since the fork of trussed's
[piv-authenticator](https://github.com/FlorianFranzen/piv-authenticator/tree/ecc-import)
grew the missing Yubico surface -- ECC import into every slot, a real `GET METADATA`,
partial-AID selection, retry-counter semantics -- the same construction works for PIV:
the `virtual-piv` check presents the app (the Nitrokey 3's PIV implementation) behind
`vpcd` and drives `piv upload` and `piv check` against it, twice, plus a wrong-subkey
check that must fail. That exercises the whole provisioning conversation the YubiKey
suite performs: reset by pin exhaustion, the derived AES-256 management key with its
touch requirement, the user pin, four imported P-256 keys with their pin and touch
policies read back through metadata, the byte-for-byte certificate comparison, and the
certificate authorities in msroots -- the check asserts that none of the advisory
comparisons warn. Touch prompts go through trussed's user-presence request (the same
mechanism opcard uses for UIF), which the virtual platform grants automatically; a real
device blinks and waits for the button. The check runs against our fork until the
branch is upstreamed; the flake input pin says exactly which revision the claims hold
for.

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
