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

## Why there is no emulated card

The obvious way to get the card layer under CI is to emulate a card. It does not work out,
and the reason is worth recording so nobody tries twice.

`vsmartcard-vpcd` is packaged in nixpkgs and does half the job: it installs a PC/SC driver that
presents a virtual reader, and ships `vicc` to drive it. But `vicc` emulates
`iso7816`, `cryptoflex`, `ePass`, `nPA`, `relay` and `handler_test` — **no PIV and no
OpenPGP**. It supplies the transport and no applet that speaks either protocol. `relay` merely
forwards a real card, which is no help without one.

Filling that gap means a Java Card simulator such as jCardSim running an applet such as
PivApplet or SmartPGP. Neither is packaged, and both drag a Java toolchain and a CAP-file build
into the closure.

Even then it would not buy much on the PIV side, because what the suite checks is mostly
**Yubico extensions that no generic PIV applet implements**:

- `GET METADATA`, which `piv check` and the tests use to read back keys and policies
- an AES-256 management key, where standard PIV has 3DES
- per-slot PIN and touch policies set during key import
- the `msroots` object

An emulated card would fail on those long before reaching anything the tests care about. Put
the other way: everything an emulator could faithfully reproduce is the deterministic
certificate generation, which is already covered offline by `cargo test` without any card at
all.

OpenPGP is the more tractable half. `tests/pgp_hardware.rs` uses only standard OpenPGP card
operations — factory reset, PIN changes, key import, fingerprints, cardholder name — so a
SmartPGP or Gnuk emulator behind `vpcd` could plausibly run it unmodified. That remains open,
and would need the applet packaged first.

In the meantime the NixOS test does the part that needs no card: it derives an OpenPGP
certificate and a PIV chain inside the live image and checks the results, so the thing the
air-gapped image exists to do is exercised on every build.
