# Hardware tests

Both applets have an on-card test suite: `tests/piv_hardware/` for PIV, which automates the
[PIV diagnostic checklist](piv-hardware-tests.md), and `tests/pgp_hardware/` for OpenPGP.
They are **destructive** (the PIV one resets the PIV applet, the OpenPGP one factory-resets the
OpenPGP applet), so they are gated behind a feature *and* behind naming the card. The runs
that count are made through the harness, which knows what each card is expected to do and
records what it did; `nix flake check` runs the same suites against [simulated
cards](#simulated-cards) on every change.

## Official runs

```
nix run .#hardware-tests -- --card yubikey-5.7 --suite touch-free
nix run .#hardware-tests -- --card yubikey-5.7 --suite attended     # touch the card when it blinks
nix run .#hardware-tests -- --card yubikey-5.7 --suite touch-free --applet pgp
nix run .#hardware-tests -- --simulated
nix run .#hardware-tests -- --render
```

A card is named as `harness/expected.toml` names it, which says for every test what the card
should do: pass, be refused before anything is written (a YubiKey 4 and Curve25519), or not
be run, with the reason. Its serial comes from `.env` at the repository root, which git
ignores, one card a line:

```
# Spare cards the hardware harness may reset, never one in daily use
yubikey-5.7=34392895
yubikey-5.4=20381784
yubikey-4=6445117
lpc55s69-evk=1336719253
```

`--card` finds the card with that PIV serial without disturbing the others, reads its firmware
and its OpenPGP identifier, refuses a card whose firmware is not the one expected, stops gpg's
scdaemon, and runs the suites the flake builds, the PIV one with the tools of its end-use
steps. `touch-free` provisions without touch policies; `attended` keeps them and needs a
person at the card. Every test's outcome is compared with what was expected, either way: a
failure where a pass was expected, and a pass where a refusal was, so the expectations are
changed on purpose and never drift.

`--simulated` builds the checks of the [simulated cards](#simulated-cards) and records, for
each, the revisions of the sources it is built from: the flake's inputs as `flake.lock` pins
them and the nixpkgs packages at the pinned nixpkgs.

Each run writes `harness/results/`, one file per card, suite and applet and one for the
simulated cards, with the card's name and firmware, never its serial, the date and the commit
it ran from. Committing a result makes it the official run. `--render` turns the results into
the [test results](test-results.md) chapter and the tables of the current release in the
[release notes](releases.md), and `nix flake check` fails while those are out of date with the
results.

## Running a suite directly

For a single test while working on it, the suites run directly. Naming the card means
*typing* its identifier, read off first. Substituting a `$(ykman list --serials)` picks
whatever token happens to be plugged in, which is exactly the accident the requirement exists
to prevent, and with two tokens attached it does not even parse:

```
gpgconf --kill scdaemon        # scdaemon holds the card exclusively

ykman list                     # note the serial of the SPARE card
MTG_HARDWARE_TEST_SERIAL=12345678 \
  cargo test --features destructive-hardware-tests --test piv_hardware -- --nocapture

mind-the-gap list              # note the OpenPGP identifier of the SPARE card
MTG_HARDWARE_TEST_CARD=0006:12345678 \
  cargo test --features destructive-hardware-tests --test pgp_hardware -- --nocapture
```

Without the variable a suite fails immediately and touches nothing: the feature says "run
destructive tests", the variable says "against *that* card", and neither alone is enough to
reset a token. Each applet is reset independently, so one token can carry both suites,
though not at the same time, since they contend for the reader.

The plain PIV run is `provision_and_verify_card`: the P-256 checklist, end use included. The
other tests are `#[ignore]`, each with a reason naming the card it needs; pick the ones the
card can take with `--include-ignored --exact <names>`. The RSA-2048 PIV run
(`provision_and_verify_rsa2048_card`) works on any YubiKey 5; Curve25519 PIV keys need a token
that imports Ed25519 and X25519 keys, YubiKey firmware 5.7 or the patched trussed PIV app;
RSA-3072 and RSA-4096 PIV keys need firmware 5.7 as well. `touch_is_enforced` needs a virtual
card and fails on a real one.

`--nocapture` is what makes the touch prompts visible; without it they are buffered until the
test ends. The attended PIV run asks for a touch at `upload` and `check` (management access),
at the signatures and the key agreement on the card, and at the end-use steps (the TLS
handshake, the S/MIME signature, the PKCS#11 key agreement and the SSH login); watch the
token rather than the terminal. Each prompt blocks until you press the button, and the token's
own timeout is about fifteen seconds, so a prompt missed is a step failed. `init` needs none:
it installs the management key touch-free and arms the requirement only once the card holds
what the card seed derives. The OpenPGP suite asks for one touch for every key it uses on the
card and through gpg, about four per algorithm, since the default policy leaves each key at
the cached touch (always, on a card without it, such as the YubiKey 4).

Variables that shape a run:

- `MTG_HARDWARE_TEST_TOUCH=never` provisions both applets without touch policies (every PIV
  slot and the management key at never, every OpenPGP key's touch off after `upload`) and
  asserts those instead, so nobody has to press the key; the harness's `touch-free` suite is
  this. Such a run proves everything except that a touch is actually demanded, so the
  attended run is the one that counts; a script cannot press a YubiKey, and what would close
  the gap is hardware that sees the key blink and touches its sensor.
- `MTG_HARDWARE_TEST_KDF=on` has the OpenPGP suite's `init` set up the KDF data object on a
  card that offers it, such as a YubiKey 5, so that every pin the suite and gpg enter goes to
  the card hashed; `off` keeps it off on a Gnuk, which then refuses the key import.
- `MTG_HARDWARE_TEST_MSROOTS=off` and `MTG_HARDWARE_TEST_MANAGEMENT_ALGORITHM=tdes` (or
  `aes256`) are for a PIV card that reports a YubiKey's firmware without everything that
  firmware has, such as CanoKey. The first provisions without msroots, as `--no-msroots` does,
  and asserts that the card holds none; the second has `init` install that management key and
  the suite expect it, where unset it expects AES-256 from firmware 5.4 on.

### Several cards attached

Other cards can stay attached, so a test host can keep several plugged in. Each suite derives
its test identity from the card it names, so no two cards ever hold the same keys, and it
points the outside tools at that card alone: OpenSC sees only its reader, and gpg is handed
its serial number. Suites on different cards can run at the same time, through a lock file in
`$XDG_RUNTIME_DIR` that every suite takes. Two steps touch other cards and take it
exclusively, so they wait until no other suite is talking to a card and the others wait for
them: finding the card at the start, which asks every attached card who it is, after which a
suite addresses its card by reader alone; and the OpenPGP suite's gpg step, whose scdaemon
takes every reader. A desktop's own scdaemon is outside that lock, so stop it first. The
`virtual-parallel` check runs the PIV and the OpenPGP card-level suites side by side on two
virtual cards in one machine, so a step that disturbs another card fails there.

### The two feature flags

```toml
destructive-hardware-tests = []      # opt in
no-destructive-hardware-tests = []   # safety interlock, never enable by hand
```

The suites compile only when the first is on and the second is off. The second exists because
`--all-features` turns on *every* feature, so without it a routine `cargo test
--all-features`, in CI or from a habit, would silently wipe whatever card happened to be
plugged in. Enabling both, which is exactly what `--all-features` does, compiles the tests out
instead:

| invocation | tests in the `piv_hardware` binary |
|---|---|
| `cargo test` | 0 |
| `cargo test --all-features` | 0 |
| `cargo test --features destructive-hardware-tests --test piv_hardware` | 11 (10 ignored) |

### Learnt the hard way

- Never let a suite pick "whatever is plugged in", and never point one at a token someone
  uses daily. Type the serial of a spare.
- gpg's scdaemon opens readers exclusively. Kill it before a run, and keep an eye on it during
  one: a gpg or ssh operation on the same machine can start it again mid-run, and the suite
  then fails with "other connections outstanding". The PIV suite recognises that failure and
  says so. `cargo test` itself never starts an scdaemon (its OpenPGP tests only call `gpg
  --show-keys`, which parses a file; killing scdaemon, running `cargo test --test pgp
  gpg_accepts_exported_cert` and finding none started afterwards confirmed it), so one that
  holds the card is left over from ordinary gpg use; the OpenPGP suite's gpg step starts one
  and stops it again on teardown.
- A run that leaves the readers contended can wedge gpg-agent, and with it anything that
  authenticates through it (ssh, and sudo via `pam_rssh`). If `gpg-connect-agent /bye` hangs,
  kill gpg-agent and scdaemon; socket activation starts a fresh agent.

## Simulated cards

`nix flake check` provisions simulated cards on every run, through the real binary and the
whole PC/SC path: pcscd, a reader driver, the APDUs and a complete card state machine, with
no hardware. What each covers, by algorithm, and the sources it was last built from are in the
[test results](test-results.md#simulated-cards), rendered from `harness/expected.toml` and the
last official run. The PIV rows run the card-level half of the PIV suite against the card (the
PKCS#11 end use needs a real token and OpenSC's driver); the OpenPGP rows run the whole
OpenPGP suite, three RSA sizes included.

**The virtual OpenPGP card.** `virtual-pgp` presents Nitrokey's
[opcard](https://github.com/Nitrokey/opcard-rs), the Nitrokey 3's OpenPGP implementation, as a
PC/SC reader through vsmartcard's `vpcd`, drives `init`, `upload` and `check` against it on
both curves and RSA at 2048 and 4096 bits (the 4096-bit import is the one too large for a
single short APDU), and runs the OpenPGP suite on every algorithm, gpg signing and decrypting
through the card end to end. Its first run showed that provisioning set the *cached* touch
policy fatally, a Yubico extension to the UIF data object that a spec-conforming card refuses;
the policy is advisory since. Its suite run is also the test that found the X25519 decryption
key landing on cards byte-reversed.

**The virtual PIV card.** `virtual-piv` does the same for the PIV applet of trussed's
[piv-authenticator](https://github.com/FlorianFranzen/piv-authenticator/tree/mind-the-gap),
the Nitrokey 3's PIV implementation, in a fork that grew the missing Yubico surface (ECC
import into every slot, a real GET METADATA, partial-AID selection, retry-counter semantics).
It exercises the whole provisioning conversation a YubiKey goes through (reset by pin
exhaustion, the derived AES-256 management key with its touch requirement, the derived puk,
the user pin, the imported keys with their policies read back, the byte-for-byte certificate
comparison and msroots), checks with the wrong seeds that must fail, and asserts that no
advisory comparison warns. It runs once per algorithm (`virtual-piv`, `-p384`, `-curve25519`,
`-rsa2048`, `-rsa3072`, `-rsa4096`, RSA imported in the Yubico layout), each followed by the
card-level half of the PIV suite: its own provisioning, the policy and certificate read-back,
msroots and the card identifiers, then the card signing in 9A, 9C and 9E under their pin
policies and agreeing (or, for RSA, decrypting) in 9D, each result compared with the same
computation off the card, which is what `check` cannot prove on its own.

`virtual-piv-builder` provisions the [unattended host profile](unattended-host.md) on the same
card: P-384 throughout, pin once and touch never on 9A, 9C and 9D, and management access
without a touch. It reads the result back through yubikit, the slot policies and the
management key metadata included, and `virtual-piv-builder-tdes` does the same with the triple
DES management key a YubiKey 4 needs forced onto the card.
The checks run the fork's `mind-the-gap` branch, trussed-dev's main plus every pending PR as
one commit each, rebuilt by a generator; `nix flake update piv-authenticator` follows it, and
the flake input pin says exactly which revision the claims hold for.

**The simulated Nitrokey 3.** `usbip-nk3` builds Nitrokey's own firmware as its [USB/IP
runner](https://github.com/Nitrokey/nitrokey-3-firmware/blob/main/docs/usbip.md), a complete
Nitrokey 3 as a host process attached to the VM's kernel through `vhci-hcd`, so pcscd finds a
USB key by hotplug and talks to it through libccid. That covers what the `vpcd` checks skip:
the USB descriptors, CCID framing, the firmware's APDU dispatcher choosing between its
applets, and the backend wiring of the real applet set. It provisions both applets and runs
both suites on every algorithm, restarting the key between them, since its flash is kept in
RAM and too small for PIV's four RSA-4096 keys and OpenPGP's three at once. The PIV applet is
the piv-authenticator input, OpenPGP the opcard release the firmware ships; the firmware is
the `mind-the-gap` branch of its fork (upstream main, whose PIV has a software pin backend
without the SE050 chip since Nitrokey/nitrokey-3-firmware#723, plus the P-384 mechanism the
firmware leaves out although the applet advertises the curve), on the `mind-the-gap` branch of
usbip-device (upstream plus Sawchord/usbip-device#10), without which a reply could answer the
wrong request and the kernel dropped the key mid-enumeration.

**Gnuk.** `usbip-gnuk` provisions [Gnuk](https://salsa.debian.org/gnuk-team/gnuk/gnuk), the
OpenPGP token firmware of the Free Software Initiative of Japan, through its GNU/Linux
emulation, attached over USB/IP like the simulated Nitrokey 3. Written independently of
opcard, in C on its own scheduler, it checks mind-the-gap against a second reading of the
OpenPGP card specification. The check provisions and checks through the command line, then
runs the OpenPGP suite on Curve25519, gpg end to end included; Gnuk 2 dropped NIST P-256 and
RSA, so for those the check asserts that the card is refused while it is intact. The emulation
is a stock Gnuk 2 build, which refuses every key import until the KDF data object is set, so
the check also proves that `init` sets one up. The button is pressed by a wrapper half a second
after Gnuk asks: the emulation drops a press that arrives while it is still telling the host
to wait.

**CanoKey.** `canokey` provisions [CanoKey](https://github.com/canokeys/canokey-core), whose
PIV and OpenPGP applets are C on mbed TLS, written apart from trussed and from Gnuk; its PIV
is the only one here that is not piv-authenticator. QEMU carries the firmware as a USB device
of its own ([canokey-qemu](https://github.com/canokeys/canokey-qemu)), on a UHCI controller of
its own, so pcscd reaches it through libccid. The check gives the key a serial through its
admin applet, provisions both applets through the command line, and runs the card-level PIV
suite on every algorithm and the whole OpenPGP suite, gpg included. CanoKey answers some
requests differently from a YubiKey, which the check runs around and asserts where
mind-the-gap is the one to notice:

- It reports PIV firmware 5.7.0, yet takes a triple DES management key only. `init` tries
  AES-256, as it does for that firmware, and settles on triple DES when the key refuses it;
  the check asserts the fallback. A touch requirement for management access is refused as
  well.
- Its PIV has neither msroots nor the key history object. `upload` warns that the card refused
  msroots and names `--no-msroots`, which the check asserts once and then runs with; the
  suite's in-place tests, which keep a key in a retired slot, stay out. The suite runs with
  both `MTG_HARDWARE_TEST_MSROOTS=off` and `MTG_HARDWARE_TEST_MANAGEMENT_ALGORITHM=tdes`.
- It uses an imported X25519 key without clamping it, where RFC 7748 has every implementation
  clamp before use. mind-the-gap imports X25519 keys clamped, which is the same key with the
  same public half, so Curve25519 runs like every other algorithm.
- Its OpenPGP applet keeps no private-use data objects, and answers for 0102 with its touch
  cache time. mind-the-gap reads a card identifier only from a card that announces those
  objects, so `check` says the card holds this key seed's keys with its administrator
  unknown, which the check asserts, and `upload` trusts the card seed, at the cost of an admin
  pin try if it is the wrong one. It has no KDF data object and no cached touch either.
- Under QEMU it never asks for a touch, as if held to an NFC reader, so the suites run
  touch-free.

Behind xHCI, QEMU hands a whole reply over in one transfer, and when the reply fills its last
64-byte packet, the zero-length packet the key sends after it is read as the answer to the
next command, which then fails at random; hence the UHCI controller.

**Refused touches.** A touch on the vpcd cards goes through trussed's user-presence request,
which the virtual card grants unless the file named by `VPICC_USER_PRESENCE` says `deny`. Touch
is checked both ways there: `virtual-piv` (P-256) and `virtual-pgp` end with
`touch_is_enforced`, which refuses every touch through that file and asserts that what the
policies gate is refused (PIV 9A, 9C and 9D and the management key; every OpenPGP key) while 9E,
which needs no touch, still signs, then grants touches again and asserts it all works. A refused
touch waits out the card's 15 second timeout, as on a token nobody touches, which adds about a
minute to each check. Real hardware cannot be told to refuse, so the test runs only where
`MTG_TEST_USER_PRESENCE_FILE` names that file.

**What is not emulated.** CanoKey under QEMU leaves out a touch, and on PIV an AES-256
management key, a touch requirement for management access, msroots, and the key history
object that lets middleware find a key kept in a retired slot; those stay with
piv-authenticator in the `virtual-piv` checks, and with the real cards. A Java Card simulator
(jCardSim with PivApplet) stays off the list: protocol gaps, plus a Java toolchain in the
closure. What no simulation covers is what the real cards are for: real readers and their
quirks, a human finger, and the vendor extensions.
