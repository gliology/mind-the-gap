# Open items

- Gnuk 2 tokens: set up the KDF data object (OpenPGP card 3.3, iterated and salted SHA-256)
  during `pgp upload`, which a stock Gnuk 2 requires before any key import; the
  `usbip-gnuk` check builds the emulation with it optional until then. canokey-qemu (a QEMU
  USB device with PIV and OpenPGP) would add an independent PIV implementation in CI (see
  "What is not emulated" in [docs/hardware-tests.md](docs/hardware-tests.md))
- Virtual touch refusal: the `VPICC_USER_PRESENCE` control rides on the published stacks
  until piv-authenticator and opcard take it. Still to do: the same for the simulated
  Nitrokey 3, whose runner has a user interface of its own, and a refusal that answers at
  once instead of after the 15 second timeout, which needs trussed's virtual user interface
  to hand `uptime` to the inner one as it does the presence check
- Nitrokey 3 PIV: the protocol work is open upstream as trussed-dev/piv-authenticator
  PRs (#46 to #58, with GET METADATA, the policies, SET PIN RETRIES, digest padding and
  the RSA layout waiting on #56), and the `virtual-piv` checks provision the fork's
  `mind-the-gap` branch (main plus every PR) end to end, warning-free, on every `nix flake
  check`. Remaining: the merges, verification on real Nitrokey 3 hardware once a firmware
  carries the fixes, and the yubikey.rs slot-table bug (its `Key::list` reads the key
  history object as a certificate; `piv status` lists slots itself and is immune)
- A PIV card that is not a YubiKey is judged before the reset by the algorithms its SELECT
  response lists, but piv-authenticator lists every algorithm whatever its build carries (a
  Solo 2 image built without the `p384` and `rsa` features has neither), so the check
  passes and the import still fails after the reset. Remaining: the piv-authenticator
  change that lists only what the build supports and the yubikey.rs one that exposes the
  list (drafted, the latter pinned here from its own branch until the stack takes it), then
  a virtual check that a build without RSA is refused intact. opcard's algorithm
  information (DO FA) has the same gap: it lists RSA in a build without an RSA backend,
  which `pgp upload` trusts and such a dev kit image answers with 6A81 after the reset
- piv-authenticator empty-slot reads cost ~127 ms each on real NK3 hardware (upstream
  issue #40): a written-containers bitmap in the persistent state (maintained in
  `ContainerStorage::save`/reset, checked in GET DATA and the key history object)
  would answer NotFound without touching external flash; propose upstream
- Curve25519 PIV end use: the card-level suite runs on both curves in CI, but the
  PKCS#11 steps (TLS, S/MIME, SSH, NSS) stay with the P-256 run until OpenSC's PIV driver
  drives Ed25519 and X25519 slots
- Retired slots carry no key history object (5FC10C). Check on the virtual card whether
  OpenSC exposes the archived key management keys without it (`pkcs11-tool -O`), and write
  it (the key history counts are a protocol identifier) if it does not
- The build server profile signs Nix store paths with the 9D key, whose certificate allows
  key agreement only; PKCS#11 does not look, but 9C or a retired slot would keep signing
  and agreement apart
- Solo 2: flash the Hacker from `hw/solo2`, and decide which apps and algorithms a Solo 2
  image carries, since FIDO, PIV and OpenPGP with RSA and P-384 do not fit in its 512 KiB
  together (the per-device serial and the stack for the RSA heap are drafted upstream as
  solo2 PRs and carried on `hw/solo2`)
- Zeroize the secret copies that remain out of reach without upstream support: transient
  stack copies made when the 32-byte arrays are moved, and copies held inside foreign crates
  (`yubikey::MgmKey`'s cipher key and `p256` key buffers; openpgp-card 0.7 closed the
  `EccKey` copy by borrowing the material instead)
- Manage a card without resetting it: `upload` resets the card it targets, which stays the
  default, but it could first find out whether the card already belongs to the seed, by
  comparing its public certificates and fingerprints (no pin tries, no touch, safe on every
  attached card, so the session can list the cards a seed owns), and update such a card in
  place with the derived management key and admin pin
- Release on crates.io so `cargo install mind-the-gap` works. Blocked on the git
  dependency: upstream will not take the salt removal (it is part of the OpenPGP/LibrePGP
  dispute), so the fork gets published as a renamed crate and consumed via cargo's
  `package =` rename, keeping the source untouched
- For the next derivation scheme (`mtg2`): fold the TBS content (validity, subject, flags)
  into the PIV certificate serial, so re-issuing with different flags cannot repeat an
  (issuer, serial) pair (RFC 5280 4.1.2.2); and normalize the password (NFKD, as BIP-39
  does), so the same password typed differently derives the same keys. Both are frozen
  within `mtg1`: `check` compares certificates byte for byte (see `serial_for` in
  `src/piv/chain.rs`), and the password is part of every derivation
- Report the NSS CMS ECDH decrypt failure upstream: `cmsutil -D -f <pinfile>` on a 9D
  enveloped message returns `SEC_ERROR_INVALID_KEY` even though the token key is
  `CKA_DERIVE` and `pkcs11-tool` does the same `CKM_ECDH1_DERIVE` (see the commented block
  in `tests/piv_hardware/end_use.rs::nss_recognises_card`). Needs a minimal reproduction against a
  virtual PIV token, then a Mozilla NSS bug; restore the commented decrypt assertion once
  fixed. (The OpenSSL counterpart is already filed as openssl/openssl#24698.)
- RSA-4096 PIV import: the pinned yubikey revision carries the fix (the RSA-4096 card-level
  run passed with it on firmware 5.7.4); upstream it to yubikey.rs
