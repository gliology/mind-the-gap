# Open items

- A second, independent card implementation in CI: Gnuk's emulation build
  (`--target=GNU_LINUX`) speaks USB/IP and could reuse the plumbing `usbip-nk3` already
  has, as a second OpenPGP target next to opcard; canokey-qemu (a QEMU USB device with PIV
  and OpenPGP) would add one for both backends (see "What is not emulated" in
  [docs/hardware-tests.md](docs/hardware-tests.md))
- Nitrokey 3 PIV: the protocol work is open upstream as trussed-dev/piv-authenticator
  PRs (#46 to #58, with GET METADATA, the policies, SET PIN RETRIES, digest padding and
  the RSA layout waiting on #56), and the `virtual-piv` checks provision the fork's
  `mind-the-gap` branch (main plus every PR) end to end, warning-free, on every `nix flake
  check`. Remaining: the merges, verification on real Nitrokey 3 hardware once a firmware
  carries the fixes, and the yubikey.rs slot-table bug (its `Key::list` reads the key
  history object as a certificate; `piv status` lists slots itself and is immune)
- A PIV card that is not a YubiKey is only found unable to import an algorithm after the
  reset: piv-authenticator's SELECT response lists all nine algorithms whatever its build
  carries (a Solo 2 image built without the `p384` and `rsa` features has neither). Propose upstream that the list
  follow the backends, and have yubikey.rs expose the SELECT response, so `upload` can
  refuse such a card while it is intact, as it already does for YubiKeys by version.
  opcard's algorithm information (DO FA) has the same gap: it lists RSA in a build without
  an RSA backend, which `pgp upload` trusts and such a dev kit image answers with 6A81
  after the reset
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
- Solo 2: flash the Hacker from `hw/solo2`, pass the device uuid into the PIV app so the
  serial is per-device (the dev kit reports the 5437251 fallback), and decide which apps and
  algorithms a Solo 2 image carries, since FIDO, PIV and OpenPGP with RSA do not fit in its
  512 KiB together, nor does FIDO's `init` leave stack for the RSA heap
- Zeroize the secret copies that remain out of reach without upstream support: transient
  stack copies made when the 32-byte arrays are moved, and copies held inside foreign crates
  (`yubikey::MgmKey`'s cipher key and `p256` key buffers; openpgp-card 0.7 closed the
  `EccKey` copy by borrowing the material instead)
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
