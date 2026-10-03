# Open items

- Add Gnuk as a second virtual-card target: package its emulation build
  (`--target=GNU_LINUX`, USB/IP) and attach it via `vhci-hcd` inside the test VM, covering
  the USB CCID transport that the opcard check bypasses (see "What is not emulated" in
  [docs/hardware-tests.md](docs/hardware-tests.md))
- Nitrokey 3 PIV: the protocol work is done on our piv-authenticator fork
  (github:FlorianFranzen/piv-authenticator, branch `ecc-import` -- ECC import, GET
  METADATA, uuid serial, pin/touch policies, msroots, SET PIN RETRIES, Yubico client
  compatibility) and the `virtual-piv` check provisions it end to end, warning-free, on
  every `nix flake check`. Remaining: upstream the branch to trussed-dev as PRs (issues
  #15/#16/#31/#32 track the wants), verify on real Nitrokey 3 hardware once a firmware
  carries the fixes, and report the yubikey.rs slot-table bug upstream (its `Key::list`
  reads the key history object as a certificate; `piv status` now lists slots itself
  and is immune)
- piv-authenticator empty-slot reads cost ~127 ms each on real NK3 hardware (upstream
  issue #40): a written-containers bitmap in the persistent state (maintained in
  `ContainerStorage::save`/reset, checked in GET DATA and the key history object)
  would answer NotFound without touching external flash; propose upstream
- canokey-qemu (a QEMU USB device implementing PIV and OpenPGP) remains the
  transport-covering alternative to the vpcd checks
- Solo 2: VALIDATED ON EVK HARDWARE (2026-09-30, rev 0A LPCXpresso55S69): `piv upload`
  and `piv check` pass end to end over CCID, including a real USER-button touch on the
  management key, byte-identical certificates and msroots. Firmware:
  FlorianFranzen/solo2 branch `piv-ecc-import` (piv-authenticator `solo2` branch +
  apdu-dispatch `yubikey-le` fork -- partial-AID routing and absent-Le=256 must live in
  the dispatch layer, found only on hardware). EVK quirks: rev 0A needs the new
  `no-pfr` feature (boot ROM ffr_init hardfaults) and builds must drop log-defmt (~7 KB
  over flash). Remaining before flashing the Hacker key: rebuild app-hacker.bin with
  the updated pins (the validated fixes), then follow the flash-solo-hacker skill
  (PFR lock-state and KEYSTORE checks); also pass the device uuid into the PIV app in solo-apps so
  the serial is per-device (EVK reports the 5437251 fallback), and upstream the
  apdu-dispatch Le/RID change to trussed-dev
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
  (issuer, serial) pair (RFC 5280 4.1.2.2); frozen within `mtg1` because `check` compares
  certificates byte for byte (see `serial_for` in `src/piv.rs`)
- Report the NSS CMS ECDH decrypt failure upstream: `cmsutil -D -f <pinfile>` on a 9D
  enveloped message returns `SEC_ERROR_INVALID_KEY` even though the token key is
  `CKA_DERIVE` and `pkcs11-tool` does the same `CKM_ECDH1_DERIVE` (see the commented block
  in `tests/piv_hardware.rs::nss_recognises_card`). Needs a minimal reproduction against a
  virtual PIV token, then a Mozilla NSS bug; restore the commented decrypt assertion once
  fixed. (The OpenSSL counterpart is already filed as openssl/openssl#24698.)
