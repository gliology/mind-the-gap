# Open items

- Finish the two remaining manual PIV checks: TLS client auth from a browser, and
  Thunderbird S/MIME (see the checklist in
  [docs/piv-hardware-tests.md](docs/piv-hardware-tests.md))
- Automate the remaining manual checklist items where possible; sections 1-4 already run as
  `cargo test --features destructive-hardware-tests --test piv_hardware`
- Find or build an emulated card so the hardware suites can run in CI
  (see "Why there is no emulated card" in [docs/hardware-tests.md](docs/hardware-tests.md))
- Zeroize the secret copies that remain out of reach without upstream support: transient
  stack copies made when the 32-byte arrays are moved, and copies held inside foreign crates
  (`yubikey::MgmKey`'s cipher key, `p256` and `chacha20poly1305` key buffers)
- Test and support other keys (i.e. Solo 2, Nitrokey 3)
- Release on crates.io so `cargo install mind-the-gap` works. Blocked on the git
  dependency: upstream will not take the salt removal (it is part of the OpenPGP/LibrePGP
  dispute), so the fork gets published as a renamed crate and consumed via cargo's
  `package =` rename, keeping the source untouched
- For the next derivation scheme (`mtg2`): fold the TBS content (validity, subject, flags)
  into the PIV certificate serial, so re-issuing with different flags cannot repeat an
  (issuer, serial) pair (RFC 5280 4.1.2.2); frozen within `mtg1` because `check` compares
  certificates byte for byte (see `serial_for` in `src/piv.rs`)
- Investigate use of sequoia piv wrapper `openpgp-piv-sequoia`
- Investigate u2f integration
