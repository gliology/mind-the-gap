# Mind the Gap


DISCLAIMER: THIS IS WIP! DERIVATION PATHS MIGHT CHANGE AND BREAK COMPATIBLITY WITH PREVIOUS VERSIONS.

This repository contains the following:

- command line utility to generate smart card keys from mnemonic phrases
- live image based on NixOS to use this tool in an air-gapped environment

## How to use


Install a flake enabled nix (e.g. by following the beginning of [this guide](https://serokell.io/blog/practical-nix-flakes)) and the run the following:

```
nix build github:gliology/mind-the-gap#iso
```

The resulting live image can then be found in `result/iso` and copied to an install media of your choosing.

Once booted you can now uses the `mind-the-gap` command line tool to generate and export any keys you might need. The command line client comes with built-in help and man pages, as well as shell completion to guide you through the process. We recommend the use of the `MIND_THE_...` environment variables to pass parameters to the utility.

To just build and run the `mind-the-gap` tool in your current online environment you can also just run:

```
nix run github:gliology/mind-the-gap
```

While this is a great way to test functionality, it is strongly recommended to use an air-gapped environment for any production level keys.

## Development

The Rust toolchain is declared once in [`rust-toolchain.toml`](rust-toolchain.toml) and
honoured by both rustup and the flake, so `nix develop` and a plain `cargo` agree on the
compiler. CI builds are pushed to a binary cache; substituting from it locally is one
command:

```
cachix use mind-the-gap
```

`nix flake check` runs everything CI runs: format, clippy and the test suite, the live
system test, and boots the actual iso in qemu over both BIOS and UEFI.

## Documentation

The full documentation is built from [`docs/`](docs/) with mdBook and published as a site:

- [Key derivation](docs/derivation.md) --- the tree, the label grammar, and why every card
  should have its own subkey id
- [Several cards from one seed](docs/multiple-cards.md) --- what changes once one seed
  provisions more than one card, and what revocation would require
- [PIV certificate chain](docs/piv-certificates.md) --- the X.509 chain the PIV backend issues
- [Hardware tests](docs/hardware-tests.md) --- the destructive on-card suites
- [PIV hardware checklist](docs/piv-hardware-testing.md) --- the manual steps that cannot be
  automated

Build it locally with `nix build .#book`, or serve it with live reload from the dev shell:

```
mdbook serve --open
```

## Open issues:

- Automate the remaining manual checklist items where possible; sections 1-4 now run as
  `cargo test --features destructive-hardware-tests --test hardware` (see
  [docs/piv-hardware-testing.md](docs/piv-hardware-testing.md))
- Finish the last two items of the PIV hardware test checklist in
  [docs/piv-hardware-testing.md](docs/piv-hardware-testing.md): TLS client auth from a
  browser, and Thunderbird S/MIME. Everything else -- `piv upload`, `piv check`, per-slot
  policies, `msroots`, on-card signing and decryption, SSH and TLS client auth -- passed
  against a YubiKey 5 on 2026-09-17
- Zeroize the secret copies that remain out of reach without upstream support: transient
  stack copies made when the 32-byte arrays are moved, and copies held inside foreign
  crates (`yubikey::MgmKey`'s cipher key, `p256` and `chacha20poly1305` key buffers).
  Everything under this crate's control is wiped by type now -- every derivation returns
  `Zeroizing<Seed256>`, the long-lived seeds are stored wrapped, and the mnemonic phrase
  copies, derived pins and the exported secret-key armor are all zeroizing
- Archive previous PIV subkey generations in the retired slots (82-95)
- Test and support other keys (i.e. Solo 2, Nitrokey 3)
- Investigate use of sequoia piv wrapper `openpgp-piv-sequoia`
- Investigate u2f integration

## Alternatives:

- [sshcerts](https://github.com/obelisk/sshcerts)
