<p align="center">
  <img src="assets/logo-512.png" width="160" alt="The Mind the Gap mark: a red shield with a bar reading MIND THE GAP">
</p>

# Mind the Gap

This repository contains the following:

- command line utility to generate smart card keys from mnemonic phrases
- live image based on NixOS to use this tool in an air-gapped environment

The **major version tracks the derivation scheme**: any release within a major re-derives
the very same keys from a seed, which is what makes a lost card replaceable years later, and
a scheme change always ships as a new major -- see the
[derivation chapter](https://gliology.github.io/mind-the-gap/derivation.html).

One trust note worth stating plainly: the OpenPGP implementation is a two-commit fork of
sequoia, pinned by revision, and that single source is a single point of trust; the
[security model](https://gliology.github.io/mind-the-gap/introduction.html#security-model)
spells out what the fork changes and why.

## Quick start

Install a flake enabled nix and build the live image:

```
nix build github:gliology/mind-the-gap#iso
```

Copy the image from `result/iso` to an install medium and boot it. To try the tool in your
current online environment instead -- fine for testing, not for production keys:

```
nix run github:gliology/mind-the-gap
```

Start by minting a seed with `mind-the-gap generate`; the built-in help, man pages and shell
completion guide you from there.

Running `mind-the-gap` without a subcommand opens an interactive session, the recommended
interface for most users: it asks for the seed and optional password once, holds them in process memory only, and
refuses any line that would put a secret into the session history. The `--seed` and
`--password` flags and the `MIND_THE_...` environment variables form a second, fully
scriptable interface for experts and integrations. Arguments and environments are visible
to other processes, so that interface is for scenarios where the caller takes extra care to
protect the secrets; the
[user guide](https://gliology.github.io/mind-the-gap/introduction.html) spells out the
risks.

## Documentation

- [User guide](https://gliology.github.io/mind-the-gap/) --- how to use the tool, the key
  derivation scheme and its security model, several cards from one seed, the PIV certificate
  chain, and the hardware test suites
- [Developer reference](https://gliology.github.io/mind-the-gap/rustdoc/mind_the_gap/) ---
  rustdoc for every module, private items included
- [TODO.md](TODO.md) --- every open item

Build the user guide locally with `nix build .#book`, or serve it with live reload from the
dev shell via `mdbook serve --open`.

## Development

The Rust toolchain is declared once in [`rust-toolchain.toml`](rust-toolchain.toml) and
honoured by both rustup and the flake, so `nix develop` and a plain `cargo` agree on the
compiler. CI builds are pushed to a binary cache; substituting from it locally is one
command:

```
cachix use mind-the-gap
```

`nix flake check` runs everything CI runs: format, clippy and the test suite, rustdoc, the
rendered book and its consistency checks, the live system test, and boots the actual iso in
qemu over both BIOS and UEFI.

Where things live: user documentation is the mdBook under [`docs/`](docs/), developer
documentation is rustdoc on the modules and items themselves, open items are in
[TODO.md](TODO.md), and this README stays a landing page that duplicates none of them.

## Alternatives

- [sshcerts](https://github.com/obelisk/sshcerts)
