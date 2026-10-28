<p align="center">
  <img src="assets/logo-512.png" width="160" alt="The Mind the Gap mark: a red shield with a bar reading MIND THE GAP">
</p>

# Mind the Gap

Mind the Gap derives smart card keys, credentials and certificates for PIV and OpenPGP cards
from BIP-39 seed phrases, on an air-gapped machine. This repository contains:

- `mind-the-gap`, the command line tool, with an interactive session, config files, ceremonies
  and a plumbing mode for automation;
- a NixOS live image that runs it with every way out of the machine taken away.

The **major version tracks the derivation scheme**: any release within a major re-derives the
very same keys from a seed, which is what makes a lost card replaceable years later, and a
scheme change always ships as a new major; see the
[compatibility chapter](https://gliology.github.io/mind-the-gap/compatibility.html).

One trust note worth stating plainly: the OpenPGP implementation is a two-commit fork of
sequoia, pinned by revision, and that single source is a single point of trust; the
[security chapter](https://gliology.github.io/mind-the-gap/security.html#the-forked-sequoia-openpgp)
spells out what the fork changes and why.

## Quick start

```
nix build github:gliology/mind-the-gap#iso
```

Write the `.iso` file in `result/iso/` to a stick, boot it and run `mind-the-gap`; [your first
card](https://gliology.github.io/mind-the-gap/quick-start.html) takes it from there, and the
[recommended flows](https://gliology.github.io/mind-the-gap/flows.html) cover several devices,
teams and unattended hosts.

## Documentation

- [User guide](https://gliology.github.io/mind-the-gap/): the recommended flows, every command
  and option, ceremonies, the key derivation scheme and its security model, and the hardware
  test suites
- [Developer reference](https://gliology.github.io/mind-the-gap/rustdoc/mind_the_gap/): rustdoc
  for every module, private items included
- [TODO.md](TODO.md): every open item

Build the user guide locally with `nix build .#book`, or serve it with live reload from the
dev shell via `mdbook serve --open`.

## Development

[HUMAN.md](HUMAN.md) says how to build, test and review the code, and
[AGENTS.md](AGENTS.md) holds the working agreements. The Rust toolchain is declared once in
[`rust-toolchain.toml`](rust-toolchain.toml) and honoured by both rustup and the flake. CI
builds are pushed to a binary cache; substituting from it locally is one command:

```
cachix use mind-the-gap
```

## Alternatives

- [sshcerts](https://github.com/obelisk/sshcerts)
