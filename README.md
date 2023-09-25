# Mind the Gap

DISCLAIMER: THIS IS WIP! DERIVATION PATHS MIGHT CHANGE AND BREAK COMPATIBLITY WITH PREVIOUS VERSIONS.

This repository contains the following:

- command line utility to generate smart card keys from mnemonic phrases
- live image based on NixOS to use this tool in an air gapped environment

## How to use

Install a flake enabled nix (e.g. by following the beginning of [this guide](https://serokell.io/blog/practical-nix-flakes)) and the run the following:

```
nix build github:gliology/mind-the-gap#iso
```

The resulting live image can then be found in `result/iso` and copied to an install media of your chosing.

Once booted you can now uses the `mind-the-gap` command line tool to generate any keys you might need.

To just build and run the `mind-the-gap` tool in your current online environement you can also just run:

```
nix run github:gliology/mind-the-gap
```

## Implementation details

### Mnemonic to OpenPGP primary and subkeys

While the project was inspired by the cryptography used in bitcoin and substrate, we ended up switching to argon2id for our key derivation function.
This tools generates and accept only 24 word seeds, which is equivalent to 256bits of entropy (and 8 bits of checksum). 
All keys are derived from this root entropy through multiple rounds of argon2id using the recommended parameters for memory constraint environments.

The salt is always set to at least `MINDTHEGAP256HDKD` and optional followed by an additional context like a password, subkey ids, app or key identifiers:

```
256-bit mnemonic seed/
└── (optional password)/
    ├── app identifier/
    │   ├── primary key
    │   ├── (optional subkey id)/
    │   │   ├── mgmnt key
    │   │   ├── signing subkey
    │   │   ├── decryption subkey
    │   │   └── authentication subkey
    │   └── (additinal subkey id)/
    │       └── any other subkey type
    └── app identifier/
        ├── primary key
        ├── (optional subkey id)/
        │   ├── mgmnt key
        │   ├── signing subkey
        │   ├── decryption subkey
        │   └── authentication subkey
        └── (additinal subkey id)/
             └── any other subkey type
```

## Future goals:

- Zerorize secrets properly and consistently
- Add PIV primary certificate
- Test and support other keys (i.e. Solo 2, Nitrokey 3)
- Move away from installer to pure live image
- Investigate use of sequoia piv wrapper `openpgp-piv-sequoia`
- Investigate u2f integration

## Alternatives:

- [sshcerts](https://github.com/obelisk/sshcerts)
