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

## How to develop

The mind-the-gap flake also includes a full development environment including `rust-analyser` and `rustfmt`, which can be accessed via `nix develop`.

### Mnemonic to primary and subkeys

While the project was inspired by the key derivation cryptography used in bitcoin and substrate, we ended up switching to `argon2id` for our key derivation function.
This tools generates and accept only 24 word seeds, which is equivalent to 256bits of entropy (and 8 bits of checksum). 
All keys are derived from this root entropy through multiple rounds of `argon2id` using the recommended parameters for memory constraint environments.

The salt is always set to at least `MINDTHEGAP256HDKD` and optionally followed by an additional context like a password, (sub-)key or application identifiers:

```
256-bit mnemonic seed/
└── (optional password)/
    ├── "openpgp"/
    │   ├── primary key
    │   ├── (optional subkey id)/
    │   │   ├── admin pin
    │   │   ├── signing subkey
    │   │   ├── decryption subkey
    │   │   └── authentication subkey
    │   └── (additinal subkey id)/
    │       └── any other subkey type
    └── "piv"/
        ├── root CA key
        ├── (optional subkey id)/
        │   ├── issuing CA key
        │   ├── mgmnt key
        │   ├── card identifier
        │   ├── authentication key    (slot 9A)
        │   ├── signature key         (slot 9C)
        │   ├── key management key    (slot 9D)
        │   └── card authentication   (slot 9E)
        └── (additinal subkey id)/
             └── any other subkey generation
```

Note that the certificate authority key is a *sibling* of the subkey id, not its parent.
Were it the parent, anyone holding the authority key could re-derive every slot key.

### PIV certificate chain

The PIV backend issues a full X.509 chain rather than a set of self-signed certificates,
so that the card works with S/MIME, TLS client authentication, SSH and smartcard logon:

```
Root CA (self-signed, CA:TRUE)
└── (optional issuing CA, enabled with --intermediate)
    ├── 9A authentication   digitalSignature            clientAuth, msSmartcardLogon
    ├── 9C signature        digitalSignature, nonRepudiation   emailProtection
    ├── 9D key management   keyAgreement                emailProtection, clientAuth
    └── 9E card auth        digitalSignature            id-PIV-cardAuth
```

All keys are NIST P-256 and every certificate is signed with `ecdsa-with-SHA256`. Slot 9D
uses `keyAgreement` rather than `keyEncipherment` because these are ECDH keys and RFC 8813
forbids the latter on EC keys.

Slots 9A, 9C and 9D are bound to the cardholder; slot 9E is bound to the card and carries no
email address, as required by FIPS 201-3 section 4.2.3. Its subject uses a card identifier
derived from the seed rather than the card's serial number, so that `piv certify` (which runs
without any hardware) and `piv upload` produce identical certificates.

Export the root certificate with `mind-the-gap piv certify --kind root` and install it as a
trust anchor. The authorities are additionally written to the card's `msroots` object, where
the Windows minidriver picks them up.

Certificate generation is fully deterministic: signing uses RFC 6979 deterministic ECDSA
nonces, and the creation time defaults to the unix epoch, so re-running `piv certify` with
the same inputs reproduces the same bytes.

## Open issues:

- Run the PIV hardware test checklist in [docs/piv-hardware-testing.md](docs/piv-hardware-testing.md);
  the card layer (`piv upload`, `piv check`, `msroots`) has not yet been exercised against a real card
- Apply the deferred repo-wide `cargo fmt` pass (~290 lines, config already in `rustfmt.toml`)
- Zerorize secrets properly and consistently
- Archive previous PIV subkey generations in the retired slots (82-95)
- Test and support other keys (i.e. Solo 2, Nitrokey 3)
- Investigate use of sequoia piv wrapper `openpgp-piv-sequoia`
- Investigate u2f integration

## Alternatives:

- [sshcerts](https://github.com/obelisk/sshcerts)
