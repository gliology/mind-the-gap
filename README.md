# Mind the Gap

DISCLAIMER: THIS IS WIP! DERIVATION PATHS WILL CHANGE AGAIN WITH ADDITION OF PIV SUPPORT WHICH WILL BREAK COMPATIBLITY BETWEEN VERSIONS.

This repository contains the following:

- command line utility to generate OpenPGP keys from mnemonic phrases
- live image based on NixOS to use this tool in an air gapped environment

## How to use

Install a flake enabled nix (e.g. by following the beginning of [this guide](https://serokell.io/blog/practical-nix-flakes)) and the run the following:

```
nix build github:gliology/mind-the-gap#iso
```

The resulting live image can then be found in `result/iso` and copied to an install media of your chosing.

You can then uses any of the included tools (i.e. currently only `mnemonic2pgp`) to generate any keys you might need.

To just build and run the default command `mnemonic2pgp` you can also just run:

```
nix run github:gliology/mind-the-gap
```

## Implementation details

### Mnemonic to OpenPGP primary and subkeys

While the project was inspired by the cryptography used in substrate, we ended up diverging from the code that is used in subkey in a few places:

 - This tools generates and accept only 24 word seeds, which is equivalent to 256bits of entropy (and 8 bits of checksum). 
 - This entropy is then hashed 2048 times with pbkdf2 using sha256. The bytes `mnemonic` optional followed by a password are used as the salt for this operation.
 - The resulting hash is then used as the Ed25519 primary 
 - For subkeys this hash is then further used in a hard key derivation to create three seperate keys. In this derivation the bytes `MINDTHEGAP256HDKD` are combined with the previous output and the 256bit blake2b hash of the derivation path. The derivation path is either the bytes `signature`, `encryption` or `authentication`, depending on the subkeys being generated and its use case.
- The resulting hashes are used as the signing, encryption and authentication Ed25519/Cv25519 subkeys.

## Future goals:

- Move away from installer to pure live image
- Use __sequoia__ to upload cert directly once [#114](https://gitlab.com/sequoia-pgp/sequoia/-/issues/114) is done.
