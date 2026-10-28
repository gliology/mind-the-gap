# Open items

- Optional, upstream: deterministic ECDSA in nettle itself (MR !64, open since 2024 with
  review points left and a rebase onto nettle 4 to do) and a nettle-rs binding for it would
  let sequoia offer RFC 6979 signing; mind-the-gap signs P-256 in `src/pgp/signer.rs` and
  needs neither. A comment offering to take over !64 and a plan for the binding are drafted
  in the upstreaming tracker
- Hardware runs of the redesigned commands. The flows run on virtual cards in CI, and the
  official touch-free runs on the three YubiKey spares came out as expected, test by test
  (2026-10-23, docs/test-results.md). Still to do through `nix run .#hardware-tests`: the
  attended runs on those three, both runs on the LPC55S69 dev kit, and a Nitrokey 3 entry
  when one is here; and the flows through the command line: `init`, `upload`
  (whole identity, `--key`, and a second key seed's decryption key into `--slot 82`),
  `check` with both seeds and with each alone, `list` verdicts (initialized, foreign, blank,
  keys only), `rotate --date` (the PIV archive into a retired slot, and the OpenPGP
  generation read off the card), `rotate --from-key-seed`, `pin` and `pin --reset` (the
  derived PIV puk, the per-card OpenPGP admin pin), `wipe` and `wipe --force`, the card
  identifier in 0102 on each OpenPGP card, the unattended host's pin rotation in plumbing
  mode on the YubiKey 4, and OpenSC listing a key kept in a retired slot (`pkcs11-tool -O`)
  on a YubiKey, which keeps the key history object `upload` writes, where
  piv-authenticator answers it from the slots it holds. The support grids in the supported
  cards chapter predate the redesign and are confirmed by these runs
- CanoKey moves on: the `canokey` check runs canokey-qemu as nixpkgs pins it, whose PIV
  takes a triple DES management key only. canokey-core main takes AES-192 alone, which
  mind-the-gap derives none of, so when canokey-qemu follows, `init` finds no management
  key it can install there; the check needs a decision then. Drafted upstream: the ask for
  every algorithm a YubiKey 5.4 takes, the X25519 clamping fix, and the QEMU xHCI fix that
  would let the key leave its UHCI controller
- Virtual touch refusal: the `VPICC_USER_PRESENCE` control rides on the published stacks
  until piv-authenticator and opcard take it. Still to do: the same for the simulated
  Nitrokey 3, whose runner already answers touches by signal (`--user-presence signal`,
  enough for the `usbip-nk3` check to refuse one; a file-based control is drafted for the
  runner too), and a refusal that answers at once instead of after the 15 second timeout,
  for which a trussed change is drafted (its virtual user interface takes the inner one's
  clock when that runs ahead), after which the vpicc interfaces implement `uptime`
- Nitrokey 3 PIV: the protocol work is open upstream as trussed-dev/piv-authenticator
  PRs (#46 to #58, with GET METADATA, the policies, SET PIN RETRIES, digest padding and
  the RSA layout waiting on #56), and the `virtual-piv` checks provision the fork's
  `mind-the-gap` branch (main plus every PR) end to end, warning-free, on every `nix flake
  check`. Remaining: the merges, verification on real Nitrokey 3 hardware once a firmware
  carries the fixes (a Nitrokey 3 Hacker arrives in the week of 2026-10-26), and the
  yubikey.rs slot-table bug: its `Key::list` reads the key history object as a certificate
  (`list` reads the slots itself and is immune). That is filed upstream as yubikey.rs#682;
  a comment on it and a follow-up for the certificate calls on management slots are drafted
- A PIV card that is not a YubiKey is judged before the reset by the algorithms its SELECT
  response lists, but piv-authenticator lists a fixed set of algorithms whatever its build
  carries (a Solo 2 image built without the `p384` and `rsa` features has neither), so the
  check passes, `init` resets the card and its import of 9E fails (what that leaves is in the
  supported cards chapter). Remaining: the piv-authenticator change that lists only
  what the build supports and the yubikey.rs one that exposes the list (drafted, the latter
  pinned here from its own branch until the stack takes it), then a virtual check that a build
  without RSA is refused intact. opcard's algorithm information (DO FA) has the same gap: it
  lists RSA in a build without an RSA backend, which `upload` trusts and such a dev kit
  image answers with 6A81 on the import, the keys before it written
- piv-authenticator empty-slot reads cost ~127 ms each on real NK3 hardware (upstream
  issue #40): a written-containers bitmap in the persistent state (maintained in
  `ContainerStorage::save`/reset, checked in GET DATA and the key history object)
  would answer NotFound without touching external flash; drafted on the fork, to be opened
- Curve25519 PIV end use: the card-level suite runs on both curves in CI, but the
  PKCS#11 steps (TLS, S/MIME, SSH, NSS) stay with the P-256 run until an OpenSC release
  drives Ed25519 and X25519 slots on cards other than a YubiKey 5.7. Master does since
  OpenSC#3673 and #3737; 0.27.1, the release in nixpkgs, does not. Next: run the steps
  against an OpenSC master build in the virtual check, then ask for the release (drafted)
- Solo 2: flash the Hacker from `hw/solo2`, and decide which apps and algorithms a Solo 2
  image carries, since FIDO, PIV and OpenPGP with RSA and P-384 do not fit in its 512 KiB
  together (the per-device serial and the stack for the RSA heap are drafted upstream as
  solo2 PRs and carried on `hw/solo2`)
- Zeroize the secret copies that remain inside foreign crates. Derived seeds live on the
  heap (`SecretSeed`), so moving one copies a pointer rather than the 32 bytes; the cipher
  key schedules (aes, des, cbc) and the dalek keys wipe on drop; p256 reads its scalars in
  place. Left: `yubikey::MgmKey`, which keeps the management key unwiped until it is
  dropped (a yubikey.rs change that wipes it on drop is drafted), the HMAC state PBKDF2
  keeps while stretching an `ungap` passphrase, and on both P-256 signing paths the copies
  inside RustCrypto's `sign_prehashed_rfc6979`: the scalar's encoding it hands to `rfc6979`,
  `k` and its inverse (stack temporaries, which RustCrypto leaves to the caller), and the
  HMAC_DRBG state `rfc6979` keeps (RustCrypto/signatures#1474 adds a `zeroize` feature for
  it, which reaches us through `ecdsa` once released); and the conversions inside the curve
  crates
- Release on crates.io so `cargo install mind-the-gap` works. Blocked on the git
  dependency: upstream will not take the salt removal (it is part of the OpenPGP/LibrePGP
  dispute), so the fork gets published as a renamed crate and consumed via cargo's
  `package =` rename, keeping the source untouched
- Report the NSS CMS ECDH decrypt failure upstream: `cmsutil -D -f <pinfile>` on a 9D
  enveloped message returns `SEC_ERROR_INVALID_KEY` (see the commented block in
  `tests/piv_hardware/end_use.rs::nss_recognises_card`). Reproduced in a VM on a virtual PIV
  token and on SoftHSM: it takes two bugs. OpenSC's ECDH derive ignores the KDF NSS asks for
  and returns the raw secret, and NSS's fallback for tokens that refuse the KDF is never
  reached from CMS. A Mozilla NSS bug and an OpenSC issue are drafted, with patches; file
  them, and restore the commented decrypt assertion once both are fixed. (The OpenSSL
  counterpart is already filed as openssl/openssl#24698.)
- RSA-4096 PIV import: the pinned yubikey revision carries the fix (the RSA-4096 card-level
  run passed with it on firmware 5.7.4); the yubikey.rs PR is reviewed and ready on the
  fork's `rsa4096-import` branch, to be opened
