# Taking over mind-the-gap

You are picking up the `v1` branch: mind-the-gap 1.0, redesigned around a card seed and a
key seed, at the first release candidate (`1.0.0-rc.1`). This page says how to test it,
how to review it, and what is left before the release. It points at the rest rather than
repeating it:

- [README.md](README.md): what the tool is, in one page.
- The book in [docs/](docs/SUMMARY.md): how to use it, the recommended flows, the
  derivation scheme, and how it is tested. Read the introduction, the flows, the derivation
  and the security chapters before anything else; they are the specification the code
  implements.
- Rustdoc on the items themselves: why each piece is shaped the way it is.
- [TODO.md](TODO.md): every open item.
- [REVIEW.md](REVIEW.md): the review of this branch before release, each finding and what
  came of it.
- [AGENTS.md](AGENTS.md): the working agreements (commit style, history, security UX,
  compatibility, dependencies, the verification bar). They bind humans too.

## Where the branch stands

```
main ── … ── 6d05a8b ── e997733 … 2679990 ── code ── nix ── docs ── release (v1)
```

- `v1` is on GitHub, its CI green. It replaced an earlier `origin/v1` from 2026-10-15 that
  ended at 6d05a8b; what came after that is the release candidate.
- After 6d05a8b come five smaller theme commits (the first-card walkthrough, finding a card
  without disturbing the others, gnuk and unattended suites, `--policy`, both suites at
  once in CI), then the redesign in four: code (the bulk), nix with the hardware
  harness, the book, and the release commit that only bumps the version;
  `git log --oneline 2679990..v1` lists them.
- History is compacted: fix-ups are folded into the commit they correct, and so are the
  release review's fixes, the hardware harness, the book's reorganization, the code's
  restructuring and the command line pass. The four redesign commits are therefore the
  branch as it is. [REVIEW.md](REVIEW.md) records each of those reviews, finding by finding,
  with where each fix is in the code.
- `design.md` (untracked) is the original redesign note. Everything in it is implemented
  and documented, so it can go.

## Testing

Everything runs inside the dev shell, which carries the toolchain, mdbook, gpg, OpenSC,
ykman, cargo-deny, cargo-machete, typos and nixfmt:

```
nix develop
```

### The quick loop

```
cargo fmt --check
cargo clippy --all-targets -- --deny warnings
cargo clippy --all-targets --features destructive-hardware-tests -- --deny warnings
cargo test
```

The book's [option reference](docs/options-reference.md) is rendered from the command line,
and a test fails while the committed chapter differs; after changing an option, write it again
with

```
cargo run --bin mind-the-build -- --reference docs/options-reference.md
```

`cargo test` needs no card and changes none, but the command line tests do ask PC/SC for
the attached readers while looking for a card that does not exist, so they open every
attached token for a moment. On a machine whose ssh, sudo or gpg depend on a token, keep
them away from the readers:

```
PCSCLITE_CSOCK_NAME=/nonexistent/pcscd.comm cargo test
```

### The full gate

```
nix flake check -L
```

This is what has to pass before any push, and it runs everything CI runs on x86 but the
networked advisory check: `cargo deny check advisories` needs the RustSec database from the
network, so CI runs it on its own (`nix develop --command cargo deny check advisories` does
the same by hand). Besides the build, the tests, clippy, rustdoc, `cargo deny`'s offline
checks, `cargo machete`, typos, nixfmt and the book's links, it boots the actual iso in qemu
under both BIOS and UEFI, and NixOS VMs that provision virtual cards end to end:

| Checks | What they prove |
|---|---|
| `virtual-piv`, `-p384`, `-curve25519`, `-rsa2048`, `-rsa3072`, `-rsa4096` | every PIV flow on piv-authenticator over vpcd, and on P-256 the keys at work through OpenSC, OpenSSL, ssh and NSS |
| `virtual-piv-builder`, `-tdes` | the unattended host profile |
| `virtual-pgp` | every OpenPGP flow on opcard, gpg using the keys end to end |
| `virtual-parallel` | both suites at once on two readers |
| `usbip-nk3` | the Nitrokey 3 firmware over USB/IP, both applets |
| `usbip-gnuk` | a stock Gnuk 2 build (KDF data object required) over USB/IP |
| `canokey` | CanoKey emulated by QEMU, a third PIV and OpenPGP implementation, both suites |
| `image-ceremony` | the NixOS module, a ceremony, dry runs, recording and plumbing mode |
| `live-system`, `boot-bios`, `boot-uefi` | the air-gapped live image |
| `test-results` | the rendered test results match `harness/results/` |

A single check builds with `nix build .#checks.x86_64-linux.<name> -L`. The whole gate takes
a while and keeps every core busy. The book builds with `nix build .#book` (or
`mdbook serve --open` in the shell), the live image with `nix build .#iso`.

### Real cards

The suites are **destructive**: they reset the applet they test, so they run only with the
feature, and only against a card named by its serial. [Hardware tests](docs/hardware-tests.md)
is the one reference for running them: the official runs through the harness
(`nix run .#hardware-tests`, with the spares' serials in a git-ignored `.env`), a single suite
run directly while working on it, the variables that shape a run, and what was learnt the
hard way about scdaemon and gpg-agent. The [PIV diagnostic
checklist](docs/piv-hardware-tests.md) is the manual walk behind the PIV suite, for diagnosing
a failure.

The spares used so far are YubiKey 5 `20381784` (5.4.3) and `34392895` (5.7.4), YubiKey 4
`6445117` (4.3.7), and an LPCXpresso55S69 dev kit running the Solo 2 firmware. The
touch-free suites pass on the three YubiKeys; the attended runs and the dev kit are open
(TODO.md).

For trying the command line by hand on a spare, the fixed BIP-39 test phrase the VM checks
use is safe because it is public: `MIND_THE_SEED="abandon abandon … abandon art"` (23 times
`abandon`, then `art`). Never put a real seed in the environment of a shell with history.

## Reviewing the branch

The surface is large: `git diff --stat main v1` is about 190 files and 49,000 added lines,
and `git diff 6d05a8b v1` (what nobody outside has seen) about 140 files, +27,000/-8,000.
The redesign's code commit alone is 19,000 lines. Review it by layer, not by commit, in this
order, so that each layer is read against one already understood:

1. **The specification.** The book's introduction, recommended flows, key derivation,
   security, why it is built this way, and compatibility chapters. Everything below
   implements them; a mismatch between book and code is a finding either way.
2. **The consensus surface.** `src/seed.rs`, `src/mnemonic.rs`, `src/rsa.rs`, and their
   golden vectors in `tests/derivation/`, `tests/piv/golden.rs`, `tests/pgp/golden.rs`.
   Labels, argon2 parameters, the `mtg1` stamp and the sha2 generation are frozen once
   released: a change after 1.0 moves every key in the field. Check every label against
   the derivation chapter, and that the per-card credentials end in the card serial.
3. **What both backends share**, `src/backend.rs`: the seed subtrees, each derived once per
   builder and only when used, the `Applet` and `Backend` traits the verbs drive both
   applets through, and the update plan. `src/revocation.rs` holds the revocation kinds and
   reasons both formats encode.
4. **The PIV backend**, `src/piv/`. `keys.rs` and `chain.rs` (certificates, CRL, the
   deterministic serials), `card.rs` (init, the management key, what is refused before a
   reset), `update.rs` (the upload plan: what differs, re-planned before writing, empty
   after; cards that cannot report policies), `check.rs`, `export.rs` (the hand-built
   PBES2 PKCS#8, cross-checked by OpenSSL in the tests), `ownership.rs`.
5. **The OpenPGP backend**, `src/pgp/`. The same shape: `keys.rs`, `card.rs` (init, the KDF
   data object, the admin pin per card), `update.rs`, `import.rs`, `ownership.rs`.
6. **The command line**, `src/cli/`. `options.rs` is the one option table that flags,
   config keys, `set` names and `MIND_THE_*` variables come from; then `config.rs` (a TOML
   subset with `[piv]`/`[pgp]` tables), `verbs/` (the context and builders in `mod.rs`, what
   the options alone decide, judged before any seed is stretched, in `preflight.rs`, the verbs
   that act on a card in `cards.rs`, those that write files in `files.rs`), `session.rs`,
   `completion.rs` (the session's tab key), `reference.rs` (the book's option reference), `seeds.rs` (how secrets are asked for, or refused), `ceremony.rs`,
   `plumbing.rs`, `output.rs`, `logging.rs` (the filter that keeps card traffic out of
   the log).
7. **Nix**: `nix/module.nix` (the image's read-only config and ceremony) and
   `nix/tests/*.nix`, which are the end-to-end specification of each flow.

What deserves the closest look:

- **Security UX** (AGENTS.md): a one-shot command never prompts; no secret is logged,
  echoed or minted outside `generate`; what is secret goes to the alternate screen;
  untrusted card text is sanitized before printing.
- **Nothing destructive happens before a refusal could.** `init` and `wipe` open the card,
  judge it, and name it in the confirmation before any reset; `upload` writes only what it
  listed.
- **Idempotence.** An `upload` run twice plans nothing the second time, on every card,
  including cards without GET METADATA (the YubiKey 4), where policies cannot be read back.
- **Protocol identifiers** (AIDs, data objects, status words) match the specifications and
  other implementations.

A first review has been done this way: [REVIEW.md](REVIEW.md) lists what it found and how
each finding was fixed, which is a good map of where the risk sits; this review is the
release candidate's, on top of it. `git show v1~3 -- src/piv` (the code commit) and the like
split the big commit by directory. The test files are worth reading alongside the code: they
say what each behaviour is for.

## What is left

In order:

1. **Review** the release candidate (above).
2. **Hardware**: official runs through the harness, touch-free and attended, on the
   spares, the dev kit and a Nitrokey 3, committed and rendered into the release notes; then
   the command line flows the suites do not drive. The list is the first item of TODO.md.
3. **Every push**: run the full gate first, and wait for CI after. The ARM boot check runs
   weekly, not per push. A history rewrite starts from a `backup/*` branch, which goes once
   CI is green after the force-push.
4. **Re-provision every card in use.** mtg1 was redefined before 1.0.0-rc.1, while the
   1.0 branch was unreleased, so every card a build of it provisioned derives differently
   now. [Compatibility](docs/compatibility.md) says what moved and what carries over, and
   gives the procedure: a new `init`, an `upload` under a new date, and the old subkeys
   revoked with the old build. Mind its warning: without the new date the old subkeys are the
   very keys the card holds again, and a revocation cannot be taken back.
5. **Release**: after public testing of rc.1, bump to `1.0.0` in its own release commit.
   Publishing on crates.io waits on the sequoia fork (TODO.md).
6. **Upstream**: the fixes this tool needs from other projects, drafted and waiting to be
   opened. Among them: yubikey.rs (the RSA-4096 import on fork branch `rsa4096-import`,
   wiping `MgmKey` on drop, follow-ups to #682), the NSS bug and OpenSC issue behind S/MIME
   decryption on a card, an OpenSC release with Curve25519 PIV, the piv-authenticator
   stack, trussed and the Nitrokey 3 runner (refusing a touch at once), CanoKey (X25519
   clamping, management key algorithms), QEMU (its CanoKey device behind xHCI), and an
   OpenKeychain fix for pin changes on KDF cards. The drafts and their tracker live outside
   this repository; ask the previous maintainer for them.
7. **The rest of TODO.md.**
