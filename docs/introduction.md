# Mind the Gap

<img src="logo.svg" width="160" alt="The Mind the Gap mark: a red shield with a bar reading MIND THE GAP">


This repository contains the following:

- command line utility to generate smart card keys from mnemonic phrases
- live image based on NixOS to use this tool in an air-gapped environment

## How to use


Install a flake enabled nix (e.g. by following the beginning of [this guide](https://serokell.io/blog/practical-nix-flakes)) and the run the following:

```
nix build github:gliology/mind-the-gap#iso
```

The resulting live image can then be found in `result/iso` and copied to an install media of your choosing.

Once booted you can now uses the `mind-the-gap` command line tool to generate and export any keys you might need. The command line client comes with built-in help and man pages, as well as shell completion to guide you through the process.

Start by minting a seed with `mind-the-gap generate`, which draws entropy straight from the kernel and keeps the phrase on screen until you have proven it is written down. No other command ever invents a seed on its own.

For everything after that, the recommended interface for most users is the *interactive session*: run `mind-the-gap` without any arguments and it opens, asks for the phrase once on its first use, follows up with the optional derivation password (just press enter for none), and keeps both in memory only until you leave with `exit` or Ctrl-D. A seed given with `--seed` brings its password the same way, via `--password`: the session then asks for neither. The session speaks the same commands as the command line (`piv upload -k laptop`, `pgp check`, ...), remembers the name, emails, subkey id and backend defaults given to `set`, asks for whatever required input a command still misses (name, emails, the upload pin), and offers history and line editing; `password` reopens the password question, and everything derived afterwards changes with it.

Two different rules keep secrets safe here, and they are worth telling apart. The *seed and password* may never appear on a session line: those lines land in the recallable history, so both are rejected before parsing and only ever travel through the hidden prompts. Card *pins* are different: they are per-card inputs, the session asks for them on upload, and typing one inline with `-i` is allowed for experts who accept that it enters the session history. QR codes are shown on the terminal's alternate screen and vanish without a trace when dismissed with Esc; a code too large for the screen renders inline instead, with a warning to clear the scrollback.

The flags and `MIND_THE_...` environment variables form a second, fully scriptable interface, meant for experts and for integrating the tool into larger workflows. Here every command requires the phrase, via `--seed` or `MIND_THE_SEED`, and fails without it: a one-shot invocation never stops on a prompt for *data*, so a script cannot hang, and the optional `--password` takes its value the same way. Exactly three things still interact: the destructive confirmation before a card is wiped (answered from the terminal, never from piped input; `--yes` is the scripted consent), the `generate` write-down ceremony, and the physical touch some cards demand. Piped *sessions* follow the same contract: they never prompt, missing inputs are errors or warnings exactly as one-shot.

The missing-input rules follow one principle. Verification degrades quietly: `check` without a pin simply skips the pin check. Provisioning degrades loudly: `upload` without a pin keeps the factory pin and says so, `export` without one writes unencrypted and says so. Missing identity is an error, never a guess. Public artifacts fall back to the screen as QR codes when no output is given; secret artifacts must be told where to go; `upload`'s artifact is the card itself. Know what this interface exposes before putting a real seed through it: command line arguments are visible to every process on the machine through `ps` and typically persist in the shell history, and environment variables can be read from `/proc/<pid>/environ` by the same user and are inherited by every child process the caller spawns. The same applies to every other secret the flags accept: a card pin passed as `--pin` sits in the history and the process list exactly like the seed would, and in the interactive session a pin typed on a command line also lands in the session's recallable history, which is why the session asks for the upload pin itself when it is left off the line. One more debugging hazard: `MIND_THE_LOG_LEVEL` accepts full filter spellings, and the card libraries would trace raw APDUs (pins included) at `trace`; the tool clamps them to `info`, so a card conversation can never end up in a log. Finally, the process locks down what it can (no core dumps, not ptrace-able, memory wiped on free), but plain `nix run` on a desktop still swaps like any process; the live image runs without swap, which is one more reason production keys belong there. On the air-gapped live image, where nothing else runs and nothing persists, these channels are mostly moot; anywhere else, use this interface only when you have taken care of them, for example by sourcing the seed from a protected file into a variable that is never exported and never echoed.

To just build and run the `mind-the-gap` tool in your current online environment you can also just run:

```
nix run github:gliology/mind-the-gap
```

While this is a great way to test functionality, it is strongly recommended to use an air-gapped environment for any production level keys.

When stepping away from a live-image machine mid-session, run `forget`: it clears the screen, the scrollback and the shell history in one stroke. Powering off does strictly more, and letting the machine sit for a moment before leaving it covers what software cannot.

## Security model

- **The seed is the only secret.** Everything -- keys, pins, identifiers -- derives from the
  24 word phrase (plus the optional password) through argon2id. Subkey ids, card identifiers
  and everything else a card or certificate carries are public by design; see
  [Key derivation](derivation.md).
- **Secrets stay out of the session history and the log.** `generate` mints a phrase and
  verifies it was written down; a one-shot command takes the phrase from `--seed` and
  fails without it, and the interactive session prompts once without echoing and holds
  it in process memory only. No line of the session may name a secret, so none can end
  up in the recallable history. QR output of secret material is displayed on the
  alternate screen and gone from scrollback on dismissal.
- **The live image enforces its own air gap.** No DHCP, wireless and bluetooth modules are
  blacklisted, kernel module loading is locked after boot, and no network tooling is
  installed. Console autologin and passwordless sudo are deliberate: the threat model of a
  live image is physical possession, and nothing secret is stored on it.

## Hardware support

| Token | OpenPGP | PIV |
|---|---|---|
| YubiKey 5 | works, in production | works, in production; the full [hardware checklist](piv-hardware-tests.md) passed |
| Nitrokey 3 | works, in production — the same card code runs in CI as the [virtual card](hardware-tests.md) | works against [our patched card code](https://github.com/FlorianFranzen/piv-authenticator/tree/ecc-import) in CI (the [virtual PIV check](hardware-tests.md)); real hardware awaits the fixes shipping in a firmware |
| Solo 2 | untested | untested |
| Gnuk | untested — planned as the second virtual-card target | no PIV applet |

"In production" means real cards provisioned from real seeds and used daily, not just a
test run. Anything marked untested may well work — the backends speak standard OpenPGP
card and PIV protocols — but has not been verified against the device.
