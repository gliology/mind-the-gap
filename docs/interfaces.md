# The session and the command line

mind-the-gap has one grammar, verb first with the applet an option (`upload --app piv`), and
three ways to speak it:

- **the interactive session**, for people: `mind-the-gap` without a verb, which asks for what
  it needs and keeps it until you leave;
- **one-shot commands**, for experts and scripts: `mind-the-gap <verb> [options]`, with every
  input given as a flag or a `MIND_THE_...` variable, and nothing ever asked;
- **plumbing mode**, for programs: a one-shot command or a piped session that reports on
  stdout as JSON.

A session line, a one-shot command and a [ceremony](ceremonies.md) step are parsed alike, so
an example written for one works in the others. [Commands](commands.md) describes every verb
and [options](configuration.md) every option.

## The interactive session

```
mind-the-gap
mtg> set name='Jane Doe' emails=jane@example.org
mtg> init
mtg> upload -k laptop
mtg> quit
```

Each line of the session is a command line without the program name. The session

- asks for each seed on a hidden prompt the first time a command needs it, then for its
  optional password, and keeps both in memory until you leave;
- asks for the name and emails a command needs, and keeps the answers as defaults;
- asks for the pin `init` sets (empty keeps the factory pin) and the pins `pin` changes, the
  new one twice;
- takes defaults with `set name=value` and forgets them with `unset`, and shows them, with
  where each came from, with `set` alone;
- offers line editing and a history of the commands typed, in memory only, and completes the
  verbs, their options, the values an option takes and the names `set` takes with the tab
  key, from the options alone: never a seed, a password or anything typed before.

`help` lists the verbs, and `help <verb>` explains one, without the process options, the seed
phrase and the passwords, which a line cannot carry; `--card-seed` and `--key-seed` stay, as
a line gives them bare to be asked for that seed. Ctrl-C abandons the line being typed; `quit` or
Ctrl-D leaves the session, and the seeds go with it.

A session started with `--card-seed` or `--key-seed` without a value asks for that seed apart
when it is first needed and keeps it for every line: `mind-the-gap --card-seed --key-seed` is
the session of the [hardened flow](flows.md#hardened). A line's own bare `--card-seed` or
`--key-seed` asks for that seed for that line alone. The process options `--log-level`,
`--plumbing` and `--config` are fixed when the program starts, so a line cannot change them.

Where a ceremony is installed at `/etc/mind-the-gap/ceremony`, as on an [image built with
one](image.md), `mind-the-gap` without a verb runs its first recipe and then opens the session,
which keeps the seeds the ceremony asked for and is where a failed step can be looked into.

## One-shot commands

```
MIND_THE_SEED="<24 words>" mind-the-gap publish -n 'Jane Doe' -m jane@example.org --to certs/
```

Here a command takes its seeds from `--seed` (or `--card-seed=PHRASE`, `--key-seed=PHRASE`)
or their variables, and fails without them: a one-shot invocation never stops on a prompt for
data, so a script cannot hang. The error names the flag and the variable that would have
given what was missing. What the options alone decide (a name, the emails, a validity without
a date, a slot without `--key decryption`, the pins a pin change takes) is judged before any
seed is stretched, and told all at once, so a command that cannot run fails at once rather
than after a derivation. Three things still interact:

- the confirmation before a card is written, which names the card, comes only after the card
  was found fit, and is answered from the terminal, never from piped input; `--yes` gives it
  in advance, and without a terminal and without `--yes` the command aborts rather than hang;
- the `generate` write-down ceremony;
- the physical touch some cards demand.

`set` alone shows the defaults here as in a session, with the config files it read. Across
runs defaults live in the [config file](configuration.md#config-files), so here `set --save`
and `unset --save` change that file, while `set` and `unset` without it, and `quit`, which
change a session alone, are refused.

A session whose stdin is piped from a script never prompts either, exactly like a one-shot
command. It reports each failing line without stopping, then exits with an error that counts
them, so `mind-the-gap < steps && …` holds only when every line went through.

## Plumbing mode

For automation, mind-the-gap has a mode a program can read rather than a person:

```
mind-the-gap --plumbing pin --app piv --card 20381784
{"command":"pin","ok":true}
```

`--plumbing` (or `MIND_THE_PLUMBING=true`) changes three things:

- **stdout carries one JSON object per command** and nothing else:
  `{"command":"<verb>","ok":true}`, or `{"command":"<verb>","ok":false,"error":"<message>"}`
  with the whole chain of causes in the message, and what the command found (see below).
  Everything a command would print for a person goes to stderr instead, next to the log, and
  `--to -` is refused: material goes to a file.
- **Nothing prompts.** Not for a seed, a pin or a name, not on a piped stdin and not on the
  terminal either: a missing secret is an error that names the flag and the variable that
  give it, and a confirmation has to be given in advance with `--yes`. `generate`, which shows
  a phrase to a person, refuses.
- **The first error stops.** A session fed from stdin, or a ceremony, stops at the first
  failing command rather than reporting it and going on. The exit status is non-zero when
  anything failed.

Most commands report only how they went. The two that look rather than act report what they
found, in the same object:

- `list` adds `cards`: one entry per reader, with its `applets`, each with the `applet`
  (`PIV` or `OpenPGP`), the `card` (serial or identifier), the `owner` verdict where a card
  seed was given, the `holder` the card names, and its `keys`, each with its `slot`, the
  `fingerprint`, the certificate's `subject` for PIV, and whether it is the key seed's
  (`ours`).
- `check` adds the record (`seed_id`, or `card_seed_id` and `key_seed_id` apart, `piv_root`,
  the SHA-256 of the root of the algorithm in use, and `pgp_identity`) and, with a card, its `reader` and one verdict per applet, with the
  mismatches as its `error`.

```
mind-the-gap --plumbing list --app piv
{"command":"list","ok":true,"cards":[{"reader":"Yubico YubiKey CCID 00 00","applets":[{"applet":"PIV","card":"20381784","owner":"initialized by this card seed","holder":null,"keys":[...]}]}]}
```

Text a card shows (a subject, a cardholder name) is the card's, untrusted; the report carries
it as it is, escaped only as JSON escapes strings, where the text output escapes it for the
terminal.

The secrets come from the documented variables, as for any one-shot command: the seeds from
`MIND_THE_SEED`, `MIND_THE_CARD_SEED` and `MIND_THE_KEY_SEED`, the pins from `MIND_THE_PIN`
and `MIND_THE_CURRENT_PIN`. The main use is a host that looks after its own card, such as an
[unattended host](unattended-host.md#the-hosts-pin) rotating its user pin: `pin` with the
current pin needs no seed, so the host never holds one.

## How secrets are asked for

Only the interactive session asks, on the terminal with no echo, as
[above](#the-interactive-session): for each seed and its password once, for a pin whenever a
command needs one. One-shot commands, piped sessions and plumbing mode ask for nothing and take
secrets from their flags and variables ([secrets](configuration.md#secrets)). What may never
appear on a line, in the history, a config file or a ceremony is the [security
chapter](security.md#secrets-stay-out-of-the-history-the-config-and-the-log)'s to say.

What happens when an input is missing follows one principle. Verification degrades quietly:
`check` without a pin skips the pin. Provisioning degrades loudly: `init` without a pin keeps
the factory pin and says so, `ungap` without one writes the keys unencrypted and says so. A
missing identity is an error, never a guess. Public material falls back to QR codes on the
screen when no `--to` is given; secret material is never written to stdout.

## What each channel exposes

Know what the one-shot interface exposes before putting a real seed through it:

- **Command line arguments** are visible to every process on the machine through `ps`, and
  persist in shell history.
- **Environment variables** can be read from `/proc/<pid>/environ` by the same user, and are
  inherited by every child process.
- A pin passed as **`--pin`** is exposed the same way, and in a session it enters the
  session's in-memory history.

On the air-gapped image, where nothing else runs and nothing persists, these channels are
mostly moot; anywhere else, take care of them first, for example by sourcing the seed from a
protected file into a variable that is never exported. The [security
chapter](security.md#secrets-stay-out-of-the-history-the-config-and-the-log) covers the
session, the config and the log.
