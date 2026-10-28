# Options

An option has one name. `--subkey` on the command line is `subkey` in the config file, `set
subkey=laptop` in a session or a ceremony, and `MIND_THE_SUBKEY` in the environment. Each
option means the same on every verb that takes it, so a default set once applies wherever it
makes sense, and nothing has to be learnt twice. On the machine, `mind-the-gap <verb> --help`
and `man mind-the-gap-<verb>` (`man mind-the-gap-upload`) list a verb's options with what each
does; the [option reference](options-reference.md) lists every verb's, with its default and its
variable.

## The settings

An option with a variable is a setting: it can be a default, from a config file, a `set` or
the environment, and a default for an option a verb does not take is simply not used by it.
`set --help` lists the settings, grouped as a verb's help groups its options: the card, the
derivation (`algorithm`, `legacy`, `subkey` and `date`), the identity the certificates name,
the keys to act on, and the ceremony file and record of `run`.

A setting that is on or off (`legacy`, `intermediate`, `fixed-touch`, `no-msroots`) takes
`true` or `false` as a default; on the command line its flag turns it on.

A validity counts on the calendar from midnight UTC of the day the keys were created, their
`date`: `2y` from 2026-01-01 ends at 2028-01-01T00:00:00Z, and `6mo` from 2026-03-15 at
2026-09-15. A month that lacks the day ends the validity on its last day, so `1mo` from
January 31st ends on the last day of February, and `1y` from February 29th on February 28th.
Minutes, hours and seconds are refused: no certificate is planned in them, and `24m` is more
likely meant as two years than as twenty-four minutes.

Everything else is never a default: what belongs to one command (`--yes`, `--dry-run`, `--to`,
and a verb's own, such as `publish --part` or `revoke --kind`), the process options, which
hold for the whole run and which a session line cannot change, and the [secrets](#secrets).
[Commands](commands.md) says what each does on its verb.

The log is coloured where it goes to a terminal; `MIND_THE_LOG_STYLE` takes `always` or `never`
instead of that `auto`, and `NO_COLOR` turns colour off as well.

## Secrets

The seeds, their passwords and the pins are options too, so that scripts and experts can
pass them, but never defaults: no config file, no `set` and no ceremony can hold one. Each has
its variable, as for any option (the [option reference](options-reference.md#every-verb) lists
them); `rotate` takes the key seed it moves off as `--from-key-seed`, and `pin` the current
pin as `--current-pin`.

The seed flags other than `--seed` take their phrase after an equals sign, because without a
value they mean "ask me": `--key-seed` alone asks for the key seed in a session. See [what
each channel exposes](interfaces.md#what-each-channel-exposes) before passing a real one.

## Config files

Defaults across runs live in TOML files, a table of settings, with a table of its own for
each applet's half of a command:

```toml
# ~/.config/mind-the-gap/config.toml
name = "Jane Doe"
emails = ["jane@example.org"]
policy = "strict"
intermediate = true

[pgp]
algorithm = "rsa2048"
```

Two files are read, the second over the first:

1. `/etc/mind-the-gap/config.toml`, the system's. On the live image it is written from the
   image's NixOS configuration (`programs.mind-the-gap.config`, see [building an
   image](image.md#the-nixos-module)) and is read-only, so an image built for a team carries
   the team's defaults, and nobody at the keyboard changes them by accident.
2. `$XDG_CONFIG_HOME/mind-the-gap/config.toml` (`~/.config/mind-the-gap/config.toml` by
   default), the user's; `--config FILE` (or `MIND_THE_CONFIG`) reads another file in its
   place.

`mind-the-gap set` shows which of them were read, and every default in force behind the layer
it comes from.

A file names only settings: an unknown name, a secret or a per-command option is an error
that names the file, rather than a default silently ignored.

### Writing it

`set --save` writes defaults into the user's file (or the one `--config` names) as well as
setting them, and `unset --save` takes them out again; on the command line they are the way
to change the file, in a session they change the session and the file at once:

```
mind-the-gap set --save name='Jane Doe' emails=jane@example.org pgp.algorithm=rsa2048
mind-the-gap unset --save pgp.algorithm
```

Each value goes through its option's own parser first, and the same rules as for a file hold,
so a secret, an option of one command or a typo is refused and the file is left as it was.
The file is created readable by its owner alone, with a comment at the top; an existing one is
edited line by line, a setting's line taking the new value with its comment, a new setting
going after the last of its table, and everything else kept as it was; an edit that would
change any other default is refused. Control characters are written escaped, as `\uXXXX`. A
file `--config` names that is not there yet is created like the user's, which no other
command does: they refuse a `--config` file that is missing. The image's file is never
written, and neither is a file that is a link to one kept elsewhere, nor one its owner may not
write. A ceremony cannot save: its settings last as long as it does.

## Each applet's own defaults

A setting in `[piv]` or `[pgp]` is a default for that applet's half of a command alone; TOML's
dotted keys say the same, `pgp.algorithm = "rsa2048"`, and so does `set pgp.algorithm=rsa2048`
in a session. A command that acts on both applets takes each half's options from its own
table over the general settings, so the file above uploads Curve25519 keys to nothing and
RSA-2048 keys to the OpenPGP applet, while PIV keeps its P-256. A flag is the same on
both halves and beats both tables.

The algorithm is what the tables are for: the cards differ in what each applet can hold, a
YubiKey 4 P-256 and P-384 in PIV but only RSA in OpenPGP, Gnuk only Curve25519 and no PIV at
all. [Supported cards](supported-cards.md#choosing-an-algorithm-per-applet) says which card
takes which.

## Precedence

From strongest to weakest, for a command:

1. the option on the command line, the session line or the ceremony step;
2. in a session or a ceremony, a `set`, for the applet's own table before the general one;
3. the option's environment variable;
4. the user's config file, the applet's own table before the general settings;
5. the system's, which is the image's on the live image, in the same order;
6. the built-in default.

A session reads the environment once, when it starts, and parses its lines without it, so
that a variable read again on every line can never undo a `set`. The pins' variables are the
exception: they are no setting, and stay in force for every line. A ceremony's `set` lasts as
long as the ceremony.
