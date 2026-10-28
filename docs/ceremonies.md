# Ceremonies

A key ceremony is a written procedure, followed step by step, that leaves a record. A
ceremony file is that procedure in a form mind-the-gap runs: named recipes of commands, each
run after the recipes it depends on, every step shown before it runs, and the whole run
stopped at the first step that fails.

## The file

Laid out like a justfile. A recipe starts at the left margin with its name and, after a
colon, the recipes that run before it. Its steps follow, indented, one command line each,
exactly as a [session](interfaces.md#the-interactive-session) takes them. `#` starts a comment.

```
# A device card: the card, its keys, its public half
device: card keys publish

card:
    set policy=strict
    init

keys: card
    upload
    check

publish: keys
    publish --to /media/usb/certs/
    publish --format ssh --to /media/usb/ssh/
```

- Recipe names are lowercase letters, digits and hyphens. The first recipe is the one `run`
  runs without a name.
- A recipe runs once in a run, however many recipes depend on it, and dependencies run in the
  order they are listed. A cycle, a missing dependency or a recipe defined twice is refused
  before anything runs.
- A step is any verb but `run`: a recipe that needs another lists it as a dependency.
- `set` and `unset` in a step last as long as the ceremony. A ceremony asks for pins and
  seeds, but not for a name or emails: give those in a `set` step or the config file, so the
  procedure says who it provisions.
- A ceremony file holds no secret. A step that names a seed, a password or a pin is refused:
  the seeds and pins are asked for when a step needs them, or come from the environment.

A card that needs its own order of steps gets a recipe of its own. Gnuk takes a new user pin
only once it holds keys, so its recipe sets the pin last, with the card seed rather than the
factory pin; in a session the step asks for the new pin, twice:

```
gnuk:
    init --app pgp
    upload --app pgp
    pin --app pgp --reset
```

## Running one

```
mind-the-gap run                       # the first recipe of the default file
mind-the-gap run publish               # one recipe and what it depends on
mind-the-gap run --ceremony team.mtg card
```

Without `--ceremony` the file is `$XDG_CONFIG_HOME/mind-the-gap/ceremony` (by default
`~/.config/mind-the-gap/ceremony`), then the system's `/etc/mind-the-gap/ceremony`. Tab
completion in bash, zsh and fish offers the recipes of the file `run` would read, a
`ceremony` default in a config file included, from the files alone. Each step
is shown as `==> [3/6] keys: upload` before it runs. A failing step stops the ceremony with
the file and line it came from, and nothing after it runs; the steps before it stay done, and
since every writing verb writes only what differs, running the ceremony again picks up where
it stopped.

A ceremony runs in the session that started it: `run` inside an interactive session uses the
seeds it holds and asks for the ones it lacks, while a one-shot `mind-the-gap run` asks for
nothing and takes the seeds from the environment.

## Trying one first

```
mind-the-gap run --dry-run
```

shows every step, runs the read-only ones (`list`, `check`, `set`, `unset`), and hands
`--dry-run` to the steps that write to a card (`init`, `upload`, `rotate`, `pin`, `wipe`,
`revoke`), which then show what they would write. The remaining steps (`publish`, `ungap`,
`trust`, `generate`) are listed and not run.

```
mind-the-gap run --check
```

goes one step further back and runs nothing at all: it reads the whole file, plans every
recipe (an unknown dependency or a cycle is an error), refuses a step that holds a secret or
runs another ceremony in any recipe, and lists the file's recipes with what each depends on,
then the steps of the one asked for:

```
Recipes: device (card keys publish), card, keys (card), publish (keys)
[1/5] card: set policy=strict
...
```

It needs no seed and touches no card, so it is how to look at a ceremony before a card is
attached. A recipe the file does not have is an error that names the ones it does.

## Keeping a record

```
mind-the-gap run --record /media/usb/records/
```

writes a transcript into the directory, `ceremony-<time>.log`: the tool's version as
`mind-the-gap --version` gives it (the release, the derivation scheme its keys come from and,
on a released image, the source revision it was built from), the ceremony file's path and
SHA-256, the recipe, then every step with the time it ran, every log line it printed, and
whether it finished or failed. The transcript never holds a secret,
by the same rule that keeps secrets out of the log; what it holds is what an auditor of a key
ceremony asks for: which procedure was followed, by which tool, and what happened at each
step. Output a command prints on stdout, such as the plan an `upload` shows, is not part of
the transcript: the log says what was written.

## On the live image

An image built with a ceremony carries it read-only at `/etc/mind-the-gap/ceremony`, checked
with `run --check` when the image is built, and `mind-the-gap` without a verb runs its first
recipe before it opens the session. [Building an image](image.md) shows how.
