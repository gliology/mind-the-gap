# Commands

Every command is a verb, with the applet an option: `mind-the-gap <verb> [options]`, or the
same line without the program name in a session or a ceremony (see [the session and the
command line](interfaces.md)). Without `--app`, a verb that talks to a card acts on every
applet the card carries, PIV and OpenPGP, and leaves out an applet the card lacks; `--app piv`
or `--app pgp` names one, and then a card without it is an error. A verb that only derives
(`publish`, `revoke`) produces both applets' material unless told otherwise.

Every option means the same on every verb that takes it, and doubles as a config key, a `set`
name and an environment variable: see [options](configuration.md). The [option
reference](options-reference.md) lists every verb's options with their defaults and variables,
as `mind-the-gap <verb> --help` and the verb's man page, `man mind-the-gap-<verb>`
(`man mind-the-gap-upload`), say them on the machine. The options that recur:

- `--card` names the card, by a PIV serial, an OpenPGP identifier (`0006:12345678`) or a
  reader name, as `list` shows them; without it the verb takes the one card attached, and
  refuses to guess between several.
- `--subkey` and `--date` say where the keys sit under the key seed: the device and the key
  generation ([derivation](derivation.md#the-key-path)).
- `--key` and `--slot` narrow a verb to some of the usable keys, and put the decryption key
  into a retired PIV slot.
- Every verb that writes to a card takes `--dry-run`, which shows what would be written, and
  `--yes`, which answers the confirmation in advance.
- Every verb that writes out of the gap takes `--to`: a file, a directory (which `publish`
  fills with one file per piece), or `-` for stdout. Without it, the material is shown as QR
  codes on the terminal. Secrets and OpenPGP revocations never go to stdout, and files
  holding them are readable by their owner alone; the PIV revocation lists are public, made
  to be published.

Which seed a verb takes:

| verb | card seed | key seed |
|---|---|---|
| `generate`, `run`, `set`, `unset`, `quit`, `wipe --force` | | |
| `list` | if known | if known |
| `check`, `upload`, `rotate` | yes | yes |
| `init`, `wipe` without `--force`, `pin --reset` | yes | |
| `pin` | | |
| `trust`, `revoke`, `publish`, `ungap` | | yes |

One phrase given with `--seed` (or asked for in a session) is both seeds; `--card-seed` and
`--key-seed` give either apart.

## generate

```
mind-the-gap generate
```

Mints a 24 word phrase from the kernel's entropy and shows it on the terminal's alternate
screen until a quiz proves it was written down, then wipes the screen. In a session it asks
for the phrase's password and keeps the new seed for the commands that follow. Last it prints
the seed id, which is public: written down with the phrase, it is what `check` is compared
with to tell a mistyped phrase or password from the right one. It is the only command that
ever mints a seed.

## list

```
mind-the-gap list
```

Every attached card by reader, with its applets, their serial or identifier and the
certificates and keys they hold. With a card seed at hand, each applet says whether that card
seed initialized it; with a key seed, which keys are its own at the chosen `--subkey` and
`--date`. It reads only what a card shows without a pin and leaves every card as it was found,
so it spends no pin try, asks for no touch, and is safe while other programs use the cards.
In a session it uses the seeds the session holds and never asks for one.

The verdicts:

- **initialized by this card seed**: the card seed derived the identifiers this card carries,
  so its credentials open the card.
- **holds keys of this seed, administrator unknown**: an OpenPGP card without room for the
  card identifier, holding the key seed's keys. Who administers it cannot be read off it; a
  verb that writes to it trusts the card seed, at the cost of an admin pin try if wrong.
- **not initialized by this card seed**: another card seed, or another tool.
- **blank**: nothing on the card to judge by.

## check

```
mind-the-gap check [--card CARD] [--pin PIN]
```

First the record: the seed id (or the card seed's and the key seed's apart), the SHA-256 of
the PIV root authority and the fingerprint of the OpenPGP primary key. Keep them with the
phrase, and compare them whenever the phrase is typed in again: a mistyped password derives
another seed without a word, and this is where it shows.

Then, where one card is attached or `--card` names one, the card. With the card seed: whose
card it is, its management key or admin pin, its CHUID, CCC and 9E certificate. With the key
seed: the chosen keys and their certificates, byte for byte, and the PIV authorities in
`msroots`. `--pin` checks the user pin too, held to each applet's rule (see [pin](#pin)):
a pin one applet cannot take is refused where that applet is named with `--app`, and
otherwise left out of its comparison with a warning. Pin and touch policies that differ from `--policy`
are warned about rather than failed, since the keys are still right. `check` never writes;
on OpenPGP it compares the fingerprints before it spends an admin pin try.

A card without PIV GET METADATA (YubiKey 4, YubiKey 5 before 5.3) cannot report the keys
and policies its slots hold, so `check` compares differently there:

| | card with GET METADATA | card without |
|---|---|---|
| slot public keys | read back and compared with the derived ones | proven by a signature challenge: the card signs a fresh random digest, which has to verify under the derived public key |
| pin and touch policies | read back, a mismatch warns | not verifiable on this card (warned once) |
| management key touch | read back, a mismatch warns | not verifiable |

The signature challenge is as conclusive as a read-back: only the derived private key can
produce a signature that verifies under the derived public key. It needs `--pin` for every
slot whose pin policy is not `never`; without it, `check` warns that those keys cannot be
verified on this card.

## init

```
mind-the-gap init [--card CARD] [--pin PIN] [--policy POLICY] [--algorithm ALGORITHM]
```

Resets the card's applets and gives each what the card seed derives for this card, bound to
its serial:

- PIV: the management key (`--management-algorithm`, AES-256 where the firmware takes it),
  the puk, the CHUID and CCC, and the card authentication key in 9E with a certificate of its
  own; then the user pin, and the management key's touch requirement as `--policy` asks;
- OpenPGP: where `--kdf` asks for it, the KDF data object, so that the card takes its pins
  as iterated and salted SHA-256 hashes; then the admin pin, the card identifier in data
  object 0102, the language preferences (`--lang`, English where omitted), and the user pin.

No key of the identity's: `upload` adds those. Before anything is erased, `init` opens the
card, refuses one that cannot hold what is asked of it, and asks for confirmation naming it.
Without `--pin` the card keeps the factory pin `123456` and `init` says so; a session asks for
the pin instead. Gnuk takes a new user pin only once it holds keys: there `init` leaves the
factory pin and says to change it with `pin` after `upload`.

`--algorithm` chooses the PIV 9E key's algorithm here; the keys `upload` adds take it from
their own `--algorithm`.

`--kdf auto` (the default) sets up the KDF data object on a Gnuk, which keeps its keys
wrapped under the pin and, as Gnuk 2 ships, imports no key without one. `--kdf on` sets it
up on any card that offers it (YubiKey 5, OpenPGP card 3.3 and later) and refuses one that
does not; `--kdf off` never does. With it the pin never crosses the reader in the clear, but
every program that asks for the pin has to hash it: gpg does, OpenKeychain does not yet.

## upload

```
mind-the-gap upload [--card CARD] [-k SUBKEY] [-d DATE] [--key KEYS] [--slot SLOT]
```

Puts the key seed's keys and certificates onto a card the card seed initialized. It compares
the card with what the seeds derive, lists what differs, asks, writes exactly that under the
card's derived credentials, and reads the card back to prove it holds what was derived. So
the same verb provisions a freshly initialized card, re-certifies after a change of name,
emails or validity, applies another `--policy`, adds a key from another key seed, and
repairs a certificate that went missing. It never erases what it does not list.

- `--key` writes only the named keys (`authentication`, `signature`, `decryption`); the
  others stay as they are.
- `--slot 82` to `--slot 95` puts the decryption key into a retired PIV slot instead of 9D,
  for a previous generation's key or another identity's. Retired keys fill the slots from 82
  up, as middleware reads them, so a slot with an empty one below it is refused in favour of
  the first free one.
- Without `--policy`, keys already on the card keep their policies; a key going onto the card
  gets `--policy` or the default. With `--policy` every chosen key is brought to it, which on
  PIV means importing the same key again, and the management key's touch follows.
- `--lang`, `--url` and `--login` write the OpenPGP cardholder data, `--name` the cardholder
  name.
- The PIV authorities go into `msroots` only when the whole identity goes onto the card, so a
  key from another key seed never replaces them; `--no-msroots` deletes them.

A card the card seed did not initialize is refused before anything is spent on it.
Another algorithm than the card holds means other keys throughout, which takes `init` first.

## rotate

```
mind-the-gap rotate --date DATE [--card CARD]
mind-the-gap rotate --from-key-seed [--date DATE] [--card CARD]
```

Moves a card to a new key generation, or off a key seed that leaked. `rotate` reads the
generation the card holds off the card (the 9D certificate's start, the OpenPGP decryption
key's creation time), derives that generation from the previous key seed where
`--from-key-seed` gives one, and then:

- on PIV, keeps the previous decryption key with its certificate in the first free retired
  slot, so that what was encrypted to it stays readable, before it uploads the new
  generation;
- on OpenPGP, which has one decryption slot, uploads the new generation, and says that the
  previous decryption key leaves the card: `ungap --date <previous>` exports it for decrypting
  in software.

The order makes an interrupted rotation safe to repeat. Publish the new certificates
afterwards, and revoke the previous generation's with `revoke --kind subkeys --date
<previous>`. See [rotation, revocation and recovery](rotation.md).

## pin

```
mind-the-gap pin [--card CARD] [--app APP]
mind-the-gap pin --reset [--card CARD] [--app APP]
```

Changes the card's user pin. Without `--reset` the card checks the current pin
(`--current-pin`, or a session asks), and no seed is involved: this is the verb a host runs on
its own card. With `--reset` the new pin is set with what the card seed derives for the card,
the puk on PIV and the admin pin on OpenPGP, so a forgotten or blocked pin is replaced without
a reset and without touching a key. A PIV pin is 6 to 8 ASCII characters; an OpenPGP card
takes at least 6 and says how many at most.

Without `--app` both applets get the new pin, and both are expected to take the same current
one; name one with `--app` where they differ.

## wipe

```
mind-the-gap wipe [--card CARD] [--force]
```

Resets the card's applets and gives them nothing: the PIV applet ends up with the factory pin,
puk and management key, the OpenPGP applet with the factory pins. For retiring a card or
handing it on. `wipe` refuses a card the card seed did not initialize unless `--force` says it
may be anyone's, and asks before it erases, naming the card.

## trust

```
mind-the-gap trust FILE [--level LEVEL] [--to PATH]
```

Certifies the user ids of another OpenPGP certificate with the key seed's identity: a
colleague's after checking their fingerprint, a team's or a host's that you vouch for.
`--level` says how well the claim was verified (`generic`, `persona`, `casual`,
`positive`). The certified certificate goes to `--to`, or a QR code.

## revoke

```
mind-the-gap revoke --kind subkeys [-k SUBKEY] [-d DATE] [--key KEYS]
                    [--code CODE] [--reason TEXT] [--to PATH]
mind-the-gap revoke --kind certificate [--code CODE] [--reason TEXT] [--to PATH]
```

Revokes, from the key seed alone, without the card:

- `--kind subkeys`: this device's keys of this generation. OpenPGP gets the certificate with
  revocation signatures on those subkeys; PIV a revocation list signed by the identity's root
  authority. The decryption key is the identity's, on every card, so revoking one device
  leaves it standing; `--key decryption` alone revokes it instead.
- `--kind certificate`: the whole identity. OpenPGP gets the revocation of the primary key;
  PIV a list revoking every key's certificate.

`--kind` has no default, since a revocation cannot be taken back. `--code` is the reason
(`0` unspecified, the default, `1` superseded, `2` compromised, `3` retired) and `--reason` a
text for it. An OpenPGP revocation is a capability, so it is written like a secret: to a file
of the owner's, or the alternate screen. A PIV list is public, written as PEM
(`piv-revocation-p256.crl.pem` in a directory, named by the algorithm), and keeps every
revocation the list already at `--to` holds; it names the certificates as `upload` issued
them, so it takes the same identity options. [Revocation](rotation.md#revocation) explains both, and what a
published list needs.

## publish

```
mind-the-gap publish [--part PART] [--format FORMAT] [--to PATH]
```

Writes the identity's public material out of the gap.

| `--format` | PIV | OpenPGP |
|---|---|---|
| `text` (default) | the certificates as PEM, `piv-chain.pem`; the lists as PEM, `piv-revocation-p256.crl.pem` | the armored certificate, `pgp.asc` |
| `binary` | one DER file per certificate; the lists as DER, `piv-revocation-p256.crl` | the binary certificate, `pgp.gpg` |
| `ssh` | the 9A key as an OpenSSH line, `piv-authentication.pub` | the authentication subkey, `pgp-authentication.pub` |
| `wkd` | | a Web Key Directory, `<domain>/hu/<hash>` and `<domain>/policy` per email domain, as `gpg-wks-client --install-key` lays it out |

`--part identity` is the identity alone (the PIV root authority, the OpenPGP primary key with
its user ids), `--part keys` the chosen keys alone; `all` is both. `--part crl` is the PIV
revocation list as it stands: the one at `--to` signed again with a new date, or an empty one,
and with `--intermediate` the issuing authority's own list beside it, each file named by the
suffix of its URL; `--format binary` writes them as the DER a server hands out (see
[revocation](rotation.md#piv)). Several pieces need a directory: `--to certs/`. Each device
publishes its own subkeys, and the certificates merge wherever they are imported, into one
identity with every device's keys.

## ungap

```
mind-the-gap ungap --pin PASSPHRASE --to keys/
mind-the-gap ungap --app piv --key decryption --date PREVIOUS --pin PASSPHRASE --to old/
```

Writes secret keys out of the gap, encrypted under `--pin`, for decrypting in software or for
escrow: the one verb whose output can sign and decrypt without a card. Without `--pin` the
keys are written unencrypted, with a warning. The keys are written owner-only, and never to
stdout.

- OpenPGP: the primary and the chosen subkeys, as one armored secret key certificate,
  `pgp-secret.asc`.
- PIV: each chosen key as PKCS#8 (`piv-<key>.key.pem`) next to its certificate
  (`piv-<key>.pem`), encrypted with PBES2, PBKDF2-HMAC-SHA256 and AES-256-CBC, which is what
  `openssl pkcs8 -topk8` writes. A mail client imports the pair as PKCS#12:
  `openssl pkcs12 -export -inkey piv-decryption.key.pem -in piv-decryption.pem -out
  decryption.p12`. That is the way to read mail encrypted to a decryption key no card holds
  any more.

Unlike everything else here an export is not derived: its salt and IV are random, so each
one is a different file with the same key inside.

## run

```
mind-the-gap run [RECIPE] [--ceremony FILE] [--record DIR] [--dry-run | --check]
```

Runs a recipe of a [ceremony](ceremonies.md) and the recipes it depends on. `--dry-run`
shows the steps and what the writing ones would write; `--check` checks the whole file and
lists the steps without running any, touching no card and asking for no seed.

## set and unset

```
mtg> set subkey=laptop policy=strict
mtg> set
mtg> unset policy
mind-the-gap set
mind-the-gap set --save name='Jane Doe'
```

Session defaults, by the options' long names, checked by each option's own parser as they are
set; `set --help` lists the names, grouped as a verb's help groups the options, and a name that
is none is answered with the closest one. `set` alone shows the defaults, in a session and on
the command line alike: first the config files consulted, the image's and the user's, each
read or absent, then the state of the seeds (never a seed), then every default in force behind
the layer it comes from, `image`, `user`, `environment` or `set`, as
[precedence](configuration.md#precedence) orders them:

```
Config files:
  image  /etc/mind-the-gap/config.toml (absent)
  user   /home/jane/.config/mind-the-gap/config.toml (read)
Seeds:
  seed       asked for when needed
  card seed  the seed
  key seed   the seed
Defaults:
  user         name = Jane Doe
  user         pgp.algorithm = rsa2048
  set          subkey = laptop
```

`unset` forgets the default in force and goes back to the one beneath it: the environment's, a
config file's, or the built-in one. Without `--save` setting and forgetting belong to a session
or a ceremony; `set --save` and `unset --save` change the user's [config
file](configuration.md#writing-it) too, which is how the command line changes defaults across
runs.

## quit

```
mtg> quit
```

Leaves the session, like Ctrl-D, and the seeds it held go with it. On the command line it is
refused, there being no session to leave, and so it has no man page and no place in
`mind-the-gap --help`.
