# Compatibility and upgrading

A derivation scheme is a promise: within a major version, the same phrase and options
re-derive the same keys, credentials and certificates forever. The argon2 parameters, the
label grammar, the scheme stamp and the hash generation behind them are frozen constants of
the scheme, and the golden vectors in the test suite are the promise in executable form.

## The scheme and the version

**The crate's major version tracks the scheme.** Every 0.x release derived under `mtg0`; 1.x
derives under `mtg1`. Within a major the derivation never moves, which is the whole point, and
the golden vectors in the test suite pin every label, credential and certificate.

A change to anything that moves a key, a credential or a certificate ships as a new scheme
behind a new major version, and the scheme before it stays available, as `mtg0` does now.
Everything else (commands, options, output) follows ordinary versioning.

## mtg1, the 1.x releases

The scheme of the 1.x releases is `mtg1`, as the [key derivation](derivation.md) chapter
specifies it. It took its final form with the first release candidate, 1.0.0-rc.1: builds of
the 1.0 branch before it, which were never released, derived differently under the same
stamp, and their golden vectors were replaced rather than kept. The stamp stayed `mtg1:`,
since no release ever derived anything else.

### Cards provisioned before 1.0.0-rc.1

The card seed and the key seed, the credentials bound to each card's serial, the derived puk,
the generation step, the shared decryption key and the certificate serial rule all changed
what those builds derived. What carries over is the identity: the OpenPGP primary key and the
PIV root authority's key derive as before, so the OpenPGP fingerprint stays and the PIV trust
anchor keeps its key, though its certificate is issued again under the new serial rule and its
digest changes. A device's signing and authentication keys without a date also derive as
before. What moves is everything a card is administered with (credentials and identifiers,
now bound to its serial) and the decryption key, which is now the identity's, the same on
every card.

So every card such a build provisioned is provisioned again, as a new generation:

1. `init` the card with the new tool. The reset does not need the old credentials: it spends
   the pin's and puk's tries, which any card allows.
2. `upload --date YYYY-MM-DD`, so that every key on the card is new, and `publish` the
   certificates.
3. Revoke the old build's subkeys of each card with the old build itself,
   `pgp revoke --kind subkeys -k <id>`, and publish that too.

The date in step 2 is not optional. Without it, the device's signing and authentication
subkeys derive as they did under the old build, so those subkeys would be the very keys the
card holds again, and a revocation cannot be taken back.

## mtg0, the 0.x releases

OpenPGP cards provisioned by the 0.x releases keep working, unchanged, with `--legacy`: the
same keys, the same admin pin, the same certificates, from one seed. That scheme, `mtg0` by
convention, is frozen exactly as it was: one seed for everything, labels made of sequence
bytes and key flag values, the admin pin derived from the subkey id rather than the card, no
card identifier and no stamp. It only ever derived Curve25519 keys, so it refuses
`--algorithm`.

`check --legacy` recognises such a card by its keys, and `upload --legacy` writes to it under
its legacy admin pin. A card moves to `mtg1` with `init`, then `upload`, without `--legacy`;
`init --legacy` is refused, since `init` installs what the current scheme derives.

## Upgrading from 0.x

The command line changed with the scheme, and some of what a 0.x script or profile still
carries now means something else:

- **Verb first.** A 0.x command named the applet first, `mind-the-gap pgp upload`; a 1.x
  command names the verb, with the applet an option, `mind-the-gap upload --app pgp`, and
  without `--app` acts on both. `status` is now `list`, `certify` is `publish`, and `export`
  is `ungap`; `check`, `upload`, `revoke` and `trust` kept their names. A card is initialized
  with `init` before `upload` puts the identity's keys on it.
- **PIV cards start over.** `--legacy` is OpenPGP's alone, so a PIV card provisioned by 0.x
  has no legacy path: it is initialized and uploaded again under `mtg1`, which gives the
  identity a new PIV root authority, and every relying party replaces the old root in its
  trust store with the new one (`publish --app piv --part identity`).
- **`--date` kept its name and changed its meaning.** In 0.x it was the creation date of the
  OpenPGP primary key, or of the PIV certificates. Under `mtg1` it is the
  [generation](derivation.md#the-key-path), a step of the derivation, and under `--legacy`
  the subkeys' creation time. A `MIND_THE_DATE` left in a profile or a CI environment
  therefore derives other keys without a word: unset it, and give the identity's date as
  `--identity-date` (`MIND_THE_IDENTITY_DATE`). For an OpenPGP card kept under `--legacy`,
  the old `--date` is now `--identity-date` and the old `--subdate` is now `--date`;
  `MIND_THE_SUBDATE` went with `--subdate`.
- **No seed, no command.** 0.x derived from a random phrase when none was given; a command
  that derives now fails without its seed, and only `generate` mints one.
- **Renamed options and parts.**
  - `-o`/`--output` is `-o`/`--to`.
  - `--qr` is gone: a verb shows QR codes wherever `--to` is omitted.
  - `upload --output` and `upload --qr` also wrote the OpenPGP certificate; `upload` now
    writes to the card alone, and `publish` writes the certificate.
  - `certify --kind`: `generic` (the default) and `full` are `publish`, whose `--part all`
    is the default; `uids` is `--part identity` and `subkeys` is `--part keys`; `primary` has
    no counterpart. PIV's `certify`, which wrote the root authority, is `publish --app piv
    --part identity`.
  - `trust --input FILE --kind LEVEL` is `trust FILE --level LEVEL`.
  - `revoke --text` is `--reason`, and `revoke` requires `--kind`: 0.x revoked the whole
    certificate, as `--kind certificate` does now.
  - `--card` took a serial alone; it now also takes an OpenPGP identifier or a reader name
    ([which card is which](multiple-cards.md#which-card-is-which)).
- **Short flags that went.** `-q` (`--qr`); `-t` (`certify --kind`, `trust --kind`, `revoke
  --text`); `-i` as `trust --input`, now `--pin` alone; and `-c` as `revoke --code`, now
  `--card`, which `revoke` does not take. The others kept their letters.
- **One name per option.** Every option is now also a config key, a `set` name and a
  `MIND_THE_*` variable of the same name ([options](configuration.md)).
