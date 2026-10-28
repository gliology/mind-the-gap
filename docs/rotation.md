# Rotation, revocation and recovery

A card is initialized once and then changed in place: new certificates, new policies, a new
key generation, a new pin. Keys that are done with are revoked, from the key seed alone. Nothing
in this chapter resets a card, so nothing in it can lose what the card holds.

## Changing what a card holds

`upload` is the one verb for writing the key seed's keys and certificates, whether the card
holds nothing yet or everything already. It compares the card with what the seeds derive under
the options given, lists the differences, one write per line, asks, writes exactly those under
the card's derived credentials, and reads the card back to prove it holds what was derived. So
a change of name or emails, a longer `--validity`, an `--intermediate`, another `--policy`, a
certificate gone missing: each is the same command with the new options.

```
mtg> upload --validity 5y --dry-run
mtg> upload --policy strict
```

What it compares is all public (slot metadata, certificates, fingerprints, touch flags), so the
list is made, shown and confirmed before any credential is used, and made again right before
the writes, so a card swapped in between is not written blind.

**Policies stay unless you ask.** Without `--policy`, keys already on the card keep their pin
and touch requirements: changing a date never quietly adds or drops a touch. A PIV card fixes a
key's policy when the key is imported, so changing it imports the same key again; cards without
GET METADATA (YubiKey before 5.3) cannot report a slot's policy, so `upload` leaves their keys
and management key touch as they were imported and says so; another policy there takes `init`,
then `upload`. An OpenPGP touch is a setting of its own, except where
`--fixed-touch` made it change only with the key.

**Names are part of the certificates.** PIV certificates carry the emails, so an `upload`
without the `--emails` the card was provisioned with rewrites every certificate without them;
the list shows it, so read it. A config file or `set` keeps the identity in one place.

What `upload` cannot do in place is another algorithm, which means other keys throughout
(`init`, then `upload`), or anything about the card's own credentials, which only `init` sets.

## Rotating to a new generation

Keys have a [cryptoperiod](best-practice.md#rotation-and-cryptoperiods). A generation is a
step of the derivation, named by its day, so a rotation is the same identity at a new date:

```
mtg> rotate --date 2027-01-01
```

`rotate` reads the generation the card holds off the card itself (the start of the 9D
certificate, the creation time of the OpenPGP decryption key), derives that generation to
confirm it, and then:

| | PIV | OpenPGP |
|---|---|---|
| previous decryption key | kept, with its certificate, in the first free retired slot | leaves the card; `ungap --date <previous>` exports it for decrypting in software |
| new keys | 9A, 9C and 9D at the new date | signing, decryption and authentication at the new date |
| credentials | unchanged | unchanged |

On PIV the previous decryption key is written first, so an interrupted rotation never loses
it, and a rotation run again finds it kept already and carries on. The card's key history
object counts the retired keys, which is how middleware such as OpenSC finds them: SP
800-73-4 has them fill the slots from 82 up, so the count's keys are read from 82 on. `upload
--slot` follows the same rule and refuses a retired slot with an empty one below it, naming
the first free one instead. Once every card of the
identity holds the new generation:

1. `publish` the new certificates on each device, so correspondents encrypt to the new key;
2. `revoke --kind subkeys --date <previous>` on each device, and `revoke --kind subkeys --key
   decryption --date <previous>` once, which retires the previous generation's keys.

Old decryption keys are kept, signing and authentication keys retired
([why](best-practice.md#rotation-and-cryptoperiods)).

## Moving off a leaked key seed

When a key seed leaks, the identity is compromised, and the remedy is a new identity on the
same cards. In the [hardened flow](flows.md#hardened) the cards answer to a card seed apart from
the key seed, so they stay manageable throughout:

```
mind-the-gap --card-seed --key-seed
mtg> rotate --from-key-seed --date 2027-01-01
```

The session asks for the card seed, the new key seed and, for the rotation, the leaked one.
`rotate` confirms the card holds the leaked key seed's generation, keeps its decryption key in
a retired PIV slot, and uploads the new key seed's keys and certificates, the PIV authorities in
`msroots` included. Then revoke the old identity (`revoke --kind certificate` with the leaked
key seed), publish the new one, and tell correspondents: it is a new identity, with a new
fingerprint.

When one phrase was both seeds, a leak is the card seed's too, and the cards have to be
initialized again under a new phrase first, which resets them; keep the old decryption key with
`ungap` from the leaked phrase if old mail needs it.

## Changing the user pin

```
mtg> pin
mtg> pin --reset
```

`pin` changes the user pin with the current one, which the card checks itself; it needs no seed,
which makes it the verb a host runs on its own card ([unattended
hosts](flows.md#unattended-host)). `pin --reset` sets a new pin with what the card seed derives
for the card, the puk on PIV and the admin pin on OpenPGP, so a forgotten or blocked pin is
replaced without a reset and without touching a key. Both refuse to spend the last try of the
credential they use. In a session the new pin is asked for twice, on the terminal with no echo;
a one-shot command takes it from `--pin` (or `MIND_THE_PIN`), and the current one from
`--current-pin` (or `MIND_THE_CURRENT_PIN`).

## Replacing a lost card

The phrase provisions a replacement with the very same keys: `init` the new card, `upload` with
the same subkey id and date. Whether to keep those keys is the real question:

- **The card is gone and its pin with it, or might be:** its keys must be considered exposed.
  Provision the replacement under a new subkey id, revoke the lost device's keys with `revoke
  --kind subkeys -k <old id>`, and rotate the identity's decryption key, which the lost card
  held.
- **The card broke, or is in a drawer you trust:** provision the replacement with the same
  subkey id, and nothing changes for anyone.

The lost card's credentials are its own, derived from its serial, so they open nothing else
whatever happens to it.

## Revocation

`revoke` re-derives the identity from the key seed, so a revocation can be made **at any time,
air-gapped, without the card**: there is no revocation certificate to pre-generate and store,
which is the usual ceremony. It takes the scope as `--kind`, and the reason as `--code` (`0` unspecified, `1`
superseded, `2` compromised, `3` retired; a lost card is `2` if its pin may be known, else `3`)
with an optional `--reason` text:

- `--kind subkeys` retires one device's keys of one generation (`-k`, `-d`), leaving the
  identity and every other card alone. The decryption key is the identity's, on every card,
  so revoking one device leaves it standing; `--key decryption` alone revokes it instead,
  after a [rotation](#rotating-to-a-new-generation) put its successor on the other cards.
- `--kind certificate` retires the whole identity and every card with it.

### OpenPGP

```
mtg> revoke --app pgp --kind subkeys -k laptop --code 3 --reason "laptop lost" --to laptop-revoked.asc
```

What comes out for `--kind subkeys` is the certificate carrying revocation signatures on
those subkeys, because a lone subkey revocation signature has nothing to attach to; for
`--kind certificate` it is the revocation of the primary key. Import or publish it, and the
device's subkeys, or the identity, read as revoked. An OpenPGP revocation is a capability, so
it is written like a secret: to a file of the owner's, or the alternate screen, never to
stdout. Publishing needs nothing beyond wherever people fetch your certificate: a keyserver, a
[Web Key Directory](commands.md#publish), your website.

### PIV

`revoke` signs a revocation list with the identity's root authority: for a device, its
certificates, or with `--intermediate` its issuing authority, and with it every certificate
that authority issued; for `--kind certificate`, every key's certificate. A root authority
cannot revoke itself, so after `--kind certificate` take it out of the trust stores as well.

A certificate's serial is derived from everything it says, so `revoke` finds the serials by
issuing the certificates again from the options given: the same `--name`, `--emails`,
`--validity`, `--crl-url`, `--date` and `--intermediate` as the upload that put them on the
card. Revoked with other options, the list names certificates that were never issued, and the
ones on the card stay valid; a config file that keeps the identity's options avoids that.

To be found, a list has to be where the certificates say. `--crl-url` names a URL ending in a
list's name with `.crl`, such as `http://example.org/alice.crl`, and each of the identity's
lists is published beside it, under that name with a suffix of its own: the root's with the
algorithm, `alice-p256.crl`, as each algorithm has a root of its own, and with `--intermediate`
the issuing authority's with the authority's tag after it, `alice-p256-issuing-9b3e5d17.crl`
(the tag in lowercase here), so that each device and generation has a list of its own. A URL
the lists cannot be named from is refused where PIV is named, before any seed is stretched: it
needs a scheme, a host (but for `file:`), no empty path segment, no query or fragment, and a
last segment that is the list's name, letters, digits, `-`, `.`, `_` and `~` before the
`.crl`, none of them percent-encoded, since the suffixes are added to it; the path before the
name may be percent-encoded.

Every certificate the root issues itself names the root's list in its `cRLDistributionPoints`,
and verifiers fetch the list from there, so it has to hold every revocation so far: `revoke`
reads the list already at `--to` (the file, or the root's list in the directory, as below),
keeps its entries and adds the new ones. It accepts only a list this identity's root signed,
and since every signature here is deterministic, that is checked by signing the list again. The
URL is part of the certificates, so it is best decided before provisioning; adding it later is
an `upload` that re-issues every certificate.

Such a list is due again a year after it is signed. `publish --part crl` signs it afresh,
before then, and publishes an empty one before anything is revoked. A verifier checks each
certificate against the list of whoever issued it, so with `--intermediate` the issuing
authority signs a list of its own, which its certificates name. That list is empty for good,
since revocation happens at the root, which lists the authority; it is dated from the
authority's start and never due, so it is published once and never needs signing again.
`publish --part crl` writes it next to the root's (so `--to` names a directory then).

A list's file carries the suffix its URL does, whatever the URL: `piv-revocation-p256.crl.pem`
and `piv-revocation-p256-issuing-9b3e5d17.crl.pem`, so the lists of several algorithms sit side
by side in one directory and each run finds its own. `revoke` writes PEM, the form a list is
kept and read in. A distribution point over HTTP serves DER (RFC 5280 section 4.2.1.13), which
`publish --part crl --format binary` writes, as `piv-revocation-p256.crl` and
`piv-revocation-p256-issuing-9b3e5d17.crl`: each goes to the URL with its suffix,
`alice-p256.crl` and `alice-p256-issuing-9b3e5d17.crl`. Without `--to`, the QR codes carry the
PEM, whatever the format.

A file `--to` names is read back as the previous list in either form. In a directory, the
previous list is the root's list in whichever form is there, `piv-revocation-p256.crl.pem` or
`piv-revocation-p256.crl`; where both are, the one with the greater CRL number, the newer, as
long as it revokes everything the older does. Two lists of one number that differ, or a newer
list that lacks a revocation of the older, are refused, naming both files: keep the one that
was published and move the other away. A list file is only ever written over by the list read
from it, or by the very same bytes, so no run drops what a list in the directory revokes.

`revoke` writes only the PEM, so after each `revoke` the DER beside it is still the previous
list: publish it again with `publish --part crl --format binary --to` the same directory, which
reads the newer PEM, before uploading the `.crl` to the server.

Without `--crl-url`, a revocation list is for the relying parties you configure yourself (a
VPN, a door system, a mail gateway), which take it as a file, and it is never due.

The list is dated by the machine's clock, so set it first on an air-gapped machine: `revoke`
refuses a clock that reads before the identity or the list it replaces.

### Not revoking at all

The cheapest alternative is not to revoke. Each device's keys derive from its own subkey id,
so retiring a card can simply mean provisioning its successor under a new subkey id and no
longer trusting the old certificates, which needs no infrastructure whatsoever. With
`--intermediate`, "no longer trusting" has a natural unit: that device's issuing authority.
