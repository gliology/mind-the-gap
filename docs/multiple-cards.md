# Several cards and identities

Provisioning more than one card is the normal case: a laptop, a desktop, a spare in a drawer,
a team's key on every member's card. This chapter walks through what that takes, and what each
choice costs. The [flows](flows.md) say which combination to start from.

## One subkey id per device

**Give every device its own subkey id.** Without one, every card of an identity is a clone of
the others: the same signing and authentication keys, so nothing tells which card signed or
logged in, and losing one card means revoking the keys of all of them.

```
mtg> upload -k laptop
mtg> upload -k desktop
```

The subkey id changes the device's own keys and nothing above them:

| | `-k laptop` | `-k desktop` |
|---|---|---|
| PIV root authority, OpenPGP primary key | the identity's | the same |
| 9A, 9C, OpenPGP signing and authentication | the laptop's | the desktop's |
| 9D, OpenPGP decryption | the identity's | the same |
| management key, puk, admin pin, card identifiers | the card's own, from its serial | the card's own |

So one trust anchor, or one OpenPGP identity, covers every device, while each card holds keys
of its own. One per algorithm, that is: the algorithm is part of every derivation, the root's
too, so a card on another algorithm chains to a root of its own, named by it
(`CN=Jane Doe PIV Root CA rsa2048` beside `CN=Jane Doe PIV Root CA p256`), with a revocation
list of its own, and relying parties install each root their cards chain to. The card's credentials never depend on the subkey id: they come from the card seed
and the card's serial, so `upload -k desktop` can go onto any card the card seed initialized,
and re-running it reproduces that card's keys byte for byte, which is how a lost card is
replaced.

The subkey id is a step of the derivation and appears in nothing published: the PIV
certificates of every card carry the identity's subject, as the OpenPGP subkeys carry no device
name, and a device's certificates are told apart by their keys. It is no secret either, so
treat it as a name.

## Which card is which

With several cards on the desk, `list` says which of them a card seed initialized and which
keys are a key seed's, on the device `-k` names:

```
mtg> list -k laptop
Yubico YubiKey OTP+FIDO+CCID 00 00
  PIV card 20381784
    initialized by this card seed
    Authentication key: 4f1c... (CN=Jane Doe), this key seed's
    ...
  OpenPGP card 0006:20381784
    initialized by this card seed
    ...
Nitrokey Nitrokey 3 [CCID/ICCD Interface] 01 00
  OpenPGP card 000F:A1B2C3D4
    not initialized by this card seed
```

It reads only what a card shows without a pin, so it spends no pin try, asks for no touch, and
leaves every card as it was found. A PIV card shows which card seed initialized it in its
CHUID and its 9E certificate, an OpenPGP card in the card identifier `init` writes into data
object 0102: identifiers derived from the card seed and the card's serial, which reveal
nothing of the seed (see [derivation](derivation.md#published-identifiers)). The other
verdicts are in the [commands chapter](commands.md#list).

No certificate names its device, so a device's keys are recognized by deriving them: `list -k
laptop` marks the laptop's own keys (9A and 9C) as this key seed's and a desktop's not, while
the decryption key, the identity's, shows as this key seed's on every card; `check -k laptop`
compares a card with everything the laptop's subkey id derives. On the air-gapped side,
`publish -k laptop`, with the generation's `-d` for a dated one, reproduces the laptop's
certificates, with their fingerprints and serials, to compare with a certificate met
elsewhere.

`--card` then names one, in any of three ways: a PIV serial, an OpenPGP identifier
(`0006:12345678`), or the reader as `list` shows it. A serial or an identifier is looked up by
asking every attached card who it is, without disturbing it; a reader is opened directly, and is
the way to address a card while other programs work on the cards next to it. One `--card`
covers both applets of a card.

## Encryption: one key for the identity

Signing and authentication work per card without any thought: the verifier checks whichever key
was used. Encryption does not, because the sender chooses the key, and chooses one:

```
:pubkey enc packet: version 3, algo 18, keyid E4D4C05ABCB4171A
```

One packet, one key. With a decryption key per card, mail encrypted for the laptop could not be
read on the desktop. So mind-the-gap derives the decryption key without the device step: it is
the identity's, the same on every card, and without `--intermediate` its PIV certificate is the
same too. Merging the certificates every device publishes gives what a correspondent needs:

```
Subkey: CC769FDA… signing                          <- laptop
Subkey: 38699EF0… authentication                   <- laptop
Subkey: EBDD6E10… signing                          <- desktop
Subkey: 37719944… authentication                   <- desktop
Subkey: 4677E8FF… transport + data-at-rest         <- one, on both cards
```

**The cost** is that a shared key is shared: a card lost with its pin exposes the decryption
key of every card. It is then [rotated](rotation.md): a new generation on every card, with the
old key kept in a retired PIV slot for the mail already encrypted to it.

## Retired slots

PIV keeps twenty retired key management slots, `0x82` to `0x95`, for decryption keys that are no
longer current but must keep decrypting. mind-the-gap fills them two ways:

- `rotate` moves the previous generation's decryption key into the first free one, with its
  certificate, before it uploads the new generation ([rotation](rotation.md)).
- `upload --key decryption --slot 82` puts the decryption key of the chosen key seed and
  generation there, which is how a person's card carries a team's decryption key next to their
  own, or a generation that was rotated on another card:

```
mtg> upload --key-seed --key decryption --slot 82
```

The card seed authenticates the card, the key seed derives the key, and the key seed's root
authority certifies it. A key derives the same in a retired slot as in 9D, so `check --key
decryption --slot 82` verifies it later.

Only decryption keys are kept this way; old signing and authentication keys are retired, for
the reasons [rotation and cryptoperiods](best-practice.md#rotation-and-cryptoperiods) gives.

OpenPGP cards have one decryption slot. A team's decryption key there would replace the
person's, so a team key on an OpenPGP card wants a card of its own.

## An issuing authority per device

`--intermediate` inserts an issuing authority between the PIV root authority and the slot
certificates, one per device and generation. As no certificate names a device, each is named by
a tag of its own key, the first four bytes of its subject key identifier
([derivation](derivation.md#piv-certificates-from-the-seed)):

```
laptop   CN=Jane Doe PIV Issuing CA 9B3E5D17
desktop  CN=Jane Doe PIV Issuing CA D27E0B65
```

Which device an authority is for is told on the air-gapped side: `publish --app piv -k laptop
--intermediate`, with the generation's `-d` for a dated one, writes the laptop's chain, its
issuing authority included.

That turns a device's certificates into one revocable unit: revoking a card without one lists
each of its certificates on the root's revocation list; with one, that card's issuing authority
is the single entry, and its certificates fall with it, for verifiers that check the issuing
authority's status. It costs an extra tier in every path, and with `--crl-url` a second,
never-changing list to publish ([revocation](rotation.md#piv)). The root asserts
`pathLenConstraint: 1` either way, so it is one certificate whether or not a device has an
issuing authority.

## Summary

- One subkey id per device; it is no secret, and no certificate names it.
- Signing and authentication need no further thought; the decryption key is the identity's,
  on every card.
- `list` tells cards apart without spending a pin try; `--card` names one.
- Retired PIV slots keep previous generations' and other identities' decryption keys.
- `--intermediate` makes a device one revocable unit; [revocation](rotation.md#revocation)
  covers what revoking one takes.
