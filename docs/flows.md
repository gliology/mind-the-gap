# Recommended flows

A handful of flows cover what people actually do with derived cards. They differ in how many
phrases are involved, which of them administers the cards, and how much each card is trusted
on its own, which is a trade between safety and hassle. Pick the first one that fits; [why it
is built this way](best-practice.md) explains the reasoning behind each choice.

| Flow | Seeds | Cards | For |
|---|---|---|---|
| [Personal](#personal) | one phrase | one card | a single person, one key set |
| [Personal, several devices](#personal-several-devices) | one phrase | one per device | one identity on a laptop, a desktop and a spare |
| [Team or service identity](#team-or-service-identity) | each administrator's card seed, a key seed per team or service | the members' cards, or one per service | code signing, shared decryption |
| [Hardened](#hardened) | a card seed and a key seed apart, both with passwords | one per device | identities whose keys must outlive a leaked administrator |
| [Unattended host](#unattended-host) | the administrator's card seed, the host's own key seed | one per host | build servers, services that sign or decrypt without a person |

Every example below is typed in an [interactive session](interfaces.md#the-interactive-session),
which asks for each phrase on a hidden prompt when a command first needs it. The same lines
work as one-shot commands with the phrases in `MIND_THE_SEED`, `MIND_THE_CARD_SEED` and
`MIND_THE_KEY_SEED`, and as steps of a [ceremony](ceremonies.md).

## Personal

One phrase, which is both the card seed and the key seed, and one card.

```
mtg> set name='Jane Doe' emails=jane@example.org
mtg> init
mtg> upload
mtg> publish --to /media/usb/
```

`init` resets the card and installs what the phrase derives for *this* card: its own PIV
management key and puk, its own OpenPGP admin pin, its identifiers and the PIV card
authentication key. `upload` adds the identity's keys and certificates under those
credentials. A lost card is replaced from the phrase with the very same keys ([replacing a lost
card](rotation.md#replacing-a-lost-card)). This is the least hassle, and the whole safety rests
on the paper: a leaked phrase leaks everything, cards and identity alike.

## Personal, several devices

One phrase, one card per device, each named by its subkey id. With the laptop's card
plugged in, then the desktop's:

```
mtg> set name='Jane Doe' emails=jane@example.org
mtg> set subkey=laptop
mtg> init
mtg> upload
mtg> set subkey=desktop
mtg> init
mtg> upload
```

With both attached at once, `--card` names one, by the serial or identifier `list` shows.

Each device signs and authenticates with keys of its own, so a signature or an SSH login says
which card made it, and a lost card is revoked on its own (`revoke --kind subkeys -k laptop`). The decryption key is the identity's, the same on every
card, and a lost card with its pin means [rotating](rotation.md#rotating-to-a-new-generation) it
on every card. One OpenPGP certificate carries all of it, merged from each device's `publish`;
one PIV root authority certifies every card. [Several cards and identities](multiple-cards.md)
goes through what that takes.

## Team or service identity

A distinct identity (a team, a release signing key, a service) gets a phrase of its own: its
**key seed**. It derives that identity's own OpenPGP certificate and PIV root authority, and
the keys the identity uses. Whoever administers the cards keeps their own **card seed**, so
the key seed never needs to open a card, and a card's credentials never depend on who else
holds the team's keys.

A service with a card of its own, administered by Alice:

```
mind-the-gap --card-seed --key-seed
mtg> set name='Release signing' emails=release@example.org
mtg> init
mtg> upload --key signature
```

The session asks for Alice's card seed when `init` needs it and for the team's key seed when
`upload` does. Any administrator can initialize a team card with their own card seed, and
every holder of the key seed can derive the team's keys, which makes it a
[shared key](best-practice.md#shared-keys); where that is too much, give each person their own
key seed and certify them with the team's identity ([trust](commands.md#trust)).

A team's decryption key can also join the members' personal cards, in a retired PIV slot,
without disturbing the person's own keys:

```
mtg> upload --key-seed --key decryption --slot 82
```

The card seed (the person's phrase) authenticates the card, the team's key seed derives the
key, and the team's root authority certifies it. OpenPGP has one slot per role, so there the
team's decryption key would replace the person's: a team key on an OpenPGP card wants a card
of its own.

A distinct identity is also where an address with a subaddress belongs:
`release+ci@example.org` for a build host's own certificate, certified by the person who runs
it ([why](best-practice.md#distinct-identities-get-distinct-certificates)).

## Hardened

The card seed and the key seed are two phrases, each with a password, and every device has
its own subkey id and the `strict` policy:

```
mind-the-gap --card-seed --key-seed
mtg> set name='Jane Doe' emails=jane@example.org policy=strict subkey=laptop
mtg> init
mtg> upload
```

The split makes a leak survivable ([key separation](best-practice.md#key-separation)): after a
leaked card seed the cards are initialized again under a new one, and after a leaked key seed
every card [moves to a new key seed](rotation.md#moving-off-a-leaked-key-seed) while it keeps
answering to its administrator.

## Unattended host

A host signs or decrypts without a person: a build server signing store paths, a service
decrypting its secrets. The administrator initializes the host's card from their own card
seed on the air-gapped machine, with the host's own key seed, commissioned so that it needs no
touch:

```
mind-the-gap --key-seed
mtg> set name='pavlov builder' subkey=pavlov-1 algorithm=p384 policy=once-pin
mtg> init --app piv
mtg> upload --app piv
```

The host then holds the card and its own user pin, never a seed. [Unattended
hosts](unattended-host.md) explains every choice of this profile, how the host sets and
rotates its pin, and how a lost pin is recovered.
