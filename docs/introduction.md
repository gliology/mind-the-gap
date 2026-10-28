# Mind the Gap

<img src="logo.svg" width="160" alt="The Mind the Gap mark: a red shield with a bar reading MIND THE GAP">

Mind the Gap derives smart card keys, pins and certificates from a BIP-39 seed phrase, on an
air-gapped machine, and puts them on PIV and OpenPGP cards. Nothing it writes has to be
backed up: the phrase on paper re-creates every card, every certificate and every credential,
years later, byte for byte.

The repository carries two things:

- the `mind-the-gap` command line tool;
- a NixOS live image that runs it with the network, the disks and every way out of the
  machine taken away.

## Two seeds, and usually one phrase

Everything descends from a seed, and a seed plays two roles. The **card seed** administers
cards: it derives each card's own credentials (the PIV management key and puk, the OpenPGP
admin pin) and its identifiers, all bound to the card's serial number, so that one card's
credentials open no other card. The **key seed** is an identity: it derives the identity's
root authority or OpenPGP primary key and every key the identity uses.

A person with their own cards needs one phrase, which is both. The roles part where the people
or the risks do: a team's administrator issues every member's card from their own card seed,
while the team's signing key comes from the team's key seed; a host's card carries the host's
identity but answers to the administrator. The [recommended flows](flows.md) walk through
each case, and the [glossary](glossary.md) says what each term means.

## Where to go next

- **A first card:** [your first card](quick-start.md) goes from booting the image to a
  provisioned card in seven steps, [the live image](live-image.md) says how to work on the
  image, and [after the gap](after-the-gap.md) sets up the everyday machine the card is used
  on.
- **More than one card, a team, a host:** the [recommended flows](flows.md) pick the setup,
  and the guides that follow them cover several cards, rotation and revocation, unattended
  hosts, policies, ceremonies and an image of your own.
- **Looking something up:** [the session and the command line](interfaces.md) explains the
  three interfaces, [commands](commands.md) every verb, [options](configuration.md) every
  option, and [troubleshooting](troubleshooting.md) the messages that need explaining.
- **Deciding whether to trust it:** [key derivation](derivation.md) is the specification,
  [security](security.md) what the tool and the image protect and what they leave to you,
  [why it is built this way](best-practice.md) the practice each choice follows, and
  [supported cards](supported-cards.md) what has run on which card.

To try the tool on an online machine:

```
nix run github:gliology/mind-the-gap
```

That is a fine way to learn it; keys meant for production belong on the air-gapped image,
for the reasons the [security chapter](security.md#on-your-own-machine) gives.
