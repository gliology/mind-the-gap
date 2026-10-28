# Your first card

From nothing to a provisioned card and its public half on your everyday machine, with one
phrase. Each step links to the chapter that explains it.

## 1. Boot the image

```
nix build github:gliology/mind-the-gap#iso
```

Write the `.iso` file in `result/iso/` (`mind_the_gap-<version>-<label>-x86_64-linux.iso`)
to a USB stick and boot it on a machine you can take offline. The image has no network and
keeps nothing; [the live image](live-image.md) says what greets you there, and the [security
chapter](security.md#the-live-image) what it locks down.

## 2. Mint the phrase

```
mind-the-gap generate
```

Write the 24 words down on paper. The screen keeps them until a short quiz proves the copy
is right, then wipes them. This phrase is the only secret: every key, pin and certificate
below comes from it, and it re-creates all of them later.

## 3. Open a session and say who you are

```
mind-the-gap
```

The first command that needs the phrase asks for it on a hidden prompt, then for an optional
password (Enter for none). Both stay in memory until you leave. Set the identity and the name
of this card's device once:

```
mtg> set name='Jane Doe' emails=jane@example.org subkey=laptop
```

The subkey id names the device; every card gets its own, so that one lost card never means
replacing the others ([why](multiple-cards.md)).

## 4. Write down the record

Before the card is plugged in, `check` shows what the phrase derives:

```
mtg> check
Seed id: e63cbb22d6f5c53c
PIV root authority: cac90756... (CN=Jane Doe PIV Root CA p256)
OpenPGP identity: 38BAAB2F9DE7D459C34A80B3AF859A5F33253C3A
```

Note these next to the phrase. A password has no checksum, so a typo in it derives other
keys without a word of complaint; the seed id is how you notice, every time you type the
phrase in again ([derivation](derivation.md#the-seed-id)).

## 5. Initialize and provision the card

Plug the card in:

```
mtg> init
mtg> upload
```

`init` asks for the card's new user pin, then names the card it is about to reset; answer
`yes`. It gives the card its own credentials and identifiers, from the card seed and the
card's serial. `upload` then lists the keys and certificates it is about to write and asks
again. A card that cannot hold the keys is refused before anything on it is erased.

There is no puk and no admin pin to note down: both are derived for this card, so a
forgotten pin is replaced with `pin --reset`, which needs only the phrase.

## 6. Take the public half across

```
mtg> publish --to /media/usb/
```

That writes the OpenPGP certificate and the PIV certificate chain to the stick
([publish](commands.md#publish)), mounted there first ([the transfer
stick](live-image.md#the-transfer-stick)); without `--to` they are shown as QR codes instead, one
part at a time with `--part identity` or `--part keys`. On the everyday machine,
`gpg --import pgp.asc` and `gpg --card-status` with the card attached link its keys; the PIV
root in `piv-chain.pem` is what servers and clients trust for the card's certificates. [After
the gap](after-the-gap.md) sets that machine up.

## 7. Leave

`quit` the session and power the machine off. To step away before then, `quit` and run
`forget` at the shell, which clears the screen, the scrollback and the shell's history
([leaving the machine](live-image.md#leaving-the-machine)). The card goes into service; the
paper goes somewhere safe. A second card is `set subkey=desktop`, then `init` and `upload`
again, in the same session.
