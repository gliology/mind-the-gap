# Your first card

From nothing to a provisioned card and its public half on your everyday machine. Each step
links to the chapter that explains it.

## 1. Boot the image

```
nix build github:gliology/mind-the-gap#iso
```

Copy `result/iso` to a USB stick and boot it on a machine you can take offline. The image
has no network and keeps nothing; the [introduction](introduction.md#security-model)
explains what it locks down.

## 2. Mint the phrase

```
mind-the-gap generate
```

Write the 24 words down on paper. The screen keeps them until a short quiz proves the copy
is right, then wipes them. This phrase is the only secret: every key, pin and certificate
below comes from it, and it re-creates all of them later.

## 3. Open a session

```
mind-the-gap
```

The first command that needs the phrase asks for it on a hidden prompt, then for an
optional password (Enter for none). Both stay in memory until you leave. Tell the session
who you are once:

```
mtg> set -n 'Jane Doe' -m jane@example.org
```

## 4. Provision the card

Give every card its own subkey id, here `laptop`, so one lost card never means replacing
the others ([why](multiple-cards.md)):

```
mtg> pgp -k laptop upload
mtg> piv -k laptop upload
```

Each upload asks for the card's user pin and then names the card it is about to reset;
answer `yes`. A card that cannot hold the keys is refused before anything on it is erased.
There is no puk and no admin pin to note down: a forgotten pin is fixed by running the same
upload again.

## 5. Take the public half across

```
mtg> pgp -k laptop certify
mtg> piv -k laptop certify --kind root
```

Each shows a QR code to scan with the everyday machine (or writes a file with `-o` for a
USB stick). There, `gpg --import` the OpenPGP certificate and `gpg --card-status` with the
card attached links its keys; the PIV root is what servers and clients trust for the card's
certificates ([PIV certificate chain](piv-certificates.md)).

## 6. Leave

`quit` the session and power the machine off. The cards go into service; the paper goes
somewhere safe. A second card is the same steps with another subkey id, in the same session.
