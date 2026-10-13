# PIV cards for build servers

A build server can keep its signing identity on a PIV card rather than in a key file: the
card signs, and the private key never exists anywhere the server could leak it. Deriving
that card from a seed gives the usual guarantee on top: if it dies or goes missing, the seed
provisions a replacement with the very same keys and certificates.

Such a card is used differently from a person's. Nobody is there to type a pin or touch a
button for each signature, and the machine it ends up in is not where it was provisioned.
This chapter describes the profile for that case, and why each flag is what it is.

## The profile

```
mind-the-gap -s '<mnemonic>' -k pavlov-1 -n 'pavlov builder' piv --algorithm p384 \
  --pin-policy once --touch-policy never --management-key-touch never \
  upload -c <serial> --pin <pin> --yes
```

Run it on the air-gapped machine (the live image), with the server's card attached. `-k`
names the card: one id per server, so every server holds its own keys while one root
certificate authority covers all of them (see [several cards from one
seed](multiple-cards.md)).

| flag | why |
|---|---|
| `--algorithm p384` | the cache signing key has to be ECDSA P-384 for Determinate Nix to use it, and `--algorithm` applies to every slot and both authorities at once, so the whole chain moves to P-384 |
| `--pin-policy once` | the server signs unattended: it unlocks the card with the pin once per session, not once per signature (9C would otherwise demand the pin before every one) |
| `--touch-policy never` | nobody is at the server to touch the card |
| `--management-key-touch never` | management access is only ever needed during provisioning, which happens on the air-gapped machine; the derived management key never reaches the server, so a touch would guard nothing there |
| `--management-key auto` (default) | AES-256 where the card supports it; 3DES on a YubiKey 4, or a YubiKey 5 before firmware 5.4, which take nothing else |

Slot 9E keeps its pin-less, touch-less policy whatever the overrides say, as the PIV
specification requires; the overrides apply to 9A, 9C, 9D and any retired slots. The
policies are fixed when a key is imported, so changing them means running `upload` again.

The pin is the one secret that has to reach the server, in whatever way it keeps its other
secrets. It unlocks signing on that one card and nothing else: it is not part of any
derivation, and the seed stays on paper.

## YubiKey 4

A YubiKey 4 (firmware 4.3) takes P-256, P-384 and RSA keys with pin and touch policies, so
it carries this profile fine, with two differences from a YubiKey 5 that the tool handles on
its own:

- Its only management key algorithm is 3DES. `--management-key auto` reads the firmware
  version the card reports and installs the derived 3DES key (see [the PIV management
  key](derivation.md#the-piv-management-key)); `check` asks the card which algorithm it
  holds, so it needs no flag.
- It has no `GET METADATA` command (that arrived with firmware 5.3), so the card cannot say
  which public key a slot holds or which policies it carries. `upload` skips its read-back
  check of each imported key and leaves it to `check`.

Ed25519 and X25519 keys need firmware 5.7, so `--algorithm curve25519` is out on these cards.

This has been tried on a real card. On 2026-10-14 a YubiKey 4 on firmware 4.3.7, in
FIDO+CCID mode, was provisioned with exactly the profile above in 4.9 seconds: `upload`
installed the derived 3DES management key, and `check --pin` proved all four slot keys by
signature challenges and matched every certificate and the `msroots` object byte for byte.
The card then worked unattended as the server's identity through OpenSC: SSH signatures
from 9A and a git commit signature from 9C through an ssh-agent, with the pin entered once
and no touch, and ECDSA P-384 Nix store path signatures from 9D, about 330 ms each, which
Determinate Nix accepted.

## What `check` verifies

Run `check` with the same flags, still on the air-gapped machine, before the card goes into
the server. It needs the seed, so it cannot run on the server itself.

```
mind-the-gap -s '<mnemonic>' -k pavlov-1 -n 'pavlov builder' piv --algorithm p384 \
  --pin-policy once --touch-policy never --management-key-touch never \
  check -c <serial> --pin <pin>
```

On every card it authenticates with the derived management key, verifies the pin, compares
each slot certificate byte for byte with the derived one, and checks the certificate
authorities in the `msroots` object. What differs is how the slot keys are compared:

| | card with `GET METADATA` | card without (YubiKey 4, YubiKey 5 before 5.3) |
|---|---|---|
| slot public keys | read back and compared with the derived ones | proven by a signature challenge: the card signs a fresh random digest, which has to verify under the derived public key |
| pin and touch policies | read back, a mismatch warns | not verifiable on this card (warned once) |
| management key touch | read back, a mismatch warns | not verifiable |

The signature challenge is as conclusive as a read-back: only the derived private key can
produce a signature that verifies under the derived public key. It does need the pin for
every slot whose pin policy is not `never`; without `--pin`, `check` warns that those keys
cannot be verified on this card and challenges only 9E. A slot whose touch policy is not
`never` asks for a touch on stderr before it signs.

## Recovery

A lost, broken or retired card is replaced by running the same `upload` against a new card.
Every key, certificate and identifier comes out the same, so whatever trusts the old card's
root or keys trusts the new one without a change. Revoke trust in the old card only if it
may have fallen into the wrong hands together with its pin; in that case provision the
replacement under a new card id (`-k pavlov-2`) instead, which gives it new keys under the
same root.
