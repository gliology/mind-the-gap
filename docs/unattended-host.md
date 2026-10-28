# Unattended hosts

A host can keep its identity on a card rather than in a key file: the card signs or decrypts,
and the private key never exists anywhere the host could leak it. A build server signing its
store paths is the usual case, a service decrypting its secrets another. Deriving that card
gives the usual guarantee on top: if it dies or goes missing, the seeds provision a replacement
with the very same keys and certificates.

Such a card is used differently from a person's. Nobody is there to type a pin or touch a button
for each signature, the machine it ends up in is not where it was provisioned, and the host
should hold as little as possible: no seed, no management key, no admin pin.

## Who holds what

| | held by | derives |
|---|---|---|
| card seed | the administrator, on the air-gapped side | the card's management key, puk and identifiers |
| key seed | the host's own, on the air-gapped side | the host's identity, its root authority and keys |
| user pin | the host, in its secret store | nothing: it unlocks this card |

The host's key seed is a phrase of its own because the host is an identity of its own: its own
certificate and root, which the administrator's identity can certify, and which is revoked on
the host's schedule rather than the person's. The card answers to the administrator's card seed
because administering it is the administrator's job, and the host's key seed never needs to
open a card.

## The profile

On the air-gapped machine, with the host's card attached:

```
mind-the-gap --key-seed
mtg> set name='pavlov builder' subkey=pavlov-1 algorithm=p384 policy=once-pin
mtg> init --app piv
mtg> upload --app piv
mtg> check --app piv
mtg> publish --app piv --part identity --to /media/usb/
```

The session asks for the administrator's phrase as the card seed and for the host's key seed.

| setting | why |
|---|---|
| `algorithm=p384` | the cache signing key has to be ECDSA P-384 for Determinate Nix to use it, and `--algorithm` applies to every slot and the authorities at once, so the whole chain moves to P-384 |
| `policy=once-pin` | the host signs unattended: it unlocks the card with the pin once per session rather than once per signature (9C would otherwise demand the pin before every one), and nobody is at the host to touch the card. Management access goes without a touch too: it is only ever needed on the air-gapped machine, and the management key never reaches the host, so a touch would guard nothing there. `upload` warns that 9C no longer asks for the pin before every signature; for a host's signature that is the point |
| `subkey=pavlov-1` | one id per host, so each holds its own keys under the one root of the host identity, or of a fleet's |
| `management-algorithm=auto` (the default) | AES-256 where the card takes it; 3DES on a YubiKey 4, or a YubiKey 5 before firmware 5.4, which take nothing else |

The policy applies to 9A, 9C, 9D and the retired slots; 9E keeps its own in every mode (see
[pin and touch policies](policies.md)).

## The host's pin

The user pin is the one secret that reaches the host, and it is the host's own: random, kept in
the host's secret store (systemd credentials, a TPM-sealed file), and never seen on the
air-gapped side. `init` leaves the factory pin `123456`, and the host sets its own on first
boot, in [plumbing mode](interfaces.md#plumbing-mode), which never prompts, with the factory
pin as the current one:

```
MIND_THE_CURRENT_PIN=123456 MIND_THE_PIN="$(systemd-creds decrypt pin.cred -)" \
  mind-the-gap --plumbing pin --app piv --card 20381784
```

It then rotates the pin on its own schedule the same way, from the pin it holds to the next:

```
MIND_THE_CURRENT_PIN="$(systemd-creds decrypt current.cred -)" \
MIND_THE_PIN="$(systemd-creds decrypt next.cred -)" \
  mind-the-gap --plumbing pin --app piv --card 20381784
```

`pin` with the current pin needs no seed. If the host loses its pin, or a wrong one blocks it,
recovery happens on the air-gapped side, with the puk the card seed derives for the card, and
no key is touched:

```
mtg> pin --reset --app piv --card 20381784
```

## YubiKey 4

A YubiKey 4 (firmware 4.3) takes P-256, P-384 and RSA keys with pin and touch policies, so it
carries this profile fine, with two differences from a YubiKey 5 that the tool handles on its
own:

- Its only management key algorithm is 3DES. `--management-algorithm auto` reads the firmware
  version the card reports and installs the derived 3DES key (see [the PIV management
  key](derivation.md#the-piv-management-key)); everything that authenticates later asks the
  card which algorithm it holds.
- It has no GET METADATA (that arrived with firmware 5.3), so the card cannot say which public
  key a slot holds or which policies it carries. `upload` skips its read-back of each imported
  key and leaves it to `check`.

Ed25519 and X25519 keys need firmware 5.7, so `--algorithm curve25519` is out on these cards.

## Signing store paths

The host signs with the signature key in 9C, OpenSC's object `id=%02`, whose certificate is
the one issued for signatures; 9D stays the host's key for decrypting what is encrypted to it,
its secrets for one. [Signing with 9C](after-the-gap.md#signing-with-9c) says why the choice is
the host's to make. Under `once-pin` the pin unlocks 9C once per session, like the other slots.

```
pkcs11:id=%02;type=private
```

The profile was tried on a real card before the 1.0 redesign: on 2026-10-14 a YubiKey 4 on
firmware 4.3.7 took the derived 3DES management key, passed `check` with every slot key proven
by a signature challenge, and then worked unattended as the server's identity through OpenSC:
SSH signatures from 9A and a git commit signature from 9C through an ssh-agent, with the pin
entered once and no touch, and ECDSA P-384 Nix store path signatures, about 330 ms each, which
Determinate Nix accepted. That run signed with 9D; the profile signs with 9C now.

## Before the card goes into the host

Run `check` with the same settings, still on the air-gapped machine; it needs the seeds, so it
cannot run on the host itself. It compares everything the seeds derive with the card, and on
a card without GET METADATA, such as the YubiKey 4, proves each slot key with a signature
challenge instead, which needs `--pin` for the slots whose pin policy asks for one
([check](commands.md#check)).

## Recovery

A broken or retired card is replaced by running the same `init` and `upload` against a new card:
the host's keys and certificates come out the same, so whatever trusts the old card trusts the
new one without a change, and the new card's credentials are its own. If the old card may have
fallen into the wrong hands together with its pin, provision the replacement under a new subkey
id (`subkey=pavlov-2`) instead, which gives it new keys under the same root, and revoke the old
one's.
