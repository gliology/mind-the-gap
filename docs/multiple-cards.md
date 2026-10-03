# One seed, several cards

Provisioning more than one card from a single seed is the normal case — a laptop, a desktop, a
spare in a drawer — and it forces a handful of choices that are easier to make deliberately
than to discover later. This document walks through them for both backends.

Everything below was measured against the tool rather than reasoned about.

## Give every card a subkey id

**Do this first.** Without `--subkey`, every card provisioned from one seed is a cryptographic
clone of the others: same keys, same certificates, same card id.

```
MIND_THE_SUBKEY=laptop  mind-the-gap piv upload
MIND_THE_SUBKEY=desktop mind-the-gap piv upload
```

Everything below the subkey id changes with it; the authority above it does not:

| `--subkey` | root CA | 9A key | card id |
|---|---|---|---|
| *(none)* | `8689cddf…` | `f3450d17…` | `9482DB69` |
| `laptop` | `8689cddf…` | `4fc4587c…` | `E1FE3429` |
| `desktop` | `8689cddf…` | `094d61dc…` | `C40CBAD3` |

OpenPGP behaves the same way: the primary key is identical across ids, the three subkeys are
not. So one trust anchor — or one OpenPGP identity — covers every machine, while each card
holds distinct key material.

Clones are not merely untidy. You cannot tell which card signed or authenticated anything,
losing one card means revoking the identity on every machine, and on the PIV side every card
gets the same CHUID GUID, which Windows keys its smartcard cache on.

Re-running `upload` with the *same* id is a different matter: it reproduces that card byte for
byte, which is how a lost card is replaced.

### The subkey id is public

It appears in the derivation labels and, once a card is provisioned, in the certificates
themselves — `dnQualifier=mtg1:laptop` on PIV, a subkey binding notation on OpenPGP. Treat it
as a name, not a secret. "Which card is this" is exactly what it is for.

If you want a second secret that separates one set of exported keys from another, that is what
`--password` is for. It feeds the root entropy derivation, above everything discussed here.

## Signing is easy, encryption is not

This is the asymmetry that drives every remaining decision.

**Signing and authentication work per card without any thought.** The verifier checks whichever
key was actually used, so four cards with four signing keys all just work.

**Encryption does not.** The *sender* chooses one key, and clients choose exactly one. Encrypt
to an OpenPGP certificate carrying three encryption subkeys and you get a single recipient:

```
:pubkey enc packet: version 3, algo 18, keyid E4D4C05ABCB4171A
```

One packet, one card. The others cannot open that message. With equal subkey creation dates the
choice is effectively arbitrary; stagger them with `--subdate` and it becomes deterministic —
newest wins — but it is still one card.

PIV has the same problem wearing different clothes: a sender encrypts to one specific 9D
certificate, so mail encrypted for the laptop cannot be read on the desktop.

There are two answers, and they are mirror images.

## Answer one: share the decryption key

```
mind-the-gap pgp -k laptop  --shared decryption upload
mind-the-gap pgp -k desktop --shared decryption upload
```

`--shared` derives the named keys without the subkey id, so they come out identical on every
card while the rest stay card specific. Merging the two certificates gives what you want:

```
Subkey: CC769FDA… signing                          <- laptop
Subkey: 38699EF0… authentication                   <- laptop
Subkey: EBDD6E10… signing                          <- desktop
Subkey: 377199446… authentication                  <- desktop
Subkey: 4677E8FF… transport + data-at-rest         <- one, on both cards
```

One encryption subkey, four card-specific signing and authentication subkeys, one identity. Any
sender can encrypt to you and either card opens it, while signatures and SSH logins remain
attributable to a particular card.

PIV takes the same flag with `--shared key-management`. Slot 9E is deliberately not offered:
it identifies the card, so a shared one would defeat its only purpose.

**The cost** is that a shared key is shared. Losing one card exposes the decryption key for
every card, and replacing it means re-provisioning all of them.

## Answer two: rotate, and archive the old keys

The alternative is to let each card have its own decryption key and keep the superseded ones
readable. That is precisely what the PIV retired slots are for: `0x82`–`0x95` are *Retired Key
Management* keys, twenty of them.

Name the superseded generations while provisioning the new one, newest first:

```
mind-the-gap piv -k gen3 --retire gen2 --retire gen1 upload
  0x82 <- sub:gen2 -> key:key-management
  0x83 <- sub:gen1 -> key:key-management
```

The archived key is byte for byte the key that generation used live, because slot keys derive
by the *role* they serve rather than the slot they sit in: `key:key-management` under an older
subseed is the same key whether it lives in 9D or in 0x82. Each archived slot gets its own
certificate, qualified by the generation it belongs to rather than the one running the card, so
an old certificate says which rotation it came from:

```
dnQualifier=mtg1:gen1, CN=Florian Franzen
```

Archived slots are ordinary parts of the chain, so `certify` reproduces them offline and
`check` verifies them alongside the live slots. They keep slot 9D's policies, since that is
what they are. Twenty generations fit; a twenty-first is an error rather than a silent drop.

Declaring them during provisioning is not an arbitrary choice. `upload` factory-resets the
card, so a second invocation to add an archived key would wipe what it was meant to preserve,
and the management key authorising the write belongs to the generation running the card while
the archived key belongs to an older one. Doing it in one pass is the only place both are
known.

**Retire decryption keys, destroy signing keys.** The intuition usually runs the other way, so
it is worth stating plainly. Old decryption keys must be kept or old ciphertext is lost. Old
signing keys should be destroyed: an old signature is verified against its archived
certificate, never against the private key, so keeping the key only creates the ability to
forge backdated signatures. Authentication keys are live credentials with no historical value.

### Choosing between them

| | share | rotate and archive |
|---|---|---|
| new mail readable on | every card | the current card |
| old mail readable on | every card | the card that held the key, via its retired slot |
| losing one card exposes | the shared decryption key, everywhere | that card's generation only |
| replacing a card | re-provision all cards | provision the new one, archive the old |
| available today | yes | yes |

Share when the cards are peers you use interchangeably. Rotate when they are a succession, or
when a lost card must not compromise the others.

## What `--intermediate` changes

`--intermediate` inserts an issuing CA between the root and the slot certificates. With several
cards it does something more useful than adding a tier: **each subkey id gets its own issuing
CA**, with a distinct subject and a distinct key.

```
laptop   CN=Florian Franzen PIV Issuing CA laptop    key b550201d…
desktop  CN=Florian Franzen PIV Issuing CA desktop   key 9707e372…
```

That turns a card into a single revocable unit. Without an intermediate, retiring a card means
revoking four leaf certificates, all listed on the root's CRL. With one, you revoke that card's
issuing CA — one entry — and its four leaves fall with it.

It costs an extra tier in every path, and the root must assert `pathLenConstraint: 1`, which the
tool handles. For a single card it buys little. For a fleet it is the difference between a CRL
that lists four entries per lost card and one that lists one.

## Revocation, and what you would have to host

### OpenPGP

`mind-the-gap pgp revoke` exists and works. It re-derives the primary key from the seed, so a
revocation certificate can be produced **at any time, air-gapped, without the card** — you do
not need to pre-generate one and store it somewhere safe, which is the usual ceremony. Reason
codes follow the OpenPGP set (`0` unspecified, `1` superseded, `2` compromised, `3` retired,
`32` UID retired, `100`–`110` private).

Hosting requirement: none beyond publishing the updated certificate wherever people fetch it —
a keyserver, WKD, your website.

`--kind subkeys` narrows it to one card. A subkey is revoked by its primary, and the primary is
re-derivable from the seed, so a lost card can be retired without it present and without
touching the identity or any other card:

```
mind-the-gap pgp -k laptop revoke --kind subkeys -c 1 -t "laptop lost"
```

What comes out is the certificate carrying the revocations, because a lone subkey revocation
signature has nothing to attach to. Import or publish it and that card's three subkeys read as
revoked while the user id and every other card stay live. This is the payoff for giving each
card its own subkey id.

### PIV

Nothing today. X.509 has no self-revocation: a certificate is revoked by its issuer publishing
a statement, which means a CRL or OCSP.

**A static CRL file is the right answer for most people**, and it is feasible — but it needs
three things, and the tool currently provides none of them.

1. **A CRL, signed by the issuing authority.** Derivable offline like everything else, so this
   part fits the air-gapped model: the root key comes back from the seed, and the certificate
   serial numbers are deterministic, so a CRL can be issued for a card that is not present.
2. **A URL in the certificates.** This is the part people miss. The chain currently carries
   **no `cRLDistributionPoints` extension** — verified: no CDP and no AIA on any certificate in
   the chain — so no verifier will look for a CRL, and one published today would be ignored by
   everything. The extension has to be baked in at issuance, which means deciding the URL
   *before* provisioning. Adding it later means re-issuing and re-uploading every card.
3. **Somewhere to serve it.** Any static host will do: object storage, a web server, GitHub
   Pages. It is one file, fetched over plain HTTP by design — a CRL is signed, so it needs no
   transport security.

The wrinkle in "static" is that a CRL expires. It carries `thisUpdate` and `nextUpdate`, and
clients reject one that is past `nextUpdate`, so the file has to be re-signed periodically
whether or not anything was revoked — and re-signing needs the seed, which means an air-gapped
session on a schedule. A long `nextUpdate` reduces that burden but lengthens the window in
which clients keep trusting a cached CRL after you revoke something. Somewhere around 90 days
is the usual compromise.

OCSP is strictly worse here: it needs a responder that is online and signing, which defeats the
point of deriving everything from an offline seed.

**The cheapest alternative is not to revoke at all.** Because each card's keys derive from its
own subkey id, retiring a card can simply mean re-provisioning under a new one and no longer
trusting the old certificates — which needs no infrastructure whatsoever. With
`--intermediate`, "no longer trusting" has a natural unit: that card's issuing CA. This is a
perfectly respectable answer for a personal fleet, and it is the only reason the missing CRL
support is not urgent.

## Summary

- Always set `--subkey`, one per card. The machine name is a good id.
- It is public, and appears in certificates. Use `--password` if you want secrecy.
- Signing and authentication need no further thought.
- For encryption, pick: `--shared decryption` for interchangeable cards, or rotate and archive
  for a succession.
- Use `--intermediate` once you have a fleet, so a card is one revocable unit.
- Decide your CRL URL *before* provisioning, or plan to re-issue.
