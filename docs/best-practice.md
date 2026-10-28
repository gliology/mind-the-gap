# Why it is built this way

The [recommended flows](flows.md) follow established key management practice, mostly NIST SP
800-57 (key management), SP 800-73-4 and FIPS 201 (PIV), and the OpenPGP conventions that
mail clients rely on. This chapter says which practice each choice follows, and what it costs.

## Key separation

SP 800-57 part 1 (section 5.2) asks that a key serve one purpose, so that a compromise in one
use does not spill into another. mind-the-gap applies that one level up, to the seeds: the
card seed administers cards and derives no usable key; the key seed derives an identity and
its keys and opens no card.

With the two apart, a leak is contained:

- A leaked **card seed** exposes the cards' credentials, which let someone holding a card
  replace its keys, but no key and no identity. Initialize the cards again under a new card
  seed; the identities and every signature they made stay valid.
- A leaked **key seed** exposes the identity and its keys, but not the cards. Revoke the
  identity's keys and [migrate](rotation.md#moving-off-a-leaked-key-seed) every card to a new
  key seed; the cards keep answering to their administrator throughout, and the old decryption
  key moves to a retired slot so that what was encrypted to it stays readable.

One phrase in both roles, the personal flows, gives that up for less to keep safe: a leaked
phrase is everything. The [hardened flow](flows.md#hardened) is the separated one, and adds
the `strict` policy: a touch before every use of every key, so malware on a machine the card
is plugged into cannot quietly use it.

## Per-card credentials

SP 800-73-4 and the vendors' guidance (Yubico's among them) ask for a unique management key
per card, rather than the factory key or one key for a fleet. Every credential mind-the-gap
derives carries the card's serial as its last segment, so the management key, the puk and the
admin pin differ on every card, and the one captured from a compromised machine's session
opens no other card. They are derived rather than generated, so the card seed recovers them
whenever needed, and there is no credential database to protect, lose or back up.

The puk is derived too, rather than blocked as before 1.0: a forgotten or blocked pin is set
anew with `pin --reset` from the air-gapped side, without wiping a key. The puk counts its
tries like any puk, so a wrong card seed blocks it after three, and `pin --reset` refuses to
spend the last one.

## One certificate per identity, one decryption key per identity

A verifier accepts a signature from any valid signing subkey of a certificate, and an SSH
server checks whichever authentication key is offered, so per-device signing and
authentication keys under one certificate just work, and each device's keys can be revoked
alone when the device is lost. That is what the subkey id is for.

Encryption is the other way round: the sender picks the key. gpg encrypts to the newest
encryption subkey of a certificate, other clients to all or to one, and none knows which card
the recipient will read with. Per-device decryption keys would leave mail readable on some
cards only. So the decryption key is derived without the device step, and every card of the
identity holds the same one; on PIV, 9D likewise, with one certificate on every card.

The cost is that the decryption key is as exposed as the most exposed card; [several cards
and identities](multiple-cards.md#encryption-one-key-for-the-identity) says what that means
in practice.

## Distinct identities get distinct certificates

A host, a service or a team is not a device of a person: it acts on its own, is handed over,
and is revoked on its own schedule. It gets its own key seed, so its own certificate, keys and
root authority, which the person can certify with [trust](commands.md#trust), rather than
subkeys in the person's certificate.

A subaddress (`user+ci@example.org`) belongs there, on the distinct identity's certificate,
and not on a person's device subkeys. It costs something: the label is public, mail delivery
needs the provider to support subaddressing, and keyservers and Web Key Directories publish and
verify every address separately. Devices of one person carry no device label at all, in their
OpenPGP certificate or in their PIV certificates: a device is told by its keys.

## Shared keys

A key seed held by several people is a shared key: every holder can derive every key and act
as the identity, which is equivalent to an escrowed key handed to each. That is acceptable, and
often the point, for a team's code signing key or a shared mailbox, as long as everyone holding
the seed is trusted with the identity. Where a team needs to know who signed, give each person
their own key seed and let the team's identity certify them.

## Rotation and cryptoperiods

SP 800-57 part 1 (section 5.3) gives every key a cryptoperiod, after which it is replaced. A
key generation is a step of the derivation, `date:<YYYY-MM-DD>`, so generations are
reproducible and auditable: the date is the keys' creation time, visible in every certificate
and fingerprint.

**Keep decryption keys, retire signing and authentication keys.** The intuition usually runs
the other way. Old decryption keys must be kept, or old ciphertext is lost; on PIV they move
to [retired slots](multiple-cards.md#retired-slots). Old signing keys should be gone: a
signature already made is verified against its certificate, never against the private key, so
keeping the key only keeps the ability to forge backdated signatures. Authentication keys are
live credentials with no historical value. So on rotation the first are kept and the others
revoked.

Set `--validity` to the cryptoperiod you choose, and rotate before it ends; see [rotation, revocation and
recovery](rotation.md). A validity counts from the day the keys were created, so it needs a
generation date, `--date` or `--identity-date`; keys without one are created at the epoch, and
`--validity` without a date is refused rather than issuing certificates that expired long ago.

## Ceremonies and configuration

A documented key ceremony is a written procedure, run step by step, with a record. A
[ceremony](ceremonies.md) file is that procedure, and `run` follows it: each step shown before
it runs, the run stopped at the first failure, a dry run to rehearse, and a transcript with
the file's hash. Neither a ceremony nor a config file can hold a secret, and on the live image
both are read-only, built into the image from its configuration.
