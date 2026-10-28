# Glossary

The terms this book uses in a sense of its own, in alphabetical order.

**Applet.** One of the two applications a card carries that mind-the-gap provisions: PIV or
OpenPGP. `--app piv` or `--app pgp` names one; without it a verb acts on each the card
carries. Each is reset, initialized and checked on its own.

**Card identifier.** What `init` writes into an OpenPGP card's private-use data object 0102,
`mtg1:` and an `id:card` derivation of the card seed and the card's serial, so that `list`
and `check` can tell which card seed initialized the card. Not to be confused with the
*OpenPGP identifier* `MMMM:SSSSSSSS` (manufacturer and serial, as `0006:12345678`) by which
`--card` names an OpenPGP card. A PIV card shows which card seed initialized it in its CHUID
and in the subject of its 9E certificate instead, `CN=PIV Card mtg1:<card id>`: identifiers
derived from the card seed and the card's serial, which reveal nothing of the seed. See
[published identifiers](derivation.md#published-identifiers).

**Card seed.** A seed in its role of administering cards: it derives each card's management
key, puk, admin pin and identifiers, bound to the card's serial, and no usable key. One phrase
is usually both the card seed and the key seed; `--card-seed` gives it apart.

**Ceremony, recipe, step.** A *ceremony* is a file of named *recipes*, each a list of *steps*
that run after the recipes it depends on; a step is one command line, as a session takes it.
`run` runs one recipe. See [ceremonies](ceremonies.md).

**Generation.** The day a set of keys was made, `--date`, which is a step of the derivation
(`date:<YYYY-MM-DD>`) as well as the keys' creation time. A rotation moves a card to a new
generation. See [the key path](derivation.md#the-key-path).

**Identity.** What a key seed stands for: a person, a team, a service or a host, with its own
OpenPGP certificate (its primary key and user ids) and its own PIV root authority. Its usable
keys sit under it, and the identity's *creation date* is `--identity-date`.

**Issuing authority.** With `--intermediate`, a certificate authority between the PIV root
authority and the slot certificates, one per device and generation, so that a device's
certificates are revoked as one unit. It is named by a tag of its own key. See [an issuing
authority per device](multiple-cards.md#an-issuing-authority-per-device).

**Key seed.** A seed in its role of an identity: it derives the identity and every key it
uses, and opens no card. `--key-seed` gives it apart from the card seed.

**Plumbing.** The mode for programs, `--plumbing`: one JSON object per command on stdout,
nothing asked, and the first error stops. See [plumbing mode](interfaces.md#plumbing-mode).

**Policy mode.** One of the words `--policy` takes (`strict`, `relaxed`, `once-pin`, …), each
a choice of pin and touch requirements that mind-the-gap maps onto what each applet can
express. See [pin and touch policies](policies.md).

**Record.** What `check` shows first and what is written down next to the phrase: the seed id,
the SHA-256 of the PIV root authority and the fingerprint of the OpenPGP primary key. Not to be
confused with a ceremony's transcript, which `run --record` keeps.

**Retired slot.** One of the twenty PIV key management slots `82` to `95`, which keep
decryption keys that are no longer current but must keep decrypting: a previous generation's,
or another identity's. See [retired slots](multiple-cards.md#retired-slots).

**Root authority.** The PIV certificate authority of an identity, derived from the key seed
and the algorithm, one per algorithm and named by it, `CN=<name> PIV Root CA p256`, which
certifies the slot certificates (or the issuing authorities) and is what relying parties
install as a trust anchor. See [PIV certificate chain](piv-certificates.md).

**Scheme.** The set of derivation rules a release derives under: `mtg1` for the 1.x
releases, the stamp its identifiers carry, and `mtg0` by convention for the 0.x releases,
which stamped nothing and which `--legacy` keeps for OpenPGP cards. See
[compatibility](compatibility.md).

**Seed.** The 32 bytes argon2id makes of a phrase and its optional password, from which
everything descends. It plays two roles, card seed and key seed.

**Seed id.** A short public value derived from a seed, shown by `generate` and `check`.
Written down with the phrase, it tells a mistyped phrase or password from the right one. See
[the seed id](derivation.md#the-seed-id).

**Subkey id.** The name of the device (or other use) a set of keys is bound to,
`--subkey`, a step of the derivation (`sub:<id>`). It is no secret, and nothing published
carries it: a device's certificates and subkeys are told apart by their keys. Not to be
confused with an *OpenPGP subkey*, a key under an OpenPGP primary key: the signing and
authentication subkeys derive under the subkey id, but the decryption subkey is the identity's
and does not.
