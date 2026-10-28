# PIV certificate chain

The PIV applet gets a full X.509 chain rather than a set of self-signed certificates, so that
the card works with S/MIME, TLS client authentication, SSH and smartcard logon:

```
Root authority (self-signed, CA:TRUE)                   the identity, from the key seed
└── (an issuing authority per device and generation, with --intermediate)
    ├── 9A authentication   digitalSignature                    clientAuth, msSmartcardLogon
    ├── 9C signature        digitalSignature, nonRepudiation    emailProtection
    └── 9D key management   keyAgreement                        emailProtection, clientAuth

9E card authentication (self-signed)  digitalSignature  id-PIV-cardAuth    the card, from the card seed
```

By default all keys are NIST P-256 and every certificate is signed with `ecdsa-with-SHA256`.
With `--algorithm curve25519` the whole chain moves to Curve25519: the authorities and slots
9A, 9C and 9E hold Ed25519 keys and every certificate is signed with `id-Ed25519`, while slot
9D holds an X25519 key (RFC 8410). Either way slot 9D uses `keyAgreement` rather than
`keyEncipherment`, because these are key agreement keys and RFC 8813 forbids the latter on EC
keys. With `--algorithm rsa2048`, `rsa3072` or `rsa4096` every key is an RSA key of that size
and every certificate is signed with `sha256WithRSAEncryption`, PKCS#1 v1.5 being as
deterministic as the other two; there slot 9D transports keys rather than agreeing on them and
takes `keyEncipherment` instead. The algorithm is part of every key's derivation label, so the
chains share nothing; see the [derivation chapter](derivation.md#the-algorithm-segment).

Slots 9A, 9C and 9D are bound to the cardholder and carry the identity's emails as alternative
names. All of them carry the identity's subject, on every card alike: 9A and 9C are the
device's, told apart from another device's by their keys and serials, as no certificate names a
device; 9D is the identity's, the same key on every card, and so is its certificate, as long as
the root issues it; with `--intermediate` its issuer is the device's issuing authority, so each
device has a 9D certificate of its own for the one key.

The authorities are named after the identity. The root is `CN=<name> PIV Root CA <algorithm>`,
the algorithm spelled as `--algorithm` takes it (`p256`, `p384`, `curve25519`, `rsa2048`,
`rsa3072`, `rsa4096`): the root derives from the key seed and the algorithm alone, so the
algorithm is what tells one identity's roots apart, and it says nothing the root's key does not
show. The issuing authority is named by a tag of its own key, `CN=<name> PIV Issuing CA <tag>`
(see [derivation](derivation.md#piv-certificates-from-the-seed)). With `--org`, `--unit` and
`--country`, every subject but 9E's carries `O`, `OU` and `C` as well.

Every subject fits the bounds RFC 5280 sets in its appendix A.1, which strict verifiers hold a
certificate to: 64 characters for a common name, an organization and an organizational unit,
two letters for a country. The longest common name is the issuing authority's, the name and 24
characters more, so `--name` takes at most 40 characters whatever the algorithm and whether
there is an issuing authority, since an identity keeps its name when it adds either later;
`--org` and `--unit` take 64 each, and `--country` two uppercase letters, such as `DE`. The
bounds count characters as given, not bytes and not the escapes a subject adds. Where PIV is
named, with `--app piv` or a `--slot`, or is among the applets a verb that needs no card acts
on, a name past its bound is refused before any seed is stretched; `upload` and `rotate`
without `--app` judge it once the card has decided the applets, still before anything is
written, and `check` without `--app` leaves PIV out with a warning and compares the rest. An
OpenPGP user id has no such bound.

9E is bound to the card and carries no email address, as FIPS 201-3 section 4.2.3 requires. Its
key and its certificate come from the card seed and the card's serial, not the key seed: the
certificate is signed by its own key, says which card this is (`CN=PIV Card mtg1:<card id>`),
and whoever relies on that pins the key it carries, the way a door reader enrols a card.

With `--crl-url`, every certificate names the revocation list of its issuer as its CRL
distribution point, which is where verifiers look for it: what the root issues itself (the slot
certificates, or the issuing authority where there is one) names the root's list, and what an
issuing authority issues names that authority's own. Each list has a URL of its own, made from
the one given; [revocation](rotation.md#piv) says how, and how to keep the lists there. The
root names none, since nothing above it could revoke it, and neither does 9E, which is its own
issuer. The URL is part of the certificates, so like the names it is given the same way every
time.

Publish the root authority with `publish --app piv --part identity` and install it as a trust
anchor; `publish --app piv` writes the whole chain. The authorities are also written to the
card's `msroots` object, where the Windows minidriver picks them up, whenever the identity's
keys go onto the card. [After the
gap](after-the-gap.md#the-piv-certificate-chain-as-a-trust-anchor) says where each goes on the
machines that use the card.

Certificate generation is fully deterministic: signing uses RFC 6979 deterministic ECDSA
nonces (Ed25519 and PKCS#1 v1.5 are deterministic by construction), the root's creation time is
`--identity-date` and the keys' is `--date` (the identity's without one, the unix epoch
without either), and the serial
numbers are hashes of what makes each certificate itself (see [derivation](derivation.md#piv-certificates-from-the-seed)).
So `publish` on any machine, with no card present, produces exactly the certificates `upload`
writes.
