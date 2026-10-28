# Key derivation

Every key, pin, identifier and certificate mind-the-gap writes is a function of a seed and a
path of labels, and nothing else. That is the whole product: the same phrase, given the same
options, re-derives the same cards years later, byte for byte, so there is nothing to back up
but the paper.

## From the phrase to a seed

`generate` mints 24 word phrases, which carry 256 bits of entropy (and 8 bits of checksum);
phrases of 12 to 24 words are accepted, see [the algorithm segment](#the-algorithm-segment) for
what a shorter one costs. The phrase's entropy and the optional password go through
`argon2id` (64 MiB, three passes, one lane) to make the **seed**, and every step down from
there is another `argon2id` pass over the parent's 32 bytes, with a label for salt:

```
seed  = argon2id(entropy,      "MINDTHEGAP256HDKD" || password)
child = argon2id(parent seed,  "MINDTHEGAP256HDKD" || label)
```

These parameters are frozen constants of the scheme, exactly like the labels below: tuning
them would move every key, so a change ships as a new scheme behind a new major version
([compatibility](compatibility.md)).

Two properties of this construction are deliberate. There is no random salt, because
determinism is the point: the same phrase must re-derive the same keys years later, and
uniqueness comes from the 256 bits of entropy instead. And the password enters in the salt
position rather than the password input; argon2 folds both into its initial state
symmetrically, so this is equivalent in strength, and the context prefix keeps the salt above
the format's minimum length even with no password at all.

The password is taken in Unicode NFKD, as BIP-39 takes its passphrase. Keyboards and systems
differ in how they spell the same character (`ä` as one code point, or as `a` and a combining
diaeresis), and full-width forms fold to their plain ones, so a password derives the same keys
however it was typed. A plain ASCII password is its own NFKD form.

## The tree

A seed plays two roles. As the **card seed** it derives what administers a card: each card's
credentials and identifiers, every one of them bound to the card's own serial. As the **key
seed** it derives an identity and its usable keys. One phrase is usually both; `--card-seed`
and `--key-seed` give either apart (see [the flows](flows.md)).

```
seed
├── id:seed                                       the seed id
├── app:piv/
│   │  as the card seed, for the card with serial <serial>:
│   ├── pin:management:aes256:<serial>            management key, AES-256
│   ├── pin:management:tdes:<serial>              management key, 3DES
│   ├── pin:puk:ascii:<serial>                    puk
│   ├── id:chuid:<serial>                         CHUID Card UUID (version 4 bits set)
│   ├── id:ccc:<serial>                           CCC card identifier
│   ├── id:card:<serial>                          card id, in the 9E subject
│   ├── key:card-authentication:<alg>:<serial>    card authentication key, 9E
│   │  as the key seed:
│   ├── key:root-ca:<alg>                         root authority
│   ├── [sub:<id>/][date:<iso>/]
│   │   ├── key:issuing-ca:<alg>                  issuing authority (--intermediate)
│   │   ├── key:authentication:<alg>              9A
│   │   └── key:signature:<alg>                   9C
│   └── [date:<iso>/]
│       └── key:key-management:<alg>              9D, or a retired slot
└── app:pgp/
    │  as the card seed, for the card with serial <serial>:
    ├── pin:admin:ascii:<serial>                  admin pin
    ├── id:card:<serial>                          card identifier, data object 0102
    │  as the key seed:
    ├── key:primary:<alg>                         primary key
    ├── [sub:<id>/][date:<iso>/]
    │   ├── key:signature:<alg>                   signing subkey
    │   └── key:authentication:<alg>              authentication subkey
    └── [date:<iso>/]
        └── key:decryption:<alg>                  decryption subkey
```

The identity sits directly under the applet's subtree: the PIV root authority and the OpenPGP
primary key are siblings of the keys, not their parents. Were the authority the parent,
anyone holding its key could re-derive every key it certifies.

## Derivation labels

Each label is `<prefix>:<name>`, with names lowercase and hyphenated, and the prefix says what
comes out:

| prefix | meaning | output |
|---|---|---|
| `app` | an applet's subtree | intermediate seed |
| `sub` | a device, by its subkey id | intermediate seed |
| `date` | a key generation, by its day | intermediate seed |
| `key:<name>:<algorithm>` | key material for one algorithm | 256 bits (384 on P-384, see below) |
| `key:<name>:<algorithm>:<serial>` | a card's own key | 256 bits |
| `pin:<name>:<kind>:<serial>` | a credential of one card | as its kind says |
| `id:<name>` | an identifier | truncated to what the format takes |
| `id:<name>:<serial>` | an identifier of one card | truncated to what the format takes |

The prefix carries the use, so two derivations cannot agree just because their names match:
`key:authentication:p256` and `id:card` are different bytes, as are PIV's
`key:authentication:p256` and OpenPGP's, which sit under different `app:` subtrees.

### Credentials and the card serial

Every credential is a `pin:` label whose last two segments are its **kind** and the card's
**serial**. The kind says what the bytes become, so one name never hands the same bytes to two
encodings:

| label | becomes |
|---|---|
| `pin:management:aes256:<serial>` | the whole 32 bytes, the AES-256 management key |
| `pin:management:tdes:<serial>` | the first 24 bytes, the 3DES management key ([below](#the-piv-management-key)) |
| `pin:puk:ascii:<serial>` | the first 8 characters of the bytes in base64, the PIV puk |
| `pin:admin:ascii:<serial>` | all 43 characters of the bytes in base64, the OpenPGP admin pin |

The serial is the card's own: what a PIV card reports for itself (a YubiKey's serial number,
the trussed PIV applet's), in decimal, and the manufacturer and serial of an OpenPGP card's
application identifier, in lowercase hex as `mmmm-ssssssss`. Binding every credential to it is
what makes them per-card: the management key captured from one machine's session opens no
other card, though one card seed administers them all, and nothing has to be stored to find
a card's credentials again. A card's own identifiers and its 9E key take the serial too, so
two cards of one card seed share nothing a reader could link.

The user pin is no part of any derivation. It is the card holder's, chosen at `init` and
changed with `pin`.

### The key path

The usable keys sit under the key seed along a path of two optional steps:

- `sub:<id>`, the **subkey id**: the device (or other use) the keys are bound to. Without
  `--subkey` there is no step.
- `date:<YYYY-MM-DD>`, the **generation**: the day the keys were made. Without `--date` it is
  the `--identity-date`, since no key can be older than the identity that certifies it, and
  without either there is no step. The day is also the creation time of the keys and their
  certificates (midnight UTC, never local time), so a fingerprint or a certificate shows which
  generation it is.

A device's own keys (authentication and signature) take both steps. The decryption key takes
only the date: it is the identity's, the same on every card of the identity
([why](best-practice.md#one-certificate-per-identity-one-decryption-key-per-identity)). With
neither step, the keys derive directly under the applet, next to the identity.

**The subkey id is no secret, and no certificate carries it.** It is a step of the derivation
and nothing else: the PIV certificates of every card of an identity carry the identity's
subject, the OpenPGP subkeys no device name, and a device's keys are told apart by what they
are. Treat it as a name, not a password: the machine a card belongs to makes a good one. The
`sub:` prefix is what makes any text safe as an id: without its own prefix an id equal to a
fixed label would silently collapse two keys into one. If you want a second secret that
separates one set of keys from another, that is what the password is for.

PIV slot keys are named for the *role* they serve (`key:key-management`), not the slot they
occupy, because the retired slots hold earlier or other identities' decryption keys: a key has
to derive the same whether it lives in 9D or in 0x82.

### The seed id

`id:seed`, directly under the seed, is a short public value: its first 8 bytes in hex, shown by
`check`. A phrase has a checksum, a password does not, so a typo in the password derives a
different seed without a word. Written down next to the phrase, the seed id is what catches
that: compare it every time the phrase is typed in again. Eight bytes of an argon2 output say
nothing about the seed that the identity's public keys do not.

## The algorithm segment

Every asymmetric key carries the algorithm it is derived for as a segment of its label:
`key:signature:ed25519`, `key:key-management:p256`. The segment names what the bytes become,
with the RFC names rather than OpenPGP's: `p256` for ECDSA and ECDH on NIST P-256, `p384` for
the same on NIST P-384, `ed25519` for Ed25519 signing keys, `x25519` for X25519 key agreement
keys, and `rsa2048`, `rsa3072` or `rsa4096` for RSA keys, which sign and decrypt under the same
name.

`--algorithm` picks the algorithm for every key a command derives, identity included; without
it OpenPGP derives Curve25519 keys and PIV P-256 ones. Another algorithm derives under
different labels, so the keys share no material and none can be computed from another.

| applet | key | `curve25519` (OpenPGP default) | `p256` (PIV default) | `p384` (PIV only) | `rsa2048`, `rsa3072`, `rsa4096` |
|---|---|---|---|---|---|
| OpenPGP | primary, signing, authentication | EdDSA on Ed25519 | ECDSA on P-256 | refused | RSA, PKCS#1 v1.5 signatures |
| OpenPGP | decryption | ECDH on Curve25519 | ECDH on P-256 (SHA-256, AES-128 KDF) | refused | RSA encryption |
| PIV | root and issuing authorities, 9A, 9C, 9E | Ed25519 | ECDSA P-256 | ECDSA P-384, SHA-384 signatures | RSA, `sha256WithRSAEncryption` |
| PIV | 9D and retired slots | X25519 | ECDH P-256 | ECDH P-384 | RSA key transport |

P-384 is for PIV alone: the OpenPGP applet refuses it. Which algorithm a card can hold is in
[supported cards](supported-cards.md). The legacy OpenPGP scheme predates the segment and
refuses `--algorithm` ([compatibility](compatibility.md#mtg0-the-0x-releases)).

## RSA keys from the seed

An elliptic curve key is 32 bytes, so the 256 bits a label derives *are* the key. An RSA key
is two primes of half the modulus size each, so the derived bytes are stretched instead, by a
procedure that is as frozen as the labels: the same seed gives the same primes forever.

1. The derived 32 bytes go into SHAKE256, behind the ASCII context `MINDTHEGAPRSA` and the
   modulus size as a big-endian 16-bit number. Its output is read front to back as one
   stream.
2. Each candidate is the next modulus-size/16 bytes of the stream, read big-endian, with its
   two top bits and its lowest bit set. The top bits make every product of two candidates
   exactly the modulus size; the low bit makes the candidate odd.
3. `p` is the first candidate that is prime and for which `p - 1` is not a multiple of the
   public exponent 65537.
4. `q` is the first later candidate with the same properties that also differs from `p` by
   more than 2<sup>size/2 - 100</sup>.

These are the checks of FIPS 186-5 appendix A.1.3, the generation of probable primes,
which also allows keeping the seed a key was generated from, provided it is protected like
the key itself. The procedure has no other moving part: whether a number is prime is a
property of the number, not of the test that finds out, so any correct implementation of the
four steps arrives at the same key, and the golden vectors in the test suite were computed
by one written independently of this crate. The public exponent is always 65537, the only
one Yubico's tools import.

A key is never stronger than the phrase it comes from; [the security
chapter](security.md#a-key-is-no-stronger-than-its-phrase) rates each algorithm against the
phrase's entropy.

## P-256 scalars

A P-256 secret scalar is the 32-byte argon2id output itself, read big-endian. A candidate
outside `[1, n-1]` is rejected and the output moves on to `argon2id(output, "key:p256-retry")`
until one lies inside, a 2^-32 event per key.

## P-384 scalars

One argon2id output is 256 bits and a P-384 secret scalar takes 384, so a P-384 key is
assembled from two outputs. With `A = argon2id(parent, "key:<name>:p384")` and
`B = argon2id(A, "key:p384-extend")`, the scalar is the 48 big-endian bytes `A || B[0..16]`.
Like every NIST scalar it has to lie in `[1, n-1]`; a candidate outside is rejected and `A`
moves on to `argon2id(A, "key:p384-retry")` before the extension is taken again. `n` begins
with 192 one bits, so a rejection is a 2^-190 event that only keeps the definition total.
`B` adds width, not entropy: the key is as strong as the 256-bit `A`, which is already
beyond what P-384 itself offers (192 bits).

## The PIV management key

The management key in slot 9B authenticates every administrative operation on a PIV card. It
derives from the card seed, bound to the card's serial, in one of two algorithms:

| algorithm | label | key |
|---|---|---|
| AES-256 | `pin:management:aes256:<serial>` | the whole 32-byte output |
| 3DES | `pin:management:tdes:<serial>` | the first 24 bytes of the output |

3DES is the only management key a YubiKey 4, or a YubiKey 5 before firmware 5.4, accepts, and
it is an independent derivation rather than a truncation of the AES key, so the two never share
bytes. A 3DES key is rejected when one of its three DES keys is one of the four weak or twelve
semi-weak DES keys, or when two of them coincide (either collapses the cipher towards single
DES), parity bits ignored in both comparisons; the output then moves on to
`argon2id(output, "key:tdes-retry")` and its first 24 bytes are tried again. The odds of that
are about 2^-50.

`init --management-algorithm auto` (the default) installs AES-256 when the card reports
firmware 5.4 or later and 3DES otherwise; `aes256` and `tdes` force one. Everything that
authenticates later asks the card which algorithm it holds and derives that key, so it needs
no flag.

## Published identifiers

Identifiers a card or certificate shows are stamped with the scheme that produced them, so
they can be read back and understood without guessing:

```
CN=PIV Card mtg1:776AD915                     slot 9E subject, from id:card:<serial>
mtg1:CD6F70E62D08FD7564741C4CA85E97BB          OpenPGP data object 0102, from id:card:<serial>
```

The marker is on the identifiers, not in the derivation labels. Relabelling already moves
every key, so a version in the derivation path would separate nothing that changing the scheme
had not separated already, and each level of the path costs an argon2 pass to carry.

The OpenPGP card identifier is how an OpenPGP card says whose it is. A PIV card shows its card
seed in its CHUID and its 9E certificate; an OpenPGP card has nothing of the kind, so `init`
writes `id:card:<serial>` into the private-use data object 0102, readable without a pin and
writable only with the admin pin (which is why it is 0102 rather than 0101, which the user pin
can write). A card without private-use data objects gets none, and cannot show who
administers it.

No published identifier names a device. The person-bound PIV certificates (9A, 9C, 9D and the
retired slots) carry the identity's subject on every card, and the OpenPGP subkeys carry no
device name; a device shows only in which keys a card holds, and those say nothing of the
subkey id they derive from.

## PIV certificates from the seed

A PIV certificate is derived like everything else: its key, its subject, its validity, and its
signature, which is RFC 6979 deterministic ECDSA, pure Ed25519 or PKCS#1 v1.5, all
deterministic. Its serial number is the last 20 bytes of the SHA-256 of everything the
certificate says but its serial and signature (the to-be-signed certificate, built with a
placeholder serial), with the top bit cleared: one certificate re-issues with the same serial,
and a certificate re-issued with another name, validity, issuer, emails or list URL gets
another, as RFC 5280 asks of an issuer. The 9E certificate is signed by its own key: the card
seed holds no authority of the identity's, and needs none to say which card this is.

The root is named by its algorithm, `CN=Jane Doe PIV Root CA curve25519`, spelled as the
command line spells it rather than as its key's label does (`key:root-ca:ed25519`): the root
derives from the key seed and the algorithm alone, so the algorithm is what tells one
identity's roots apart.

The issuing authority `--intermediate` inserts is named by its own key, as no certificate names
a device: `CN=Jane Doe PIV Issuing CA 9B3E5D17`, where the tag is the first four bytes of the
authority's subject key identifier (the SHA-1 of its public key, RFC 5280 section 4.2.1.2),
written in uppercase hex as OpenSSL shows the identifier. Its key derives under the device, the
generation and the algorithm, so each of them names the authority apart, and the tag reveals
nothing the certificate's key identifier extension does not. Its revocation list is named by
the algorithm and the same tag in lowercase hex, in its URL and its file name
(`jane-p256-issuing-9b3e5d17.crl`, see [revocation](rotation.md#piv)). The
tag carries no `mtg1:` stamp: it is a standard digest of a public key, not an output of the
derivation, and a colon has no place in a file name.

## OpenPGP signatures from the seed

An OpenPGP certificate is derived like a PIV one, its signatures included, so another
implementation can rebuild it byte for byte from the keys and these rules:

- Every signature is a version 4 signature over SHA-512, and carries no salt notation (the
  `salt@notations.sequoia-pgp.org` notation upstream sequoia adds, see
  [the forked sequoia-openpgp](security.md#the-forked-sequoia-openpgp)).
- Ed25519 signs as pure EdDSA (RFC 8032) and RSA with PKCS#1 v1.5, both deterministic by
  construction. P-256 signs as ECDSA with the nonce of RFC 6979, its HMAC on SHA-512, the
  signature's own hash, and no additional data (the k' of section 3.6). s is used as
  computed, not normalized to the lower half of the group order.
- Creation times are fixed. The primary key, its direct key signature, the user id
  certifications, `trust` certifications and the certificate revocation carry the identity's
  time; the subkeys, their bindings and the back-signatures the generation's
  ([the key path](#the-key-path)); a subkey revocation the later of the two. Without a date
  the time is one second after the Unix epoch, since OpenPGP reads a creation time of zero as
  none.
