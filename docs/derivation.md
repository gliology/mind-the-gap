# Key derivation

## Mnemonic to primary and subkeys


While the project was inspired by the key derivation cryptography used in bitcoin and substrate, we ended up switching to `argon2id` for our key derivation function.
This tools generates and accept only 24 word seeds, which is equivalent to 256bits of entropy (and 8 bits of checksum). 
All keys are derived from this root entropy through multiple rounds of `argon2id` (64 MiB, three passes, one lane). These parameters are frozen constants of the scheme, exactly like the labels below: tuning them would move every key, so any change ships as a new scheme behind a new major version.

The salt is always set to at least `MINDTHEGAP256HDKD` and optionally followed by an additional context like a password, (sub-)key or application identifiers. Two properties of this construction are deliberate. There is no random salt, because determinism is the point: the same phrase must re-derive the same keys years later, and uniqueness comes from the 256 bits of seed entropy instead. And the optional password enters in the salt position rather than the password input; argon2 folds both into its initial state symmetrically, so this is equivalent in strength, and the context prefix keeps the salt above the format's minimum length even with no password at all.

```
256-bit mnemonic seed/
└── (optional password)/
    ├── "openpgp"/
    │   ├── primary key
    │   ├── (optional subkey id)/
    │   │   ├── admin pin
    │   │   ├── signing subkey
    │   │   ├── decryption subkey
    │   │   └── authentication subkey
    │   └── (additional subkey id)/
    │       └── any other subkey type
    └── "piv"/
        ├── root CA key
        ├── (optional subkey id)/
        │   ├── issuing CA key
        │   ├── mgmnt key             (AES-256, or 3DES)
        │   ├── card identifier
        │   ├── authentication key    (slot 9A)
        │   ├── signature key         (slot 9C)
        │   ├── key management key    (slot 9D)
        │   └── card authentication   (slot 9E)
        └── (additional subkey id)/
             └── any other subkey generation
```

Note that the certificate authority key is a *sibling* of the subkey id, not its parent.
Were it the parent, anyone holding the authority key could re-derive every slot key.

## Derivation labels


Each step down the tree is a fresh `argon2id` whose salt is `MINDTHEGAP256HDKD` followed by a
label of the form `<prefix>:<name>`, where names are lowercase and hyphenated:

| prefix | meaning | output |
|---|---|---|
| `app` | application subtree | intermediate seed |
| `sub` | subtree scoped to the subkey id | intermediate seed |
| `key` | key material | 256 bits |
| `key:<name>:<segment>` | key material bound to one algorithm | 256 bits (384 on P-384, 192 for 3DES, see below) |
| `id` | identifier material | truncated to what the format takes |
| `pin` | something a person types | ASCII |

The prefix carries the use case, so two derivations cannot agree just because their names
match: `key:authentication:p256` and `id:authentication` are different bytes, as are PIV's
`key:authentication:p256` and PGP's, which sit under different `app:` subtrees.

## The algorithm segment

Every asymmetric key carries the algorithm it is derived for as a third label segment, behind
a second colon: `key:signature:ed25519`, `key:key-management:p256`. The segment names what the
bytes become, with the RFC names rather than OpenPGP's: `p256` for ECDSA and ECDH on NIST
P-256, `p384` for the same on NIST P-384, `ed25519` for Ed25519 signing keys and `x25519` for
X25519 key agreement keys. The AES-256 PIV management key predates the segment and keeps its
bare `key:management` label; its 3DES sibling, added later, carries the algorithm as its
segment (`key:management:tdes`), see [below](#the-piv-management-key).

`--algorithm` picks the algorithm for a whole backend at once, authorities and primary
included, and the defaults are what each backend has always produced: OpenPGP derives
Curve25519 keys, PIV P-256 ones. Switching a card to another algorithm derives under
different labels, so the chains share no key material, and none can be computed from another.

| backend | key | `--algorithm curve25519` (OpenPGP default) | `--algorithm p256` (PIV default) | `--algorithm p384` (PIV only) |
|---|---|---|---|---|
| OpenPGP | primary, signing, authentication | EdDSA on Ed25519 | ECDSA on P-256 | refused |
| OpenPGP | decryption | ECDH on Curve25519 | ECDH on P-256 (SHA-256, AES-128 KDF) | refused |
| PIV | root CA, issuing CA, 9A, 9C, 9E | Ed25519 | ECDSA P-256 | ECDSA P-384, SHA-384 signatures |
| PIV | 9D and retired generations | X25519 | ECDH P-256 | ECDH P-384 |

Card support decides which algorithm a deployment can use: every YubiKey 5 takes both curves
for OpenPGP and P-256 and P-384 for PIV (as does a YubiKey 4), and firmware 5.7 adds Ed25519
and X25519 PIV keys; Nitrokey's opcard takes both for OpenPGP, and the trussed PIV app takes
all three as it runs in CI. P-384 exists for PIV consumers that insist on it, such as a
binary cache signing key (see [the build server profile](piv-build-server.md)); the OpenPGP
backend refuses it. The `--legacy` OpenPGP scheme predates the segment and only ever derived
Curve25519 keys, so it refuses `--algorithm`.

**The subkey id is public.** It ends up in the labels and, once recorded in a certificate,
in the certificate too, so treat it as a name rather than a secret. Use it to say *which card*
this is -- the machine it belongs to makes a good id. If you want a second secret that separates
one set of exported keys from another, that is what `--password` is for: it feeds the root
entropy derivation, above everything shown here.

The `sub:` prefix is what keeps the id safe to expose. Without it the id would share a
namespace with the fixed labels beside it, and an id equal to one of them would silently
collapse two different keys into one.

No subkey id at all derives under the bare `sub` label, with no separator; a supplied id,
even an empty one, derives under `sub:<id>`. The two are distinct on purpose: they produce
visibly different certificates, so they must not quietly agree on keys. Keys derived
without an id are also what `--shared` keys use, which is how every card can carry the
same decryption key while the rest differ.

PIV slot keys are named for the *role* they serve (`key:key-management`), not the slot they
occupy, because the retired slots hold superseded key management keys: an archived key has to
derive the same whether it lives in 9D or in 0x82.

Published identifiers are stamped with the scheme that produced them, so a card or a
certificate can be read back and understood without guessing:

```
CN=PIV Card mtg1:776AD915                     slot 9E subject
dnQualifier=mtg1:laptop                       person-bound slot subjects
subkey@mind-the-gap.gli.al = mtg1:laptop      OpenPGP subkey binding notation
```

The marker is on the identifiers, not in the derivation labels. Relabelling already moves every
key, so a version in the derivation path would separate nothing that changing the scheme had
not separated already, and each level of the path costs an argon2 pass to carry.

OpenPGP cards provisioned before this scheme keep working through `--legacy`. That scheme is
`mtg0` by convention only -- it stamps nothing, because it predates the marker and its output
is fixed.

The release version says the same thing from the other side: **the crate's major version
tracks the scheme**. Every 0.x release derived under `mtg0` and supported OpenPGP only;
every 1.x release derives under `mtg1`. Within a major the derivation never moves -- that is
the whole point -- and a future scheme would ship as 2.0.

The subkey binding notation and the `dnQualifier` exist for two reasons: a *lost* card's
subkeys can be picked out of a merged certificate by name when the time comes to revoke them,
and any card or certificate names the derivation scheme that produced it, so it can be checked
or re-derived years later without guessing. That information costs bytes -- 191 armored bytes
on a full OpenPGP certificate with a subkey id -- which gives back roughly a third of what the
patched `sequoia-openpgp` saves by dropping its per-signature salt notation (about 530 bytes,
see [below](#the-forked-sequoia-openpgp)). The trade is deliberate: the salt was random
padding, the notation is load bearing, and the certificate stays comfortably within QR code
capacity.

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

The management key in slot 9B authenticates every administrative operation on a PIV card.
It derives from the subkey seed, so each card id gets its own, in one of two algorithms:

| algorithm | label | key |
|---|---|---|
| AES-256 | `key:management` | the whole 32-byte output |
| 3DES | `key:management:tdes` | the first 24 bytes of the output |

AES-256 is what the tool has always installed, and its label is frozen as it was. 3DES is
the only management key a YubiKey 4, or a YubiKey 5 before firmware 5.4, accepts, and it is
an independent derivation rather than a truncation of the AES key, so the two never share
bytes. A 3DES key is rejected when one of its three DES keys is one of the four weak or
twelve semi-weak DES keys, or when two of them coincide (either collapses the cipher towards
single DES), parity bits ignored in both comparisons; the output then moves on to
`argon2id(output, "key:tdes-retry")` and its first 24 bytes are tried again. The odds of
that are about 2^-50.

`piv upload --management-key auto` (the default) installs AES-256 when the card reports
firmware 5.4 or later and 3DES otherwise; `aes256` and `tdes` force one. `piv check` needs
no flag: it asks the card which algorithm it holds and derives that key.

## The forked `sequoia-openpgp`

The OpenPGP backend builds a pinned fork of `sequoia-openpgp` (`gitlab.com/gli.al/sequoia`,
tag `openpgp/v2.2.0-mtg0`, revision locked in `Cargo.lock`). It carries exactly two commits
on top of the upstream 2.2.0 release: one drops the random 32 byte
`salt@notations.sequoia-pgp.org` notation from v4 signatures, one drops the descriptive
armor headers. Both shrink the certificate for QR transfer, and the salt removal is also
what keeps the output byte-for-byte reproducible -- upstream salts every signature with
fresh randomness. Review these two commits whenever the fork is rebased.

## What the published identifiers reveal

Publishing these values is safe by construction, but it is worth being precise about what
"safe" means here.

Every published identifier -- the card id, the CHUID GUID, the CCC identifier -- is an
argon2id output keyed by the subseed under its own `id:` label. Assuming argon2id behaves as a
pseudorandom function, those bytes say nothing about any `key:` output, however many of them
are collected, and the `id:`/`key:` prefix split guarantees an identifier can never be a
truncation of key material even when the names coincide. The subkey id itself is an *input*
to the derivation, not an output: revealing it costs nothing because no secrecy ever rested
on it -- the seed and the optional password are the only secrets.

What the identifiers do reveal is **metadata**. All cards from one seed share a root
authority and OpenPGP primary key, so they are publicly linkable to one identity; the subkey
ids expose your naming (machine names, by recommendation) and, with archived generations,
how many rotations a card has seen. That is the design working as intended -- "which card is
this" is the whole point -- but if the shape of your fleet is itself sensitive, choose opaque
subkey ids rather than descriptive ones. They are names, and they will be read.

## Use a subkey id per card


**Give every card its own subkey id** -- the machine it is for makes a good one -- whenever one
seed provisions more than one card:

```
MIND_THE_SUBKEY=laptop mind-the-gap piv upload
MIND_THE_SUBKEY=desktop mind-the-gap piv upload
```

Everything below the subkey id changes with it, while the authority above it does not:

| `--subkey` | root CA | 9A key | card id |
|---|---|---|---|
| *(none)* | `8689cddf…` | `f3450d17…` | `mtg1:9482DB69` |
| `laptop` | `8689cddf…` | `4fc4587c…` | `mtg1:E1FE3429` |
| `desktop` | `8689cddf…` | `094d61dc…` | `mtg1:C40CBAD3` |

So one trust anchor still covers every machine -- install the root once -- but each card holds
distinct keys and is individually identifiable, since slot 9E carries the card id in its
subject (`CN=PIV Card mtg1:E1FE3429`).

Provision two cards from one seed *without* a subkey id and they are cryptographic clones:
same slot keys, same certificates, same card id, and the same CHUID GUID and CCC card
identifier. You cannot then tell which card was used for anything, losing one means revoking
the identity on every machine, and Windows keys its smartcard cache off that GUID, so
duplicates on one domain misbehave.

Re-running `upload` with the *same* subkey id is a different matter: it reproduces the same
card byte for byte, which is how a lost card is replaced.

The card id is deliberately derived from the seed rather than read off the card's serial
number, so that `piv certify` -- which runs air-gapped, with no card present -- produces the
same certificates `piv upload` writes.
