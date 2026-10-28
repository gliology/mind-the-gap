# Security

What the tool and the live image protect, what they leave to you, and which trust decisions
they make on your behalf. The [key derivation](derivation.md) chapter specifies what is
derived; this one says what follows from it for whoever holds a phrase, a card or a published
certificate.

## The seeds are the only secrets

The keys, the card credentials and the identifiers all derive from a phrase (24 words from
`generate`; 12 to 24 are accepted) plus its optional password through argon2id. Subkey ids
and dates are no secrets, and card identifiers, seed ids and everything else a card or
certificate carries are public by design; [below](#what-the-published-identifiers-reveal) is
what they reveal. The user pin is the one secret that is not derived: it is the card
holder's, and unlocks one card.

## Secrets stay out of the history, the config and the log

`generate` mints a phrase and verifies it was written down; no other command ever invents a
seed. A one-shot command takes a phrase from its flag or variable and fails without it, and
the interactive session prompts once without echoing and holds it in process memory only.

In a session, a seed or a password never appears on a line. A line that names one is refused,
a phrase typed at the prompt by mistake is neither stored nor echoed, and only lines that
parse as commands enter the recallable history, which is kept in memory only. Card pins are
per-card inputs and the one exception: a pin may be typed on a line with `--pin`, by whoever
accepts that it then enters that history. No config file, no `set` and no ceremony can hold a
seed, a password or a pin.

QR output of secret material stays on the alternate screen, waiting there if it does not fit,
and is gone from scrollback on dismissal.

The flags and the environment are a channel too, for experts and scripts, and each exposes
something: [the session and the command line](interfaces.md#what-each-channel-exposes) says
what, before a real seed goes through one.

The log is the last channel. `MIND_THE_LOG_LEVEL` accepts full filter spellings, and the card
libraries would trace raw APDUs, pins included, at `trace`; the tool drops their records
above `info` whatever the filter says, so no card conversation ends up in a log.

## The live image

The image is where production keys belong. It enforces its own air gap:

- No DHCP. The wireless, bluetooth and USB tethering stacks cannot be loaded, not even as
  another driver's dependency, and kernel module loading is locked after boot.
- nftables drops everything but loopback in both directions, so the tools every NixOS system
  carries, curl among them, reach nothing.
- Console autologin and passwordless sudo are deliberate: the threat model of a live image is
  physical possession, and nothing secret is stored on it.

It keeps RAM short-lived and hard to read:

- Freed pages are zeroed by the kernel, the tool is locked into RAM (the memlock limit is
  lifted for it), and there is no swap.
- Suspend, hibernation and the lid switch are disabled: the only way out of a session is power
  off, so a dark screen never hides a seed.
- kexec is locked, so the running kernel cannot be replaced by one that reads this one's
  memory, and the EFI pstore is off, so a crash deposits nothing in firmware.
- On AMD machines with SME the kernel asks for transparent memory encryption
  (`mem_encrypt=on`); Intel's TME has no such switch. Where the firmware offers TSME or TME,
  turn it on: it is the one measure that blunts a cold boot attack, which no software can.
  Power off and let the machine sit before walking away regardless.

No shell on the image keeps a history file, and `forget` clears the screen, the scrollback and
the running shell's history ([leaving the machine](live-image.md#leaving-the-machine)).

## On your own machine

The process does what it can; the rest is yours. Core dumps are off, the process cannot be
traced, every secret buffer is wiped on drop (argon2's working memory included), and memory
is locked into RAM when `RLIMIT_MEMLOCK` is unlimited or at least 256 MiB. The common desktop
default of 8 MiB is too small for argon2 plus the process, and locking under it would crash
the derivation rather than protect it, so the tool skips the lock and says so at
`--log-level debug`; raise the limit in `limits.conf` or the systemd unit if you want it.

What a desktop keeps that the image does not: swap when the lock was skipped, hibernation
(which writes RAM to disk, locked or not), other processes and users, a terminal with
persistent scrollback, and a kernel without the image's lockdowns. Production keys belong on
the image for those reasons, not for ceremony.

## What the published identifiers reveal

Every published identifier (the card id, the CHUID GUID, the CCC identifier, the OpenPGP card
identifier, the seed id) is an argon2id output under its own `id:` label. Assuming argon2id
behaves as a pseudorandom function, those bytes say nothing about any `key:` or `pin:` output,
however many of them are collected, and the prefixes guarantee an identifier can never be a
truncation of key material even when the names coincide. The subkey id and the date are
*inputs*, not outputs, and no secrecy rests on them. No certificate and no card carries the
subkey id; the date shows as the creation time of the keys and their certificates. The tag in
the name of an issuing authority (`--intermediate`) is no derived identifier either: it is cut
from the authority's subject key identifier, a digest of its public key that the certificate
carries anyway, so it reveals nothing more.

What is revealed is **metadata**. The keys of one identity share a root authority and a
primary key, so they are publicly linkable to it, and how many devices an identity has shows
in how many subkeys or slot certificates it publishes; the dates expose how often you rotate.
The cards' own identifiers are bound to each card's serial, so two cards of one card seed
cannot be linked by them; only whoever holds the card seed can tell they share an
administrator.

## A key is no stronger than its phrase

The modulus sizes are rated as NIST SP 800-56B rates them, the curves as SP 800-57 part 1
does:

| algorithm | security strength |
|---|---|
| `p256`, `curve25519` | 128 bits |
| `p384` | 192 bits |
| `rsa2048` | 112 bits |
| `rsa3072` | 128 bits |
| `rsa4096` | 152 bits |

A 24 word phrase carries 256 bits of entropy and covers all of them. A 12 word phrase carries
128, so `p384` or `rsa4096` from it gets the larger key's costs without its strength, and
mind-the-gap warns about that. It warns rather than refuses, since the key is sound either way
and a password may well make up the difference, which cannot be measured.

## The forked sequoia-openpgp

The OpenPGP backend builds a pinned fork of `sequoia-openpgp` (`gitlab.com/gli.al/sequoia`,
tag `openpgp/v2.2.0-mtg0`, pinned by revision in `Cargo.toml`), and that single source is a
single point of trust. It carries exactly two commits on top of the upstream 2.2.0 release:
one drops the random 32 byte `salt@notations.sequoia-pgp.org` notation from v4 signatures, one
drops the descriptive armor headers. Both shrink the certificate for QR transfer, and the salt
removal is also what keeps the output byte-for-byte reproducible: upstream salts every
signature with fresh randomness. The signatures' nonces are the other half, below. Review these
two commits whenever the fork is rebased.

## Reproducible signatures

Every OpenPGP signature is made by mind-the-gap's own signer, and sequoia only assembles the
packets around it. Ed25519 is deterministic by design (RFC 8032) and PKCS#1 v1.5 has no
randomness to begin with, so those keys sign through sequoia's code. ECDSA needs a nonce per
signature, which sequoia draws at random, so P-256 is signed with RustCrypto's RFC 6979, the
code the PIV certificates are signed with: the nonce is derived from the key and the digest by
an HMAC over the signature's own hash, and every OpenPGP signature mind-the-gap makes is over
SHA-512. That choice is part of the reproducibility promise like the labels are, since another
hash would give other nonces and other signature bytes for the same keys. The
[derivation chapter](derivation.md#openpgp-signatures-from-the-seed) specifies the signatures
in full, and the golden vectors pin the output of `publish`, `revoke` and `trust` byte for
byte, on curve25519, p256 and rsa2048.

The one output that is not reproducible is an encrypted `ungap` export: its salt and IV are
random, as they must be (the S2K's for OpenPGP, PBES2's for PIV), so every export of the same
key is a different file.

Deterministic signatures have a known weakness, and these carry neither a salt nor a hedged
nonce (RFC 6979 with fresh randomness mixed in), the configuration fault attacks target. A
signature computed wrongly, by an attacker's glitch or by a bit flipped in memory without
ECC, which needs no attacker at all, can give the key away next to the correct signature of
the same digest. One faulty signature suffices here, since the correct one is public and made
again on every run. That holds for a fault in the signature arithmetic and equally for one in
the nonce after it was derived: a k off by a single bit gives a signature whose relation to
the correct one is linear in the key, so the pair yields it. Ed25519 derives its nonce the
same way and is exposed the same way, and an RSA signature faulted in one half of its CRT
computation factors the modulus on its own (Bellcore). `trust` is the command that signs what
someone else supplies, the user ids of an imported certificate, and running it twice signs the
identical digest twice.

So every signature is made twice and compared, then verified against its public key, before
it is written, and either check failing stops the command instead. Verification catches a
fault in the signature computation, the RSA one included, since a faulted signature does not
verify. The comparison catches a transient fault in deriving the nonce, which gives a
different signature that verifies all the same. What remains is a fault that strikes both runs
the same way, and it is accepted: an attacker able to cause that is at the air-gapped host
during a ceremony its operator runs, and can read the seed resident in its memory, which
yields every key at once; a random flip would have to hit the same microsecond window twice.
