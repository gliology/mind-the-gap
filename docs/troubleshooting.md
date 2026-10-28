# Troubleshooting

By the message you see, or the symptom where there is none. The chapters linked from each
entry explain the background.

## Reaching the card

### The smart card cannot be accessed because of other connections outstanding

Something holds an exclusive PC/SC connection to the readers, almost always gpg's scdaemon,
left over from ordinary gpg use or started again by a gpg or ssh operation through gpg-agent.
The message names nothing, and every other card attached is blocked as well. Release them:

```
gpgconf --kill scdaemon
```

gpg starts a new scdaemon the next time it needs a card. To use gpg and PIV side by side
without this, see [gpg's scdaemon](after-the-gap.md#gpgs-scdaemon). If a run left the readers
contended and `gpg-connect-agent /bye` hangs, kill gpg-agent as well; socket activation starts
a fresh one.

### gpg fails with `No such device`

scdaemon uses a CCID driver of its own, which claims the USB device directly and finds it
taken by pcscd. Put `disable-ccid` into `~/.gnupg/scdaemon.conf` so that it goes through PC/SC
([gpg's scdaemon](after-the-gap.md#gpgs-scdaemon)).

### gpg fails once right after a PIV command

With `pcsc-shared` in `scdaemon.conf`, scdaemon works from what it cached of the card, and
the first gpg operation after a PIV command may fail, once or twice. Repeat it; nothing on the
card is harmed.

### `pcscd is not running`

mind-the-gap, gpg and OpenSC all reach the cards through pcscd. Start it, `systemctl start
pcscd.socket` where systemd runs, or install it first: [what a system
needs](after-the-gap.md#what-a-system-needs).

### A service or an SSH login sees no card

Distributions that build pcsc-lite with polkit let only the active local session at the
cards. A service, or a login over SSH, needs a polkit rule that allows it.

### `The card is not initialized by this card seed, so it cannot be …`

`upload`, `rotate`, `pin --reset` and `wipe` act only on a card the card seed initialized, and
refuse another before anything is spent on it. Give the card seed the card was initialized
with (in the hardened flow, the administrator's, `--card-seed`), or reset the card with `init`;
to retire or hand on a card that is someone else's, `wipe --force` resets it without any seed.
A blank card wants `init` first. `list` shows which card seed a card answers to without
spending a pin try ([list](commands.md#list)).

## Seeds and the record

### The seed id, the root or the fingerprint differs from the record

A phrase has a checksum, a password does not, so a typo in the password derives other keys
without a word of complaint. That is what the [record](glossary.md) is for: when `check` shows
another seed id than the one written down next to the phrase, the phrase or the password was
typed differently. Leave the session and type both again; nothing derived from the wrong seed
should go onto a card. The password is taken in Unicode NFKD, so the same characters typed on
another keyboard derive the same seed ([from the phrase to a
seed](derivation.md#from-the-phrase-to-a-seed)).

With the seed id as written down, a root that differs is another algorithm's or another
name's: each algorithm has a root of its own, and the subject `check` shows beside the digest
names both, `CN=Jane Doe PIV Root CA p256`.

### `No … phrase given`

`No seed phrase given`, `No card seed phrase given`, `No key seed phrase given` or, for
`rotate --from-key-seed`, `No previous key seed phrase given`. A one-shot command never asks,
so a seed it needs has to come from `--seed`, `--card-seed=PHRASE`, `--key-seed=PHRASE` or
`--from-key-seed=PHRASE`, or their `MIND_THE_...` variables; the message names them. Only the
[interactive session](interfaces.md#the-interactive-session) asks, on a hidden prompt.

### `That looks like a seed phrase; it was neither stored nor echoed`

A session line that does not parse and looks like a phrase is dropped without a trace: it
enters no history and is not repeated in the error. A command that needs the phrase asks for
it on a hidden prompt; there is nothing to type on the line.

### `The seed is fixed for the session: a line never carries it, …`

The whole message is `The seed is fixed for the session: a line never carries it, so it cannot
end up in the history; a command that needs it asks`, with `A password` or `A seed` in place
of `The seed` for the other flags. A session line named a seed or a password with its flag
(`--seed`, `--key-seed=…`, `-p`), and was refused before it could enter the history. Leave the
flag out, or give a bare `--key-seed` to have that seed asked for. A ceremony step is refused
with `… is fixed for the session and never written in a ceremony`, which covers pins too
([the rules](security.md#secrets-stay-out-of-the-history-the-config-and-the-log)).

### `Refusing to continue without confirmation, use --yes`

A command that writes to a card asks first, on the terminal; where there is none, as for a
script run by a service, it aborts rather than hang. Pass `--yes` once the command does
what you want; `--dry-run` shows what it would write. Plumbing mode asks nothing at all and
says `Plumbing asks nothing: pass --yes to write`.

## What `check` reports

`check` compares everything the seeds derive with the card, so what differs says where to
look:

- **A public key differs from the derived one:** the card holds other keys than these seeds
  and options derive. Check the seeds against the record first, then the options that move
  keys: `--subkey`, `--date`, `--algorithm`, and the key seed in use.
- **Only a certificate's digest differs:** the certificate is regenerated from the options,
  so the `--name`, `--emails`, `--validity`, `--date`, `--identity-date`, `--crl-url` or
  `--intermediate` given now differ from the `upload` that wrote it. Pass them identically, or
  keep them in a [config file](configuration.md#config-files); an `upload` with the new
  options writes the new certificates.
- **A pin or touch policy differs from `--policy`:** a warning, not a failure, since the keys
  are right. `upload --policy` brings the keys to the policy.
- **The authorities in `msroots` do not match, or are missing:** a warning too; `upload`
  writes them when the whole identity goes onto the card.
- **Keys cannot be verified without a pin:** a card without GET METADATA proves its keys by a
  signature challenge, which needs `--pin` ([check](commands.md#check)).

## Particular cards

### A Gnuk keeps the factory pin after `init`

``The card refused a new user pin before it holds keys (…); it keeps the factory pin 123456
until `pin` changes it after `upload` ``. Gnuk takes a new user pin only once it holds keys: change
it with `pin` after `upload`, or with `pin --reset` as a ceremony's last step
([ceremonies](ceremonies.md#the-file)).

### PIV `init` reset the card, then failed importing 9E

The card listed an algorithm its build lacks, which the check before the reset trusts: a
piv-authenticator build, on a Solo 2 or a Nitrokey 3, lists algorithms whatever it carries.
The card is left this card seed's, with its management key, puk, CHUID and CCC, and 9E empty.
Run `init` again with an algorithm the build holds, or `wipe` it ([cards that list more than
their build holds](supported-cards.md#cards-that-list-more-than-their-build-holds)).

### OpenPGP `upload` stopped part way with 6A81

The same on OpenPGP: the card's algorithm information names an algorithm its build lacks, as
opcard's does for RSA without an RSA backend. Nothing was reset; the keys written before the
refused one are on the card, and an `upload` with an algorithm the build holds replaces them.

### `The card refused the msroots object`

Some PIV applets (CanoKey among them) have no `msroots` object, where Windows finds the
certificate authorities. The keys and certificates are written regardless; `--no-msroots`
leaves the object out and silences the warning.

### A KDF card refuses OpenKeychain's pin

A card set up with the KDF data object (`init --kdf on`, and every Gnuk) takes its pins as
iterated and salted SHA-256 hashes, so every program that asks for the pin has to hash it. gpg
does; OpenKeychain does not yet, so its pin never matches. Use gpg with such a card. `init`
sets the KDF data object up only where asked (`--kdf on`) or where the card depends on it (a
Gnuk), so a card meant for OpenKeychain is initialized without it ([init](commands.md#init)).

## Using the keys

### SSH never offers the card key, or the signature fails

Two traps, both worth knowing before you debug a failure:

- `IdentitiesOnly=yes` filters PKCS#11 identities out before they are ever offered, so the
  card key is never tried and the failure looks like a server-side rejection.
- **The touch is easy to miss.** 9A is `touch cached` under the default policy, and if nobody
  presses the button the signing step fails with `C_Sign failed: 257`
  (`CKR_USER_NOT_LOGGED_IN`) on the direct route, or `agent refused operation` through
  `ssh-agent`, neither of which mentions the touch. Watch the token, not the terminal.

`ssh-agent` also refuses a PKCS#11 provider outside its built-in allowlist: a module in the
Nix store needs `ssh-agent -P '/nix/store/*/lib/*.so'`.

### `openssl verify -purpose smimeencrypt` fails for the 9D certificate

That is correct, and not to be fixed: the check wants `keyEncipherment`, which RFC 8813
forbids on EC keys, and the certificate carries `keyAgreement` as it must. `openssl cms
-encrypt` to it works ([known caveats](piv-hardware-tests.md#known-caveats-not-to-be-fixed)).

### Decrypting S/MIME on the card fails

Through OpenSSL's pkcs11 provider with `aes_wrap_cipher_internal: cipher operation failed`,
through NSS with `SEC_ERROR_INVALID_KEY`: both are upstream bugs, not the card's, which
after the gap explains under [OpenSSL](after-the-gap.md#openssl) and under
[NSS](after-the-gap.md#nss-firefox-chrome-and-thunderbird).

## Memory

### `Memory not locked, secrets may be swapped out`

Shown at `--log-level debug`, with the reason, typically `the memlock limit is 8192 KiB, below
the 256 MiB the derivation needs`. Locking under a small limit would crash the derivation
rather than protect it, so the tool skips the lock. Raise `memlock` in `limits.conf` or the
systemd unit to unlimited or at least 256 MiB if you want it; the live image has it lifted
already ([on your own machine](security.md#on-your-own-machine)).
