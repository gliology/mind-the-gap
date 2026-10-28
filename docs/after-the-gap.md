# After the gap: using the keys

The card leaves the air-gapped machine provisioned, and the public half leaves on the transfer
stick (`publish --to`, see [your first card](quick-start.md#6-take-the-public-half-across)).
This chapter is about the everyday machine the card is used on afterwards: what it needs to
talk to the card, how gpg, OpenSSH, OpenSSL and the NSS programs reach the keys, and which
certificate they trust.

## Cards on a Linux system

mind-the-gap, gpg and every PKCS#11 program reach a card the same way: through PC/SC, where
one daemon, `pcscd`, owns the readers and the programs open connections through it. That
gives a Linux system one requirement and one conflict worth knowing about. The live image has
both settled already ([cards on the image](live-image.md#cards-on-the-image)).

### What a system needs

- **pcscd.** Socket activation is enough, it starts on the first connection. On NixOS,
  `services.pcscd.enable = true;`; on Debian and Ubuntu the `pcscd` package; on Fedora
  `pcsc-lite`. Its CCID driver knows the YubiKey, Nitrokey and Solo USB ids, so no udev
  rules and no kernel modules are needed for it.
- **Access for non-desktop logins.** Distributions that build pcsc-lite with polkit let only
  the active local session at the cards. A service or an SSH login, such as a [build
  host](unattended-host.md)'s, needs a polkit rule that allows it.
- **For the PIV keys in other programs:** OpenSC's PKCS#11 module, `opensc-pkcs11.so`, which
  browsers, mail clients, OpenSSH (`PKCS11Provider`) and OpenSSL's pkcs11 provider load. It
  needs no configuration.
- **For the OpenPGP keys:** GnuPG, with the scdaemon setting below.

### gpg's scdaemon

gpg talks to cards through its own daemon, `scdaemon`, started on demand by gpg-agent. Out of
the box it gets in the way twice.

First, it prefers a **CCID driver of its own** that claims the USB device directly, so it
either takes the token away from pcscd or fails with `No such device` because pcscd already
has it. Route it through PC/SC instead, in `~/.gnupg/scdaemon.conf` (or system-wide in
`/etc/gnupg/scdaemon.conf`):

```
disable-ccid
```

Second, through PC/SC it holds **every reader exclusively** for as long as it runs, which is
until gpg-agent ends. That includes the PIV applet on the same card, and every other card:
mind-the-gap and OpenSC then fail with `The smart card cannot be accessed because of other
connections outstanding`, which names nothing. Release the cards with

```
gpgconf --kill scdaemon
```

and gpg starts a new scdaemon the next time it needs a card.

GnuPG has an option to share instead, `pcsc-shared`, and its manual warns that scdaemon
caches what it read from the card. Measured on a card with both applets, alternating a gpg
read with a mind-the-gap PIV command, with each configuration:

| `scdaemon.conf` | PIV while scdaemon runs | gpg right after a PIV command |
|---|---|---|
| `disable-ccid` | refused | works |
| `disable-ccid`, `pcsc-shared` | works | fails once or twice, then works |
| the same, plus `disable-application piv` | works | fails once or twice, then works |

So sharing works if a failed gpg operation is simply repeated; nothing on the card is harmed.
`disable-application piv` keeps scdaemon out of the PIV applet but does not help here, and
neither do `card-timeout`, which GnuPG 2.4 ignores, or `reader-port`, which under PC/SC cannot
name a reader. That is also why the [hardware tests](hardware-tests.md) stop scdaemon rather
than share the card with it.

Which to choose:

- **gpg every day, PIV now and then:** leave scdaemon exclusive and let gpg-agent do SSH too
  (`enable-ssh-support` in `gpg-agent.conf`, with the OpenPGP authentication key), so daily
  work never leaves scdaemon. Before a PIV task (a TLS client certificate, S/MIME through
  PKCS#11, any `mind-the-gap` command that talks to a card), run `gpgconf --kill scdaemon`.
- **Both every day:** `pcsc-shared`, and repeat the gpg operation that fails after PIV use.
- **PIV only,** such as an unattended host: do not point gpg at the card at all.

### Several cards attached

Cards of one identity carry the same OpenPGP decryption key (see [several cards and
identities](multiple-cards.md#encryption-one-key-for-the-identity)), and a backup card can
carry the same keys altogether. gpg-agent then decrypts on whichever attached card holds the
key, which is what a backup is for. To see them all, or one in particular:

```
gpg-card list --cards                                # serial numbers of the attached cards
gpg-card list D2760001240103040006123456780000       # one of them
```

`gpg --card-status` shows only one card, whichever scdaemon picked. OpenSC presents each card
as its own token, and `mind-the-gap list` lists them all, with the reader each sits in.
`--card` names one by its PIV serial, its OpenPGP identifier or that reader, `--card 'Yubico
YubiKey FIDO+CCID 01 00'`; a reader is opened directly, without asking the other cards who they
are ([which card is which](multiple-cards.md#which-card-is-which)).

## The OpenPGP keys

Import the certificate from the stick, then let gpg find the card's keys:

```
gpg --import pgp.asc
gpg --card-status
```

With the card attached, `gpg --card-status` links the certificate's subkeys to the card, and
gpg signs, decrypts and authenticates through it from then on. Each device publishes its own
subkeys, and the certificates merge wherever they are imported, so importing every device's
`pgp.asc` gives one identity with every device's keys.

For SSH through gpg-agent, see [which to choose](#gpgs-scdaemon) above; `publish --format ssh`
writes the authentication subkey as an OpenSSH line, `pgp-authentication.pub`, for a server's
`authorized_keys`.

A card set up with the KDF data object (`init --kdf on`, and every Gnuk) takes its pins hashed:
gpg does that, OpenKeychain does not yet
([troubleshooting](troubleshooting.md#a-kdf-card-refuses-openkeychains-pin)).

## The PIV certificate chain as a trust anchor

`piv-chain.pem` holds the whole [PIV certificate chain](piv-certificates.md); the root
authority alone comes from `publish --app piv --part identity`. The root is what servers and
clients trust for the card's certificates: install it as a trust anchor wherever a
certificate of the card has to verify (an `openssl ... -CAfile root.pem`, an NSS database as
below, a VPN or mail gateway's CA store).

The authorities are also written to the card's `msroots` object whenever the identity's keys
go onto the card, and the Windows smart card minidriver picks them up from there.

## The PIV keys through PKCS#11

A PIV card holds four keys: 9A authenticates (SSH, TLS client certificates), 9C signs, 9D
agrees on keys for decryption, and 9E authenticates the card itself, without a pin, to a door
reader and the like ([PIV certificate chain](piv-certificates.md)).

Everything that uses a PIV key from another program goes through OpenSC's PKCS#11 module.
Below, `$PKCS11_MODULE` stands for that `opensc-pkcs11.so`, and `$OPENSSL_PKCS11_PROVIDER` for
the `pkcs11.so` of OpenSSL's pkcs11 provider (pkcs11-provider); the project's dev shell exports
both. OpenSC numbers the PIV objects 01 (9A), 02 (9C), 03 (9D) and 04 (9E), so
`pkcs11:id=%01;type=private` is the authentication key. That mapping was confirmed on a
YubiKey, but read it off `pkcs11-tool --module $PKCS11_MODULE -O` rather than assume it.

The examples name the root authority `root.pem` and the slot certificates `9a.pem`, `9c.pem`
and `9d.pem`: the certificates of `piv-chain.pem`, one to a file. `publish --app piv --format
binary` writes them that way as DER, which `openssl x509 -inform der` turns into PEM.

### OpenSSH

```
ssh-keygen -D $PKCS11_MODULE
ssh -I $PKCS11_MODULE user@host
```

`ssh-keygen -D` lists the card's keys as OpenSSH lines; the 9A key is the one to put into a
server's `authorized_keys`, and `publish --app piv --format ssh` writes it on the air-gapped
side as `piv-authentication.pub`. ssh has no pin flag: it asks, or takes the pin from
`SSH_ASKPASS`, and the card blinks for the 9A touch during the signature.

Routed through an agent rather than `ssh -I`, note that `ssh-agent` refuses a provider outside
its built-in allowlist, so a Nix store path needs `ssh-agent -P '/nix/store/*/lib/*.so'`. When
the card key is never offered, or the signature fails with a message that does not mention the
touch, see [the SSH
traps](troubleshooting.md#ssh-never-offers-the-card-key-or-the-signature-fails).

### OpenSSL

Load the pkcs11 provider next to the default one:

```
cat > openssl-pkcs11.cnf <<EOF
openssl_conf = openssl_init
[openssl_init]
providers = prov
alg_section = algs
[algs]
default_properties = ?provider=default
[prov]
default = default_sect
pkcs11 = pkcs11_sect
[default_sect]
activate = 1
[pkcs11_sect]
activate = 1
module = $OPENSSL_PKCS11_PROVIDER
pkcs11-module-path = $PKCS11_MODULE
EOF
export OPENSSL_CONF=$PWD/openssl-pkcs11.cnf
```

`default_properties = ?provider=default` keeps the throwaway keys of a TLS handshake on the
default provider, which the card cannot generate; the card's own key still loads through
pkcs11 from its URI. The provider takes the token pin from a `pin-value=` in the URI, but for
a slot whose pin is asked for always (9C) the card asks again right before the signature, which
`CKA_ALWAYS_AUTHENTICATE` makes a second prompt; feed it on stdin when scripting.

TLS client authentication with the 9A key, against a server that demands a client
certificate issued by the root:

```
openssl s_server -accept 4433 -cert server.pem -key server.key \
                 -CAfile root.pem -Verify 2 -verify_return_error
openssl s_client -connect localhost:4433 -cert 9a.pem -key "pkcs11:id=%01;type=private"
```

That handshake *is* a browser's client certificate authentication: the TLS stack neither
knows nor cares what drives it.

S/MIME, signing with 9C and encrypting to 9D:

```
openssl cms -sign -signer 9c.pem -inkey "pkcs11:id=%02;type=private" \
            -in msg.txt -out msg.p7s -md sha256
openssl cms -verify -in msg.p7s -CAfile root.pem -purpose smimesign -out /dev/null

openssl cms -encrypt -aes256 -in msg.txt -out msg.p7m 9d.pem
openssl cms -decrypt -in msg.p7m -recip 9d.pem -inkey "pkcs11:id=%03;type=private"
```

Decrypting on the card this way does not work, and the cause is upstream: `openssl cms
-decrypt` against 9D fails at the AES key unwrap (`aes_wrap_cipher_internal: cipher operation
failed`) because of OpenSSL bug [#24698](https://github.com/openssl/openssl/issues/24698).
`fix_ecdh_cofactor()` asserts a non-NONE action type that the PKCS#11 parameter translation
never sets, so the X9.63 KDF is fed a bad SharedInfo and derives the wrong key encryption key.
The only known fix is to patch OpenSSL. The card's key agreement itself is sound, and the PIV
suite proves it two ways around the broken bridge, each agreeing with the same computation off
the card: the native derivation through the yubikey crate (step 7), and the standard PKCS#11
`CKM_ECDH1_DERIVE`, which `pkcs11-tool --derive` performs, as a client's own module would
(step 10).

### NSS: Firefox, Chrome and Thunderbird

NSS is the crypto stack Firefox, Chrome and Thunderbird share. Trust the root and add OpenSC's
module to an NSS database (Firefox and Thunderbird also load the module as a security device
in their settings):

```
certutil -A -n "Jane Doe PIV Root CA p256" -t "CT,C,C" -d sql:$HOME/.pki/nssdb -i root.pem
modutil -dbdir sql:$HOME/.pki/nssdb -add opensc -libfile $PKCS11_MODULE
certutil -L -d sql:$HOME/.pki/nssdb -h all
```

The nickname is how the database tells its certificates apart, so name each root after its
subject: an identity with keys on two algorithms has two roots, one per algorithm, which
would otherwise share a nickname.

A complete chain shows with no "unknown issuer": the root above the card's certificates, each
card certificate with its private key on the token.

Decrypting S/MIME on the card fails through NSS too, for reasons of its own: `cmsutil -D -f
<pinfile>` on a message encrypted to 9D returns `SEC_ERROR_INVALID_KEY`. It takes two bugs:
OpenSC's ECDH derive ignores the KDF NSS asks for and returns the raw secret, and NSS's
fallback for tokens that refuse the KDF is never reached from CMS. (`-f` names the token's
pin file; `-p` sets only the NSS database password.) To reproduce it by hand:

```
cmsutil -E -d sql:DB -r "<Key Management nickname>" -i msg -o env
cmsutil -D -d sql:DB -f pinfile -i env -o out
```

### Signing with 9C

Sign with the signature key in 9C, `pkcs11:id=%02;type=private`: its certificate is the one
issued for signatures (`digitalSignature`, `nonRepudiation`), where 9D's allows key agreement
only. PKCS#11 hands out either key for a signature without looking at the certificate, so the
choice is the signer's to make, and keeping signing and key agreement on different keys is
what the certificates say, and what a verifier that does look expects. An [unattended
host](unattended-host.md) signing its store paths uses this key; 9D stays the key for
decrypting what is encrypted to it.
