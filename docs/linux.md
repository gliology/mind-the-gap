# Cards on a Linux system

mind-the-gap, gpg and every PKCS#11 program reach a card the same way: through PC/SC, where
one daemon, `pcscd`, owns the readers and the programs open connections through it. That
gives a Linux system one requirement and one conflict worth knowing about. The live image
has both settled already (see [below](#the-live-image)); this page is for the machines the
cards are used on afterwards.

## What a system needs

- **pcscd.** Socket activation is enough, it starts on the first connection. On NixOS,
  `services.pcscd.enable = true;`; on Debian and Ubuntu the `pcscd` package; on Fedora
  `pcsc-lite`. Its CCID driver knows the YubiKey, Nitrokey and Solo USB ids, so no udev
  rules and no kernel modules are needed for it.
- **Access for non-desktop logins.** Distributions that build pcsc-lite with polkit let only
  the active local session at the cards. A service or an SSH login, such as a [build
  server](piv-build-server.md)'s, needs a polkit rule that allows it.
- **For the PIV keys in other programs:** OpenSC's PKCS#11 module, `opensc-pkcs11.so`, which
  browsers, mail clients, OpenSSH (`PKCS11Provider`) and OpenSSL's pkcs11 provider load. It
  needs no configuration.
- **For the OpenPGP keys:** GnuPG, with the scdaemon setting below.

## gpg's scdaemon

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
name a reader.

### Which to choose

- **gpg every day, PIV now and then:** leave scdaemon exclusive and let gpg-agent do SSH too
  (`enable-ssh-support` in `gpg-agent.conf`, with the OpenPGP authentication key), so daily
  work never leaves scdaemon. Before a PIV task (a TLS client certificate, S/MIME through
  PKCS#11, `mind-the-gap piv`), run `gpgconf --kill scdaemon`.
- **Both every day:** `pcsc-shared`, and repeat the gpg operation that fails after PIV use.
- **PIV only,** such as a build server: do not point gpg at the card at all.

## Several cards attached

Cards derived from one seed can carry the same OpenPGP keys, a backup card being the usual
reason (see [Several cards from one seed](multiple-cards.md)). gpg-agent then signs and
decrypts on whichever attached card holds the key, which is what a backup is for. To see them
all, or one in particular:

```
gpg-card list --cards                                # serial numbers of the attached cards
gpg-card list D2760001240103040006123456780000       # one of them
```

`gpg --card-status` shows only one card, whichever scdaemon picked. OpenSC presents each
card as its own token, and `mind-the-gap piv status` and `pgp status` list them all.

## The live image

The image runs pcscd, routes scdaemon through it (`/etc/gnupg/scdaemon.conf` holds
`disable-ccid`) and runs gpg-agent with SSH support. scdaemon stays exclusive, so after using
gpg on the image, run `gpgconf --kill scdaemon` before the next `mind-the-gap` command that
talks to a card.
