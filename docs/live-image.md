# The live image

The live image is where the cards are provisioned: a NixOS system that boots from a stick,
logs in on its own, and runs mind-the-gap with the network, the disks and every way out of the
machine taken away. This chapter is what working on it looks like from the keyboard. [Building
an image](image.md) makes one with your own defaults and ceremony, and the [security
chapter](security.md#the-live-image) says what the image locks down and why.

## The login banner

Every console shows a banner at login: the tool's version and the image's label, so that a
stack of burned sticks stays tellable apart, and what a bare `mind-the-gap` does here.
`mind-the-gap --version` adds the derivation scheme and the source revision the image was
built from, which a record of the keys made on it keeps. On the
stock image that is "mind-the-gap opens an interactive session"; on an image built with a
ceremony it is "mind-the-gap runs the ceremony `card` (`mind-the-gap run --dry-run` shows its
steps)". The banner also reminds of `forget` and of powering off.

An image with a ceremony is then a single purpose appliance: boot, type the phrase when
asked, watch the steps, power off.

## Cards on the image

The image runs pcscd, routes gpg's scdaemon through it (`/etc/gnupg/scdaemon.conf` holds
`disable-ccid`) and runs gpg-agent with SSH support. scdaemon stays exclusive, so after using
gpg on the image, run `gpgconf --kill scdaemon` before the next `mind-the-gap` command that
talks to a card; [after the gap](after-the-gap.md#gpgs-scdaemon) explains why.

## The transfer stick

Nothing on the image mounts a stick by itself, which keeps automounting code off it. Find the
stick with `lsblk`, then mount it where the examples write, and unmount it before pulling it:

```
lsblk
sudo mkdir -p /media/usb
sudo mount -o uid=$(id -u),gid=$(id -g) /dev/sdX1 /media/usb    # vfat
mtg> publish --to /media/usb/
sudo umount /media/usb
```

A btrfs stick mounts without the `uid` and `gid` options; `sudo chown $USER /media/usb` then
lets the session write to it. Those two are the only filesystems the image reads: every
filesystem driver is kernel code parsing whatever stick is plugged in, and module loading is
locked after boot, so an exFAT or ext4 stick cannot be mounted on it. Format the stick as FAT
on another machine.

## Leaving the machine

When stepping away from a live image machine, leave the session with `quit` and run `forget`
at the shell: it clears the screen, the scrollback and the shell's history in one stroke, and
no shell on the image keeps a history file. Powering off does strictly more.
