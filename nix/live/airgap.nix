# The air gap, enforced by configuration rather than by discipline: no address, no radio, no
# packet past loopback, and no kernel module loaded once the machine has booted. Anything a
# host needs after boot (its keyboard, a storage driver) goes into boot.kernelModules, which
# loads it before the lock takes hold.
{ lib, pkgs, ... }:

{
  # Without this NixOS brings up DHCP on every interface, and plugging in a cable would put
  # the "air-gapped" machine on a network.
  networking.useDHCP = lib.mkImageMediaOverride false;
  networking.wireless.enable = false;
  networking.firewall.enable = true;

  # No DHCP is not no network: udev coldplugs the matching NIC driver during boot, before
  # the module lock below takes hold, so a built-in ethernet port is present and one `ip
  # addr add` away from a working uplink -- and the firewall above filters inbound only.
  # Drop every packet that is not loopback, in both directions, so even a deliberately
  # configured interface moves nothing.
  networking.nftables.enable = true;
  networking.nftables.tables.airgap = {
    family = "inet";
    content = ''
      chain input {
        type filter hook input priority -10; policy drop;
        iif lo accept
      }
      chain output {
        type filter hook output priority -10; policy drop;
        oif lo accept
      }
      chain forward {
        type filter hook forward priority -10; policy drop;
      }
    '';
  };

  # Keep the radios off entirely; the card readers this is for are wired. The USB tethering
  # drivers join them: a phone plugged in "to charge" must not become an uplink during the
  # boot window before the module lock applies.
  boot.blacklistedKernelModules = [
    "bluetooth"
    "btusb"
    "cfg80211"
    "mac80211"
    "usbnet"
    "cdc_ether"
    "cdc_ncm"
    "rndis_host"
    "r8152"
  ];
  # A blacklist only stops a module's own aliases: a wifi or modem driver loaded by its PCI
  # or USB id still pulls cfg80211, bluetooth or usbnet in as a dependency. Refusing the
  # stacks themselves closes that path, whatever driver asks.
  boot.extraModprobeConfig =
    lib.concatMapStrings
      (module: ''
        install ${module} ${pkgs.coreutils}/bin/false
      '')
      [
        "bluetooth"
        "cfg80211"
        "mac80211"
        "usbnet"
      ];

  # Support common file systems for the transfer media. Kept deliberately short: every
  # filesystem here is kernel code parsing whatever USB stick gets plugged in, and vfat is
  # what freshly formatted sticks actually carry.
  boot.supportedFilesystems = [
    "btrfs"
    "vfat"
  ];

  # Refuse to load kernel modules once booted. The supported tokens (YubiKey, Nitrokey) are
  # driven from userspace through pcscd and need no device modules of their own, so the only
  # hotplug this must survive is a transfer stick and a token's HID interface -- both
  # preloaded below, since a module not loaded by now stays unloadable. A nice side effect:
  # a USB network adapter plugged in later cannot bring its driver with it.
  security.lockKernelModules = true;
  boot.kernelModules = [
    # Tokens: raw USB access for pcscd plus the HID fallback interface
    "usbhid"
    # Transfer media: USB mass storage in both flavours, exposed as SCSI disks
    "usb_storage"
    "uas"
    "sd_mod"
    # Filesystems the media may carry, including the character sets vfat needs
    "vfat"
    "nls_cp437"
    "nls_iso8859-1"
    "btrfs"
    # btrfs's checksums come from the crypto API (its softdep, crc32c_cryptoapi since 6.15),
    # which no mount can load once the lock is on: without it no btrfs mounts at all
    "crc32c"
  ];
}
