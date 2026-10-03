{ pkgs, lib, modulesPath, config, ... }:

let
  # The pre-login reminder, shared between the serial gettys and the kmscon shells:
  # the banner from assets/, followed by what this machine is running, so a stack of
  # burned sticks stays tellable apart. The VT and kmscon both speak its truecolor
  # escapes.
  banner = ''
    ${builtins.readFile ./assets/motd.ansi}
     mind-the-gap ${pkgs.mind-the-gap.version} · image ${config.system.nixos.label}

     mind-the-gap opens an interactive session; `forget` clears screen, scrollback and
     shell history; power off and let the machine sit before walking away.
  '';

  # The medium announces itself to file managers when plugged into a running system:
  # Windows Explorer and GVfs read autorun.inf (only its icon and label; execution
  # autorun no longer exists anywhere), GNOME reads .xdg-volume-info for the display name,
  # and Finder picks up .VolumeIcon.icns. All carry the tool version, like the banner,
  # so an inserted stick identifies its generation at a glance.
  volumeName = "Mind the Gap ${pkgs.mind-the-gap.version}";
  autorunInf = pkgs.runCommand "autorun.inf" { } ''
    printf '[autorun]\r\nicon=volume.ico\r\nlabel=${volumeName}\r\n' > $out
  '';
  xdgVolumeInfo = pkgs.runCommand "xdg-volume-info" { } ''
    printf '[Volume Info]\nName=${volumeName}\n' > $out
  '';
  volumeIcns = pkgs.runCommand "volume.icns" { nativeBuildInputs = [ pkgs.libicns ]; } ''
    png2icns $out ${./assets/logo-512.png} ${./assets/icon-48.png} \
      ${./assets/icon-32.png} ${./assets/icon-16.png}
  '';

  # One splash per bootloader, the mark centred on a dark canvas at the loader's native
  # resolution (syslinux is fixed at 800x600 by its MENU RESOLUTION). The mark carries
  # the sign's fixed palette, so it renders straight from the committed SVG.
  splash = width: height: logoSize:
    pkgs.runCommand "mtg-splash-${toString width}x${toString height}.png" {
      nativeBuildInputs = [ pkgs.resvg pkgs.imagemagick ];
    } ''
      resvg -w ${toString logoSize} -h ${toString logoSize} ${./assets/logo.svg} logo.png
      magick -size ${toString width}x${toString height} xc:"#181818" \
        logo.png -gravity center -composite PNG32:$out
    '';
in
{
  imports = [
    # Use NixOS iso base for booting
    (modulesPath + "/profiles/minimal.nix")
    (modulesPath + "/installer/cd-dvd/iso-image.nix")
    # Storage controllers in the initrd (SATA, NVMe, USB, SD) plus firmware, so the image
    # boots on whatever machine it is plugged into -- the same reason the installer CDs use
    # it. It adds no real network drivers (only the virtio/vmware NICs, in the initrd);
    # ethernet appears on real hardware because the full kernel module set ships on the iso
    # and udev coldplugs whatever matches, which no profile choice here can prevent. The
    # nftables table below is what actually keeps such an interface mute.
    (modulesPath + "/profiles/all-hardware.nix")
  ];

  # Adds terminus_font for people with HiDPI displays
  console.packages = lib.mkOptionDefault [ pkgs.terminus_font ];

  # Include firmware for better hardware support
  hardware.enableRedistributableFirmware = true;

  isoImage = {
    # Make iso partition easily identifiable
    edition = lib.mkForce "mind_the_gap";

    # Enable EFI and USB booting
    makeEfiBootable = true;
    makeUsbBootable = true;

    # Boot with the project mark instead of the NixOS branding. The stock grub theme
    # must go for that: when a theme is set, the EFI splash ships but never shows.
    grubTheme = null;
    efiSplashImage = splash 1920 1080 320;
    splashImage = splash 800 600 240;

    # The menu would otherwise advertise this live tool as an "... Installer"
    appendToMenuLabel = "";

    # The volume icon and name shown by file managers, see the helpers above
    contents = [
      { source = autorunInf; target = "/autorun.inf"; }
      { source = ./assets/favicon.ico; target = "/volume.ico"; }
      { source = volumeIcns; target = "/.VolumeIcon.icns"; }
      { source = xdgVolumeInfo; target = "/.xdg-volume-info"; }
    ];
  };

  # Differentiate image from install iso. Since nixpkgs 26.05 the file name derives from
  # image.baseName, which the iso module also sets, so the override has to be forced.
  image.baseName = lib.mkForce "mind_the_gap-${pkgs.mind-the-gap.version}-${config.system.nixos.label}-${pkgs.stdenv.hostPlatform.system}";

  # An installation media cannot tolerate a host config defined file
  # system layout on a fresh machine, before it has been formatted.
  swapDevices = lib.mkImageMediaOverride [ ];
  fileSystems = lib.mkImageMediaOverride config.lib.isoFileSystems;

  # The hardened kernel flavour was removed from nixpkgs 26.05 for lack of maintenance, so
  # the image runs the default kernel and keeps its hardening explicit: the locked modules
  # and blacklisted radios below, plus a restrained kernel attack surface for anything
  # unprivileged that might run during a session.
  boot.kernel.sysctl = {
    "kernel.dmesg_restrict" = 1;
    "kernel.kptr_restrict" = 2;
    "kernel.perf_event_paranoid" = 3;
    "kernel.unprivileged_bpf_disabled" = 1;
    "net.core.bpf_jit_harden" = 2;
    "kernel.sysrq" = 0;
    # Nothing on this image has any business tracing another process, and the one
    # process worth attacking holds a seed phrase in memory
    "kernel.yama.ptrace_scope" = 3;
  };

  # Nothing here uses unprivileged user namespaces; without them a whole class of
  # kernel-interface attacks from the (deliberately passwordless) user session is gone.
  # The nix daemon has to go for this: its build sandbox is built on user namespaces,
  # and an air-gapped live image has nothing to build or fetch anyway. The sandbox
  # setting needs flipping too: its default trips the assertion even with nix disabled.
  nix.enable = false;
  nix.settings.sandbox = false;
  security.allowUserNamespaces = false;

  # Zero freed pages immediately. Secrets the tools already wipe are covered either way;
  # this extends the same discipline to every allocation the kernel hands back, so RAM
  # holds as little history as possible at any moment. It narrows what a warm reboot or
  # cold boot attack can find, though true immunity is not reachable in software: power
  # the machine off and let it sit before walking away.
  boot.kernelParams = [ "init_on_alloc=1" "init_on_free=1" "efi_pstore.pstore_disable=1" ];

  # Support common file systems for the transfer media. Kept deliberately short: every
  # filesystem here is kernel code parsing whatever USB stick gets plugged in, and vfat is
  # what freshly formatted sticks actually carry.
  boot.supportedFilesystems = [ "btrfs" "vfat" ];

  # Make sure iso is distinguishable
  networking.hostName = "mind-the-gap";

  # The point of this image is the air gap, so enforce it by configuration rather than by
  # discipline: without this NixOS brings up DHCP on every interface, and plugging in a cable
  # would put the "air-gapped" machine on a network.
  networking.useDHCP = lib.mkImageMediaOverride false;
  networking.wireless.enable = false;
  networking.firewall.enable = true;

  # No DHCP is not no network: the iso carries the full kernel module set and udev
  # coldplugs the matching NIC driver during boot, before the module lock below takes
  # hold, so a built-in ethernet port is present and one `ip addr add` away from a working
  # uplink -- and the firewall above filters inbound only. Drop every packet that is not
  # loopback, in both directions, so even a deliberately configured interface moves
  # nothing.
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

  # Keep the radios off entirely; the card readers this image exists for are wired. The USB
  # tethering drivers join them: a phone plugged in "to charge" must not become an uplink
  # during the boot window before the module lock applies.
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

  # Refuse to load kernel modules once booted. The supported tokens (YubiKey, Nitrokey) are
  # driven from userspace through pcscd and need no device modules of their own, so the only
  # hotplug this image must survive is a transfer stick and a token's HID interface -- both
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
  ];

  # Add services and udev rules for common smartcards
  services.pcscd.enable = true;

  hardware.gpgSmartcards.enable = true;
  hardware.nitrokey.enable = true;

  services.udev.packages = [ pkgs.yubikey-personalization pkgs.solo2-cli ];

  # The point of a live system is amnesia, and pstore is firmware-backed persistence:
  # kernel crash records written to EFI variables survive power-off and carry dmesg,
  # registers and stack contents. The kernel parameter above keeps the EFI backend from
  # registering at all, so nothing can be deposited there in the first place.

  # Add any tools we might need. Nothing here may be able to reach a network: the image is
  # air-gapped by configuration, and a downloader on board would only invite excuses.
  environment.systemPackages = with pkgs; [
    # Clear the traces a session leaves on the terminal: scrollback, screen and, via the
    # shell alias below, the shell history. For leaving a machine mid-session; powering
    # off does strictly more.
    (writeShellScriptBin "forget" ''
      # 2J clears the screen, 3J the scrollback, H homes the cursor; reset restores
      # whatever state a crashed ceremony might have left
      printf '\033[2J\033[3J\033[H'
      tput reset 2>/dev/null || true
    '')
    gnupg
    man
    mind-the-gap
    openssl
    paperkey
    pwgen
    solo2-cli
    xkcdpass
    yubikey-manager
  ];

  # Link common completion files
  environment.pathsToLink = [ "/share/bash" "/share/man" ];

  programs = {
    # Provide some sensible aliases. `forget` must run in the interactive shell itself:
    # a child process cannot clear its parent's in-memory history, so the alias chains
    # `history -c` in front of the script that wipes the terminal.
    bash.shellAliases = {
      "mtg" = "mind-the-gap";
      "forget" = "history -c; command forget";
    };

    # Enable gnupg ssh agent
    gnupg.agent = {
      enable = true;
      enableSSHSupport = true;
      pinentryPackage = pkgs.pinentry-curses;
    };

    # Disable default ssh agent
    ssh.startAgent = false;

    # Install sensible default editor
    neovim.defaultEditor = true;
    neovim.enable = true;
    neovim.vimAlias = true;
  };

  # Default user to use to run mind-the-gap.
  #
  # Passwordless login, sudo and autologin below are deliberate: the threat model of a live
  # image is physical possession, and whoever holds the machine owns the session anyway. The
  # secrets this image handles live in the operator's head and on the cards, never on disk.
  users.users.alice = {
    isNormalUser = true;
    extraGroups = [ "wheel" "video" ];
    # Allow to login without password
    initialHashedPassword = "";
  };

  # Allow passwordless sudo from alice user
  security.sudo = {
    enable = lib.mkDefault true;
    wheelNeedsPassword = lib.mkImageMediaOverride false;
  };

  # Automatically log in at the virtual consoles.
  services.getty.autologinUser = "alice";

  # A userspace terminal on the virtual consoles instead of the kernel VT: tty1 gains a
  # real alternate screen, so the QR viewer vanishes without a trace on dismissal, plus
  # clean rendering of the half-block QR glyphs and live font zoom with
  # Ctrl+Alt+Plus/Minus when a dense code needs more rows than the screen has.
  services.kmscon = {
    enable = true;
    fonts = [ { name = "DejaVu Sans Mono"; package = pkgs.dejavu_fonts; } ];
    # Small enough that a certificate-sized QR fits on one 1080p screen
    extraConfig = "font-size=12";
  };

  # Remind user to mind the gap. The gettys (serial console) show it before login;
  # kmscon runs no getty, so interactive shells print it themselves once per login.
  services.getty.helpLine = banner;
  environment.loginShellInit = ''
    cat <<'BANNER'
${banner}BANNER
  '';

  # Mark nixos variant
  system.nixos.variant_id = "mind-the-gap";

  # Use current state version
  system.stateVersion = lib.mkDefault lib.trivial.release;
}
