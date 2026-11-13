{
  pkgs,
  lib,
  modulesPath,
  config,
  ...
}:

let
  # The pre-login reminder, shared between the serial gettys and the kmscon shells:
  # the banner from assets/, followed by what this machine is running, so a stack of
  # burned sticks stays tellable apart. The VT and kmscon both speak its truecolor
  # escapes.
  banner = ''
    ${builtins.readFile ../../assets/motd.ansi}
     mind-the-gap ${pkgs.mind-the-gap.version} · image ${config.system.nixos.label}

     ${start}; `forget` clears screen,
     scrollback and shell history; power off and let the machine sit before walking away.
  '';

  # What a bare `mind-the-gap` does on this image: the configured ceremony, or a session
  start =
    let
      recipe = config.programs.mind-the-gap.defaultRecipe;
    in
    if recipe == null then
      "mind-the-gap opens an interactive session"
    else
      "mind-the-gap runs the ceremony `${recipe}` (`mind-the-gap run --dry-run` shows its steps)";

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
    png2icns $out ${../../assets/logo-512.png} ${../../assets/icon-48.png} \
      ${../../assets/icon-32.png} ${../../assets/icon-16.png}
  '';

  # One splash per bootloader, the mark centred on a dark canvas at the loader's native
  # resolution (syslinux is fixed at 800x600 by its MENU RESOLUTION). The mark carries
  # the sign's fixed palette, so it renders straight from the committed SVG.
  splash =
    width: height: logoSize:
    pkgs.runCommand "mtg-splash-${toString width}x${toString height}.png"
      {
        nativeBuildInputs = [
          pkgs.resvg
          pkgs.imagemagick
        ];
      }
      ''
        resvg -w ${toString logoSize} -h ${toString logoSize} ${../../assets/logo.svg} logo.png
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
    # airgap module's nftables table is what actually keeps such an interface mute.
    (modulesPath + "/profiles/all-hardware.nix")
    # What makes it an air-gapped ceremony machine, shared with installed hosts: the
    # tools among them bring the tool, with the defaults and ceremony an image may ship
    ./airgap.nix
    ./hardening.nix
    ./smartcards.nix
    ./console.nix
    ./tools.nix
  ];

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
      {
        source = autorunInf;
        target = "/autorun.inf";
      }
      {
        source = ../../assets/favicon.ico;
        target = "/volume.ico";
      }
      {
        source = volumeIcns;
        target = "/.VolumeIcon.icns";
      }
      {
        source = xdgVolumeInfo;
        target = "/.xdg-volume-info";
      }
    ];
  };

  # Differentiate image from install iso. Since nixpkgs 26.05 the file name derives from
  # image.baseName, which the iso module also sets, so the override has to be forced.
  image.baseName = lib.mkForce "mind_the_gap-${pkgs.mind-the-gap.version}-${config.system.nixos.label}-${pkgs.stdenv.hostPlatform.system}";

  # An installation media cannot tolerate a host config defined file
  # system layout on a fresh machine, before it has been formatted.
  swapDevices = lib.mkImageMediaOverride [ ];
  fileSystems = lib.mkImageMediaOverride config.lib.isoFileSystems;

  # Nothing here uses unprivileged user namespaces; without them a whole class of
  # kernel-interface attacks from the (deliberately passwordless) user session is gone.
  # The nix daemon has to go for this: its build sandbox is built on user namespaces,
  # and an air-gapped live image has nothing to build or fetch anyway. The sandbox
  # setting needs flipping too: its default trips the assertion even with nix disabled.
  nix.enable = false;
  nix.settings.sandbox = false;
  security.allowUserNamespaces = false;

  # Make sure iso is distinguishable
  networking.hostName = "mind-the-gap";

  # Default user to use to run mind-the-gap.
  #
  # Passwordless login, sudo and autologin below are deliberate: the threat model of a live
  # image is physical possession, and whoever holds the machine owns the session anyway. The
  # secrets this image handles live in the operator's head and on the cards, never on disk.
  users.users.alice = {
    isNormalUser = true;
    extraGroups = [
      "wheel"
      "video"
    ];
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

  # Remind user to mind the gap
  mind-the-gap.banner = banner;

  # Mark nixos variant
  system.nixos.variant_id = "mind-the-gap";

  # Use current state version
  system.stateVersion = lib.mkDefault lib.trivial.release;
}
