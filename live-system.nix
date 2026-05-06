{ pkgs, lib, modulesPath, config, ... }:

{
  imports = [
    # Use NixOS iso base for booting
    (modulesPath + "/profiles/minimal.nix")
    (modulesPath + "/installer/cd-dvd/iso-image.nix")
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
  };

  # Differentiate image from install iso
  image.fileName = "mind_the_gap-${pkgs.mind-the-gap.version}-${config.system.nixos.label}-${pkgs.stdenv.hostPlatform.system}.iso";

  # An installation media cannot tolerate a host config defined file
  # system layout on a fresh machine, before it has been formatted.
  swapDevices = lib.mkImageMediaOverride [ ];
  fileSystems = lib.mkImageMediaOverride config.lib.isoFileSystems;

  # Hardened kernel might help
  boot.kernelPackages = pkgs.linuxPackages_hardened;

  # Support some common file systems
  boot.supportedFilesystems = [ "btrfs" "ntfs" "vfat" ];

  # Make sure iso is distinguishable
  networking.hostName = "mind-the-gap";

  # Add services and udev rules for common smartcards
  services.pcscd.enable = true;

  hardware.gpgSmartcards.enable = true;
  hardware.nitrokey.enable = true;

  services.udev.packages = [ pkgs.yubikey-personalization pkgs.solo2-cli ];

  # Live system lacks persistens storage, so protect pstore
  environment.etc."systemd/pstore.conf".text = ''
    [PStore]
    Unlink=no
  '';

  # Add any tools we might need
  environment.systemPackages = with pkgs; [
    gnupg
    man
    mind-the-gap
    openssl
    paperkey
    pwgen
    solo2-cli
    wget
    xkcdpass
    yubikey-manager
  ];

  # Link common completion files
  environment.pathsToLink = [ "/share/bash" "/share/man" ];

  # Disable font config
  fonts.fontconfig.enable = false;

  programs = {
    # Provide some sensible aliases
    bash.shellAliases = { "mtg" = "mind-the-gap"; };

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

  # Default user to use to run mind-the-gap
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

  # Remind user to mind the gap
  services.getty.helpLine = ''
    ███╗   ███╗██╗███╗   ██╗██████╗     ████████╗██╗  ██╗███████╗     ██████╗  █████╗ ██████╗
    ████╗ ████║██║████╗  ██║██╔══██╗    ╚══██╔══╝██║  ██║██╔════╝    ██╔════╝ ██╔══██╗██╔══██╗
    ██╔████╔██║██║██╔██╗ ██║██║  ██║       ██║   ███████║█████╗      ██║  ███╗███████║██████╔╝
    ██║╚██╔╝██║██║██║╚██╗██║██║  ██║       ██║   ██╔══██║██╔══╝      ██║   ██║██╔══██║██╔═══╝
    ██║ ╚═╝ ██║██║██║ ╚████║██████╔╝       ██║   ██║  ██║███████╗    ╚██████╔╝██║  ██║██║
    ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝        ╚═╝   ╚═╝  ╚═╝╚══════╝     ╚═════╝ ╚═╝  ╚═╝╚═╝
  '';

  # Mark nixos variant
  system.nixos.variant_id = "mind-the-gap";

  # Use current state version
  system.stateVersion = lib.mkDefault lib.trivial.release;
}
