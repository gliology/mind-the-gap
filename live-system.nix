{ pkgs, lib, modulesPath, ... }:

{
  imports = [
    (modulesPath + "/installer/cd-dvd/installation-cd-base.nix")
    (modulesPath + "/profiles/minimal.nix")
  ];

  # Hardened kernel might help
  boot.kernelPackages = pkgs.linuxPackages_hardened;

  # Make sure iso is distinguishable
  isoImage.edition = lib.mkForce "mindthegap";
  networking.hostName = "mind-the-gap";

  # Add services and udev rules for common smartcards
  services.pcscd.enable = true;

  hardware.gpgSmartcards.enable = true;
  hardware.nitrokey.enable = true;

  services.udev.packages = [ pkgs.yubikey-personalization pkgs.solo2-cli ];

  # Add any tools we might need
  environment.systemPackages = with pkgs; [
    mind-the-gap
    gnupg
    paperkey
    pwgen
    solo2-cli
    wget
    xkcdpass
    yubikey-manager
  ];

  # Enable gnupg ssh agent
  programs = {
    ssh.startAgent = false;
    gnupg.agent = {
      enable = true;
      enableSSHSupport = true;
      pinentryFlavor = "curses";
    };
  };
}

