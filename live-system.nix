{ pkgs, lib, modulesPath, ... }:

{
  imports = [ (modulesPath + "/installer/cd-dvd/installation-cd-minimal.nix") ];

  boot.kernelPackages = pkgs.linuxPackages_hardened;

  isoImage.edition = lib.mkForce "mindthegap";
  networking.hostName = "mind-the-gap";

  services.pcscd.enable = true;
  services.udev.packages = [ pkgs.yubikey-personalization ];

  environment.systemPackages = with pkgs; [ mind-the-gap gnupg paperkey wget yubikey-manager pwgen xkcdpass ];

  programs = {
    ssh.startAgent = false;
    gnupg.agent = {
      enable = true;
      enableSSHSupport = true;
      pinentryFlavor = "curses";
    };
  };
}

