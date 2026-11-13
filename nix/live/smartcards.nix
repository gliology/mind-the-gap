# The cards this is for: pcscd and the udev rules of the supported tokens, and gpg-agent as
# the ssh agent, asking for PINs on the terminal.
{ pkgs, ... }:

{
  services.pcscd.enable = true;

  # scdaemon through pcscd rather than its own CCID driver, which would take the token away
  # from pcscd and with it from mind-the-gap; see docs/after-the-gap.md. This also makes the
  # udev rules that driver needs (hardware.gpgSmartcards) unnecessary.
  environment.etc."gnupg/scdaemon.conf".text = ''
    disable-ccid
  '';

  hardware.nitrokey.enable = true;

  services.udev.packages = [
    pkgs.yubikey-personalization
    pkgs.solo2-cli
  ];

  programs = {
    # Enable gnupg ssh agent
    gnupg.agent = {
      enable = true;
      enableSSHSupport = true;
      pinentryPackage = pkgs.pinentry-curses;
    };

    # Disable default ssh agent
    ssh.startAgent = false;
  };
}
