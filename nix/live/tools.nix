# The tools of a ceremony: mind-the-gap, its defaults and ceremony empty unless a host sets
# them through programs.mind-the-gap.{config,ceremony}, what goes with it, an editor, and
# the memory limit that lets mind-the-gap lock its pages.
{ pkgs, ... }:

{
  imports = [ ../module.nix ];

  programs.mind-the-gap.enable = true;
  environment.systemPackages = import ./tool-packages.nix pkgs;

  # Link common completion files
  environment.pathsToLink = [
    "/share/bash"
    "/share/man"
  ];

  programs = {
    bash.shellAliases.mtg = "mind-the-gap";

    # Install sensible default editor
    neovim.defaultEditor = true;
    neovim.enable = true;
    neovim.vimAlias = true;
  };

  # mind-the-gap locks its memory when the limit allows it (see src/main.rs). Without swap a
  # locked page costs nothing and the limit can go entirely: the PAM entry covers the console
  # logins, the manager default everything systemd spawns.
  security.pam.loginLimits = [
    {
      domain = "*";
      item = "memlock";
      type = "-";
      value = "unlimited";
    }
  ];
  systemd.settings.Manager.DefaultLimitMEMLOCK = "infinity";
}
