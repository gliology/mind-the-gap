# The tools that go with mind-the-gap, shared by the tools module and the `tools` package,
# so a host can carry them in its system or receive them as a profile of their own. Nothing
# here may need a network: the machine is air-gapped by its firewall, which also holds the
# curl every NixOS system carries.
pkgs: with pkgs; [
  gnupg
  man
  openssl
  paperkey
  pwgen
  solo2-cli
  xkcdpass
  yubikey-manager
]
