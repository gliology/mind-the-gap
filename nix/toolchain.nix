# The toolchain declared in rust-toolchain.toml, one derivation carrying cargo,
# rustc, rustfmt, clippy, rust-analyzer and rust-src
{ fenix, system }:

fenix.packages.${system}.fromToolchainFile {
  file = ../rust-toolchain.toml;
  # Hash of the release manifest, identical for every system; it changes only when
  # the channel in rust-toolchain.toml does. To refresh: set to
  # nixpkgs.lib.fakeSha256, build, and copy the hash nix reports it "got".
  sha256 = "sha256-SBKjxhC6zHTu0SyJwxLlQHItzMzYZ71VCWQC2hOzpRY=";
}
