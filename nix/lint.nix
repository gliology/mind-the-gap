# Whole-repository source checks that need no build: spelling, unused dependencies
# and the formatting of the Nix code
{ pkgs }:

{
  # Spell-check the source and prose. `fpr` (a GnuPG record type) is allowlisted in
  # .typos.toml; everything else that trips this is a real typo.
  typos = pkgs.runCommand "check-typos" { nativeBuildInputs = [ pkgs.typos ]; } ''
    cd ${../.}
    typos
    touch $out
  '';

  # Unused-dependency check. Textual, so no build and no network -- the one rename
  # false positive (tiny-bip39 imported as `bip39`) is ignored in Cargo.toml.
  machete =
    pkgs.runCommand "check-machete"
      {
        nativeBuildInputs = [ pkgs.cargo-machete ];
      }
      ''
        cd ${../.}
        cargo-machete
        touch $out
      '';

  # The Nix code follows nixfmt, the formatter nixpkgs itself uses; `nix fmt` applies it
  nixfmt =
    pkgs.runCommand "check-nixfmt"
      {
        nativeBuildInputs = [ pkgs.nixfmt ];
      }
      ''
        cd ${../.}
        find . -name '*.nix' -print0 | xargs -0 nixfmt --check
        touch $out
      '';
}
