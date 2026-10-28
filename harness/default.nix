# The hardware test harness: `nix run .#hardware-tests` runs the suites against a named
# card or builds the simulated cards' checks, records the outcomes next to what was
# expected (expected.toml, results/), and renders them into the book; see hardware-tests.py
# and docs/hardware-tests.md.
{
  pkgs,
  lib,
  rust,
  src,
}:

let
  # pyscard finds the named card and reads its firmware; nothing else talks to a card but
  # the suites themselves
  python = pkgs.python3.withPackages (ps: [ ps.pyscard ]);

  program = pkgs.writeShellApplication {
    name = "hardware-tests";
    runtimeInputs = [
      pkgs.git
      pkgs.gnupg
    ];
    text = ''
      export MTG_PIV_SUITE=${rust.pivHardwareSuite}/bin/piv-hardware-suite
      export MTG_PGP_SUITE=${rust.pgpSuite}/bin/pgp-suite
      exec ${python.interpreter} ${./hardware-tests.py} "$@"
    '';
  };

  # What rendering reads and writes, and nothing else, so the check only reruns when one
  # of them changes
  renderSources = lib.fileset.toSource {
    root = src;
    fileset = lib.fileset.unions [
      (src + "/Cargo.toml")
      (src + "/harness/expected.toml")
      (lib.fileset.maybeMissing (src + "/harness/results"))
      (src + "/docs/test-results.md")
      (src + "/docs/releases.md")
    ];
  };
in
{
  app = {
    type = "app";
    program = "${program}/bin/hardware-tests";
    meta.description = "Run the hardware suites and record their results";
  };

  # The book shows what the results say: rendering them again changes nothing
  check = pkgs.runCommand "check-test-results" { } ''
    cd ${renderSources}
    ${python.interpreter} ${./hardware-tests.py} --render --check
    touch $out
  '';
}
