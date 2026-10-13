# Nitrokey's opcard as a host binary: the vpicc example connects to vpcd and
# presents a complete OpenPGP card implementation as a PC/SC reader
{
  pkgs,
  craneLib,
  opcard,
}:

craneLib.buildPackage {
  pname = "opcard-vpicc";
  version = "0";
  src = opcard;

  # Upstream does not track a Cargo.lock, so the dependency tree is pinned here:
  # opcard.lock was generated from the locked input revision and vendored from it.
  # Regenerate with `cargo generate-lockfile` in the input source when bumping.
  cargoVendorDir = craneLib.vendorCargoDeps { cargoLock = ./opcard.lock; };
  postPatch = ''
    cp ${./opcard.lock} Cargo.lock
  '';

  # The example's dependency tree reaches the pcsc crate, whose build script
  # probes for the pcsclite headers
  nativeBuildInputs = [
    pkgs.pkg-config
    pkgs.rustPlatform.bindgenHook
  ];
  buildInputs = with pkgs; [
    pcsclite
    nettle
    gmp
  ];

  # Examples are not installed by the default flow, and the crate's own tests
  # want a card to talk to -- this build *is* the card
  doCheck = false;
  # rsa4096 brings the 2048 and 3072 bit imports with it
  cargoBuildCommand = "cargo build --release --example vpicc --features rsa4096";
  installPhaseCommand = ''
    mkdir -p $out/bin
    cp target/release/examples/vpicc $out/bin/opcard-vpicc
  '';
}
