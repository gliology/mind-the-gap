# The trussed PIV app as a host binary, same construction as opcard: its vpicc
# example connects to vpcd and presents the card as a PC/SC reader
{
  pkgs,
  craneLib,
  piv-authenticator,
}:

craneLib.buildPackage {
  pname = "piv-vpicc";
  version = "0";
  src = piv-authenticator;

  # Upstream does not track a Cargo.lock, so the dependency tree is pinned here:
  # piv-authenticator.lock was generated from the locked input revision.
  # Regenerate with `cargo generate-lockfile` in the input source when bumping.
  cargoVendorDir = craneLib.vendorCargoDeps { cargoLock = ./piv-authenticator.lock; };
  postPatch = ''
    cp ${./piv-authenticator.lock} Cargo.lock
  '';

  # littlefs2-sys generates its bindings at build time
  nativeBuildInputs = [ pkgs.rustPlatform.bindgenHook ];

  # The crate's own tests want a card to talk to -- this build *is* the card
  doCheck = false;
  # The software RSA backend is always linked into the virtual card, the app only
  # dispatches to it with `rsa`
  cargoBuildCommand = "cargo build --release --example vpicc --features rsa";
  installPhaseCommand = ''
    mkdir -p $out/bin
    cp target/release/examples/vpicc $out/bin/piv-vpicc
  '';
}
