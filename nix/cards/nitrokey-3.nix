# The Nitrokey 3 firmware's USB/IP runner, its PIV app swapped for the
# piv-authenticator input so the same PIV code runs here as in virtual-piv
{
  pkgs,
  craneLib,
  piv-authenticator,
  nitrokey-3-firmware,
  usbip-device,
}:

craneLib.buildPackage {
  pname = "nk3-usbip";
  version = "0";

  # The firmware with our lock in place; the lock goes in up front rather than in a
  # build phase, so crane's stubbed dependency build sees it as well
  src = pkgs.applyPatches {
    name = "nitrokey-3-firmware-locked";
    src = nitrokey-3-firmware;
    postPatch = ''
      cp ${./nitrokey-3-firmware.lock} Cargo.lock
    '';
  };

  # nitrokey-3-firmware.lock is the firmware's own lock with piv-authenticator and
  # usbip-device resolved from the overrides; regenerate with `cargo update -p
  # piv-authenticator -p usbip-device` in a checkout carrying the same overrides when an
  # input moves.
  # The overrides go on the command line: crane reads the manifest at evaluation
  # time, where a store path is not allowed, and builds the dependencies from a
  # stubbed copy of it.
  cargoVendorDir = craneLib.vendorCargoDeps { cargoLock = ./nitrokey-3-firmware.lock; };
  cargoExtraArgs =
    "--locked -p usbip-runner"
    + " --config 'patch.crates-io.piv-authenticator.path=\"${piv-authenticator}\"'"
    + " --config 'patch.crates-io.usbip-device.path=\"${usbip-device}\"'";

  # littlefs2-sys generates its bindings at build time
  nativeBuildInputs = [ pkgs.rustPlatform.bindgenHook ];

  # The workspace's tests target the firmware, not this host build. The binary is
  # copied by hand: crane's default install asks `cargo metadata`, which does not
  # get the override above.
  doCheck = false;
  doNotPostBuildInstallCargoBinaries = true;
  installPhaseCommand = ''
    mkdir -p $out/bin
    cp target/release/usbip-runner $out/bin/
  '';
}
