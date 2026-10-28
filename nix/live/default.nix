# The air-gapped live system: its NixOS configuration, the check that exercises the
# running environment, and the checks that boot the iso
{
  nixpkgs,
  self,
  system,
  pkgs,
  nixos-lib,
}:

let
  # Add mind-the-gap through a nixpkgs overlay
  overlay = {
    nixpkgs.overlays = [ self.overlays.default ];
  };

  # The image as released names its source revision in `mind-the-gap --version` and in every
  # ceremony transcript. This image alone: the checks, the instrumented iso among them, build
  # the package without it, so that a commit which changes no source rebuilds none of them
  revision = self.rev or self.dirtyRev or null;
  released = {
    nixpkgs.overlays = [
      self.overlays.default
    ]
    ++ pkgs.lib.optional (revision != null) (
      final: prev: {
        mind-the-gap = prev.mind-the-gap.overrideAttrs { MIND_THE_GAP_REVISION = revision; };
      }
    );
  };

  # The live iso with the nixos test backdoor baked in, used by the boot checks only;
  # packages.iso remains the clean image
  instrumentedIso =
    (nixpkgs.lib.nixosSystem {
      inherit system;
      modules = [
        overlay
        (import ./system.nix)
        (pkgs.path + "/nixos/modules/testing/test-instrumentation.nix")
      ];
    }).config.system.build.isoImage;

  bootChecks = import ./boot.nix {
    inherit pkgs nixos-lib;
    iso = instrumentedIso;
  };
in
{
  configuration = nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [
      released
      (import ./system.nix)
    ];
  };

  checks = {
    # nixos-test to validate live system environment
    live-system =
      (nixos-lib.runTest {
        hostPkgs = pkgs;

        # Make self available in the node config
        node.specialArgs = { inherit self; };

        imports = [ ./test.nix ];
      }).config.result;
  }
  // (
    if system == "x86_64-linux" then
      bootChecks
    else
      # aarch64 machines boot over UEFI only -- there is no BIOS firmware to test.
      # The check runs without kvm too (the driver falls back to TCG emulation),
      # which is what the github arm runners require.
      { inherit (bootChecks) boot-uefi; }
  );
}
