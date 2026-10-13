# The VM checks that provision cards end to end through the real binary, each from a
# test module in this directory and the cards it talks to
{
  pkgs,
  self,
  cards,
  piv-suite,
}:

let
  nixos-lib = import (pkgs.path + "/nixos/lib") { };

  # Make self available in the node config, for the mind-the-gap overlay
  vmTest =
    test:
    (nixos-lib.runTest {
      hostPkgs = pkgs;
      node.specialArgs = { inherit self; };
      imports = [ test ];
    }).config.result;

  virtualPiv =
    algorithm:
    vmTest (
      import ./virtual-piv.nix {
        inherit pkgs algorithm piv-suite;
        inherit (cards) piv-vpicc;
      }
    );

  virtualPivBuilder =
    algorithm:
    vmTest (
      import ./virtual-piv-builder.nix {
        inherit pkgs algorithm;
        inherit (cards) piv-vpicc;
      }
    );
in
{
  # Provision a virtual OpenPGP card (Nitrokey's opcard behind vpcd) end to end:
  # upload, check and config through the real binary, with no hardware involved
  virtual-pgp = vmTest (
    import ./virtual-pgp.nix {
      inherit pkgs;
      inherit (cards) opcard-vpicc;
    }
  );

  # The same for PIV, once per algorithm: provision the trussed piv-authenticator
  # behind vpcd end to end -- reset, pin and management key handling, key import
  # with metadata read-back, the certificate chain -- then run the card-level
  # half of the destructive suite against it, so the card is seen signing and
  # agreeing with the keys it took
  virtual-piv = virtualPiv "p256";
  virtual-piv-curve25519 = virtualPiv "curve25519";

  # The build server profile (docs/piv-build-server.md) on the same card: P-384, pin once,
  # touch never, management access without a touch, with the policies read back through
  # yubikit. YubiKey 4 behaviour is covered on a real YubiKey 4, see docs/hardware-tests.md.
  virtual-piv-builder = virtualPivBuilder "p384";

  # A whole simulated Nitrokey 3 attached over USB/IP: PIV and OpenPGP provisioned
  # through the kernel's USB stack, libccid and the firmware's own dispatcher
  usbip-nk3 = vmTest (
    import ./usbip-nk3.nix {
      inherit pkgs piv-suite;
      inherit (cards) nk3-usbip;
    }
  );
}
