# The VM checks that provision cards end to end through the real binary, each from a
# test module in this directory and the cards it talks to
{
  pkgs,
  self,
  cards,
  piv-suite,
  pgp-suite,
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
    managementKey:
    vmTest (
      import ./virtual-piv-builder.nix {
        inherit pkgs managementKey;
        inherit (cards) piv-vpicc;
      }
    );
in
{
  # Provision a virtual OpenPGP card (Nitrokey's opcard behind vpcd) end to end:
  # init, upload and check through the real binary, with no hardware involved
  virtual-pgp = vmTest (
    import ./virtual-pgp.nix {
      inherit pkgs pgp-suite;
      inherit (cards) opcard-vpicc;
    }
  );

  # Both suites at once on a virtual PIV and a virtual OpenPGP card in one machine, so a
  # suite that disturbs another card shows here rather than on a test host
  virtual-parallel = vmTest (
    import ./virtual-parallel.nix {
      inherit pkgs piv-suite pgp-suite;
      inherit (cards) piv-vpicc opcard-vpicc;
    }
  );

  # The same for PIV, once per algorithm: provision the trussed piv-authenticator
  # behind vpcd end to end -- reset, pin and management key handling, key import
  # with metadata read-back, the certificate chain -- then run the card-level
  # half of the destructive suite against it, so the card is seen signing and
  # agreeing with the keys it took
  virtual-piv = virtualPiv "p256";
  virtual-piv-curve25519 = virtualPiv "curve25519";
  virtual-piv-rsa2048 = virtualPiv "rsa2048";
  virtual-piv-p384 = virtualPiv "p384";
  virtual-piv-rsa3072 = virtualPiv "rsa3072";
  virtual-piv-rsa4096 = virtualPiv "rsa4096";

  # The build server profile (docs/unattended-host.md) on the same card: P-384, pin once,
  # touch never, management access without a touch, with the policies read back through
  # yubikit. YubiKey 4 behaviour is covered on a real YubiKey 4, see docs/hardware-tests.md;
  # its triple DES management key is forced onto the virtual card by the second variant.
  virtual-piv-builder = virtualPivBuilder null;
  virtual-piv-builder-tdes = virtualPivBuilder "tdes";

  # The NixOS module's defaults and ceremony on an image, run against a virtual PIV card:
  # a bare `mind-the-gap` runs the ceremony, dry, recorded and in plumbing mode
  image-ceremony = vmTest (
    import ./image-ceremony.nix {
      inherit pkgs;
      inherit (cards) piv-vpicc;
    }
  );

  # A whole simulated Nitrokey 3 attached over USB/IP: PIV and OpenPGP provisioned
  # through the kernel's USB stack, libccid and the firmware's own dispatcher
  usbip-nk3 = vmTest (
    import ./usbip-nk3.nix {
      inherit pkgs piv-suite pgp-suite;
      inherit (cards) nk3-usbip;
    }
  );
  # Gnuk, a second OpenPGP card written independently of opcard, attached the same way
  usbip-gnuk = vmTest (
    import ./usbip-gnuk.nix {
      inherit pkgs pgp-suite;
      inherit (cards) gnuk-usbip;
    }
  );
  # CanoKey, a third PIV and OpenPGP card and the first PIV one outside trussed, emulated
  # by QEMU as a USB device of the machine
  canokey = vmTest (
    import ./canokey.nix {
      inherit pkgs piv-suite pgp-suite;
    }
  );
}
