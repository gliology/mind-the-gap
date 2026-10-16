# Provision Gnuk, the OpenPGP token firmware of the Free Software Initiative of Japan,
# through its GNU/Linux emulation over USB/IP.
#
# Gnuk is the one OpenPGP card here written independently of opcard, in C on its own
# scheduler, so it checks mind-the-gap against a second reading of the specification rather
# than the same code twice. Like the simulated Nitrokey 3 it attaches through vhci-hcd and
# reaches pcscd through libccid, which knows its USB id; its button is pressed by the
# wrapper the card package ships. Gnuk 2 holds Curve25519 (and secp256k1 and Curve448,
# which mind-the-gap does not derive) but neither NIST P-256 nor RSA, so those two are
# checked for the refusal that leaves the card untouched.
{
  pkgs,
  gnuk-usbip,
  pgp-suite,
  ...
}:

{
  name = "mind-the-usbip-gnuk";

  nodes.machine =
    {
      self,
      pkgs,
      config,
      ...
    }:
    {
      # Provide mind-the-gap derivation via overlay
      nixpkgs.overlays = [ self.overlays.default ];

      environment.systemPackages = [
        pkgs.mind-the-gap
        pgp-suite
        pkgs.usbutils
        config.boot.kernelPackages.usbip
      ];

      # The virtual host controller that USB/IP devices attach to
      boot.kernelModules = [ "vhci-hcd" ];

      services.pcscd.enable = true;

      # The emulated token, with its flash in a file. FSIJ's USB id, under which libccid
      # lists Gnuk; the card ident is derived from the emulation's fixed device id.
      systemd.services.gnuk-usbip = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          ExecStart = "${gnuk-usbip}/bin/gnuk-with-button --vidpid=234b:0000 /var/lib/gnuk/flash";
          StateDirectory = "gnuk";
          Restart = "always";
          RestartSec = 1;
        };
      };
    };

  testScript = ''
    start_all()

    machine.wait_for_unit("gnuk-usbip.service")
    machine.wait_until_succeeds("usbip attach -r 127.0.0.1 -b 1-1", timeout=60)
    machine.wait_until_succeeds("lsusb -d 234b:0000", timeout=60)

    machine.systemctl("start pcscd.service")
    machine.wait_for_unit("pcscd.service")

    # Written to a file rather than piped: under pipefail an early-exiting grep -q would
    # fail the pipeline even though the card is there
    machine.wait_until_succeeds(
        "mind-the-gap pgp status > /tmp/pgp-status && grep -q 'Card FFFE:F1420A7A' /tmp/pgp-status",
        timeout=60,
    )

    # A fixed test mnemonic, never a real one: this seed is in the repository
    seed = (
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon art"
    )
    identity = f"-s '{seed}' -n 'Gnuk Test' -m gnuk@example.com"
    card = "-c FFFE:F1420A7A"

    # Provision through the command line, read back, refuse a wrong subkey id
    machine.succeed(f"mind-the-gap {identity} pgp upload --pin 471120 --yes {card} -o /tmp/cert.asc")
    machine.succeed("grep -q 'BEGIN PGP PUBLIC KEY BLOCK' /tmp/cert.asc")
    machine.succeed(f"mind-the-gap {identity} pgp check {card}")
    machine.fail(f"mind-the-gap {identity} -k other pgp check {card}")

    # The algorithms Gnuk 2 dropped are refused before the reset: the keys stay in place
    for algorithm in ["p256", "rsa2048"]:
        machine.fail(
            f"mind-the-gap {identity} pgp --algorithm {algorithm} upload --pin 471120 --yes {card} "
            "2> /tmp/refused.log"
        )
        machine.succeed("grep -q 'the card was not touched' /tmp/refused.log")
        machine.succeed(f"mind-the-gap {identity} pgp check {card}")

    # The OpenPGP checklist on Curve25519, as in virtual-pgp: provisioning, the card read
    # back independently, every key at work on the card, gpg using it end to end
    machine.succeed(
        "MTG_HARDWARE_TEST_CARD=FFFE:F1420A7A pgp-suite --exact provision_and_verify_card "
        "--nocapture > /tmp/pgp-suite.log 2>&1 || { cat /tmp/pgp-suite.log; exit 1; }"
    )
    machine.succeed("grep -q 'test result: ok. 1 passed' /tmp/pgp-suite.log")
  '';
}
