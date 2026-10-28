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
        "mind-the-gap list > /tmp/list && grep -q 'OpenPGP card FFFE:F1420A7A' /tmp/list",
        timeout=60,
    )

    # A fixed test mnemonic, never a real one: this seed is in the repository
    seed = (
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon art"
    )
    # The card seed's commands take the seed alone, the key seed's the identity's names too
    secret = f"-s '{seed}'"
    identity = f"{secret} -n 'Gnuk Test' -m gnuk@example.com"
    options = "--app pgp"
    card = "-c FFFE:F1420A7A"

    # Initialize and provision through the command line. The emulation is built as a stock
    # Gnuk 2, which imports no key before the KDF data object is set, so init sets it up.
    # Gnuk takes a new user pin only once it holds keys, so init leaves the factory pin and
    # says so, and the pin is changed after the upload
    machine.succeed(
        f"mind-the-gap init {secret} {options} --pin 471120 --yes {card} "
        "--log-level info 2> /tmp/init.log"
    )
    machine.succeed("grep -q 'takes its pins hashed' /tmp/init.log")
    machine.succeed("grep -q 'until .pin. changes it after .upload.' /tmp/init.log")
    machine.succeed(f"mind-the-gap upload {identity} {options} --yes {card}")
    machine.succeed(
        f"mind-the-gap pin {options} {card} --current-pin 123456 --pin 471120"
    )
    machine.succeed(f"mind-the-gap publish {identity} {options} --to /tmp/cert.asc")
    machine.succeed("grep -q 'BEGIN PGP PUBLIC KEY BLOCK' /tmp/cert.asc")
    machine.succeed(f"mind-the-gap check {identity} {options} --pin 471120 {card}")
    machine.fail(f"mind-the-gap check {identity} -k other {options} {card}")

    # The algorithms Gnuk 2 dropped are refused before anything is written: the keys stay
    for algorithm in ["p256", "rsa2048", "rsa3072", "rsa4096"]:
        machine.fail(
            f"mind-the-gap upload {identity} {options} --algorithm {algorithm} --yes {card} "
            "2> /tmp/refused.log"
        )
        machine.succeed("grep -q 'the card was not touched' /tmp/refused.log")
        machine.succeed(f"mind-the-gap check {identity} {options} {card}")

    # The OpenPGP checklist on Curve25519, as in virtual-pgp: provisioning, the card read
    # back independently, every key at work on the card, gpg using it end to end
    machine.succeed(
        "MTG_HARDWARE_TEST_CARD=FFFE:F1420A7A pgp-suite --exact provision_and_verify_card "
        "--nocapture > /tmp/pgp-suite.log 2>&1 || { cat /tmp/pgp-suite.log; exit 1; }"
    )
    machine.succeed("grep -q 'test result: ok. 1 passed' /tmp/pgp-suite.log")
  '';
}
