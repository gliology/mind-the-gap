# Provision a *simulated* Nitrokey 3 over the kernel's USB stack.
#
# The card is Nitrokey's own firmware built as its USB/IP runner: the complete Nitrokey 3
# app set behind the firmware's APDU dispatcher and USB CCID class, running as a host
# process that the VM's kernel attaches through vhci-hcd. pcscd finds it by hotplug and
# talks to it through libccid like to any USB key, so beyond the vpcd checks this covers
# the USB descriptors, CCID framing, the dispatcher's selection between applications and
# the firmware's backend wiring. The PIV app is our piv-authenticator input, so the same
# code is provisioned here as in virtual-piv; OpenPGP is the firmware's own opcard.
{
  pkgs,
  nk3-usbip,
  piv-suite,
  pgp-suite,
  ...
}:

{
  name = "mind-the-usbip-nk3";

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
        piv-suite
        pgp-suite
        pkgs.usbutils
        config.boot.kernelPackages.usbip
      ];

      # The virtual host controller that USB/IP devices attach to
      boot.kernelModules = [ "vhci-hcd" ];

      # pcscd with its default libccid, which knows the Nitrokey 3's USB ids
      services.pcscd.enable = true;

      # The simulated key. A fixed serial makes the PIV serial (its first four bytes) and
      # the OpenPGP card ident predictable; user presence is granted automatically.
      systemd.services.nk3-usbip = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          ExecStart = "${nk3-usbip}/bin/usbip-runner --ccid --serial 0x5eed5eed5eed5eed5eed5eed5eed5eed";
          Restart = "always";
          RestartSec = 1;
        };
      };
    };

  testScript = ''
    start_all()

    machine.wait_for_unit("nk3-usbip.service")
    machine.wait_for_open_port(3240)
    machine.wait_until_succeeds("usbip attach -r 127.0.0.1 -b 1-1", timeout=60)
    machine.wait_until_succeeds("lsusb -d 20a0:42b2", timeout=60)

    machine.systemctl("start pcscd.service")
    machine.wait_for_unit("pcscd.service")

    # Written to a file rather than piped: under pipefail an early-exiting grep -q would
    # fail the pipeline even though the card is there
    machine.wait_until_succeeds(
        "mind-the-gap piv status > /tmp/piv-status && grep -q 'Serial: 1592614637' /tmp/piv-status",
        timeout=120,
    )

    # A fixed test mnemonic, never a real one: this seed is in the repository
    seed = (
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon art"
    )

    # PIV, as in virtual-piv: provision, read back byte for byte without warnings,
    # converge on a second upload, refuse a wrong subkey id
    identity = f"-s '{seed}' -n 'Usbip Test'"
    card = "-c 1592614637"
    machine.succeed(
        f"mind-the-gap {identity} piv upload --pin 471120 --yes {card} -o /tmp/chain.pem"
    )
    machine.succeed("grep -q 'BEGIN CERTIFICATE' /tmp/chain.pem")
    machine.succeed(f"mind-the-gap {identity} piv check --pin 471120 {card} 2> /tmp/check.log")
    machine.fail("grep -Eq 'Policy mismatch|WARN.*msroots' /tmp/check.log")
    machine.succeed(f"mind-the-gap {identity} piv upload --pin 471120 --yes {card}")
    machine.succeed(f"mind-the-gap {identity} piv check --pin 471120 {card}")
    machine.fail(f"mind-the-gap {identity} -k other piv check --pin 471120 {card}")

    # The card-level half of the destructive suite on every algorithm: the card signs in
    # 9A, 9C and 9E and agrees or decrypts in 9D, each result compared with the same
    # computation off the card
    for algorithm in ["p256", "p384", "curve25519", "rsa2048", "rsa3072", "rsa4096"]:
        machine.succeed(
            "MTG_HARDWARE_TEST_SERIAL=1592614637 piv-suite --ignored --exact "
            f"provision_and_verify_{algorithm}_card --nocapture > /tmp/suite.log 2>&1 "
            "|| { cat /tmp/suite.log; exit 1; }"
        )
        machine.succeed("grep -q 'test result: ok. 1 passed' /tmp/suite.log")

    # OpenPGP on a fresh key, as in virtual-pgp: provisioned with the factory pins. The PIV
    # runs above leave four RSA-4096 keys behind, and the simulated flash, kept in RAM, is
    # too small for OpenPGP's three on top; a restart of the runner empties it
    machine.succeed("usbip detach -p 00")
    machine.systemctl("restart nk3-usbip.service")
    machine.wait_for_open_port(3240)
    machine.wait_until_succeeds("usbip attach -r 127.0.0.1 -b 1-1", timeout=60)
    machine.wait_until_succeeds("lsusb -d 20a0:42b2", timeout=60)
    machine.wait_until_succeeds(
        "mind-the-gap pgp status > /tmp/pgp-status && grep -q 'Card 000F:5EED5EED' /tmp/pgp-status",
        timeout=60,
    )
    identity = f"-s '{seed}' -n 'Usbip Test' -m usbip@example.com"
    card = "-c 000F:5EED5EED"
    machine.succeed(f"mind-the-gap {identity} pgp upload --yes {card} -o /tmp/cert.asc")
    machine.succeed("grep -q 'BEGIN PGP PUBLIC KEY BLOCK' /tmp/cert.asc")
    machine.succeed(f"mind-the-gap {identity} pgp check {card}")
    machine.fail(f"mind-the-gap {identity} -k other pgp check {card}")

    # Then the OpenPGP suite on every algorithm, as in virtual-pgp: provisioning, the card
    # read back independently, every key at work on the card
    machine.succeed(
        "MTG_HARDWARE_TEST_CARD=000F:5EED5EED pgp-suite --exact "
        "provision_and_verify_card provision_and_verify_p256_card provision_and_verify_rsa_cards "
        "--nocapture > /tmp/pgp-suite.log 2>&1 || { cat /tmp/pgp-suite.log; exit 1; }"
    )
    machine.succeed("grep -q 'test result: ok. 3 passed' /tmp/pgp-suite.log")
  '';
}
