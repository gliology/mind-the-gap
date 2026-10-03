# Provision a *virtual* OpenPGP card end to end.
#
# The card is Nitrokey's opcard -- the Nitrokey 3's OpenPGP implementation -- running as a
# host process against vsmartcard's vpcd, so the whole PC/SC path (pcscd, the reader
# driver, APDUs, the card state machine) is exercised with no hardware and no USB. This is
# the automated half of what the destructive suites do to a real YubiKey: upload, check
# and configure, driven through the real binary. What it cannot cover is exactly what the
# manual checklist exists for: real readers, touch prompts and vendor extensions.
{ pkgs, opcard-vpicc, ... }:

{
  name = "mind-the-virtual-card";

  nodes.machine = { self, pkgs, ... }: {
    # Provide mind-the-gap derivation via overlay
    nixpkgs.overlays = [ self.overlays.default ];

    environment.systemPackages = [ pkgs.mind-the-gap ];

    # pcscd with vpcd as its only reader: a TCP listener on localhost that virtual cards
    # connect to, presented to clients as an ordinary PC/SC reader
    services.pcscd.enable = true;
    services.pcscd.readerConfig = ''
      FRIENDLYNAME "Virtual PCD"
      DEVICENAME   /dev/null:0x8C7B
      LIBPATH      ${pkgs.vsmartcard-vpcd}/var/lib/pcsc/drivers/serial/libifdvpcd.so
      CHANNELID    0x8C7B
    '';

    # The virtual card itself. Restart until it wins the race with pcscd's socket
    # activation: vpcd only listens once the driver is loaded.
    systemd.services.opcard = {
      wantedBy = [ "multi-user.target" ];
      requires = [ "pcscd.service" ];
      after = [ "pcscd.service" ];
      serviceConfig = {
        ExecStart = "${opcard-vpicc}/bin/opcard-vpicc";
        Restart = "always";
        RestartSec = 1;
      };
    };
  };

  testScript = ''
    start_all()

    machine.wait_for_unit("multi-user.target")
    machine.systemctl("start pcscd.service")
    machine.wait_for_unit("pcscd.service")

    # The virtual card announces itself with the FSIJ test identifier
    machine.wait_until_succeeds(
        "mind-the-gap pgp status | grep -q 'Card 0000:00000000'", timeout=120
    )

    # A fixed test mnemonic, never a real one: this seed is in the repository
    seed = (
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon art"
    )
    identity = f"-s '{seed}' -n 'Virt Test' -m virt@example.com"
    card = "-c 0000:00000000"

    # Provision the virtual card. --keep-factory-pin on purpose: opcard is reset by
    # recreating the VM, and the factory pins keep the test independent of pin handling.
    machine.succeed(
        f"mind-the-gap {identity} pgp upload --keep-factory-pin --yes {card} -o /tmp/cert.asc"
    )
    machine.succeed("grep -q 'BEGIN PGP PUBLIC KEY BLOCK' /tmp/cert.asc")

    # The card must hold exactly the derived keys
    machine.succeed(f"mind-the-gap {identity} pgp check {card}")

    # And the post-provisioning configuration path works against a conforming card
    machine.succeed(
        f"mind-the-gap {identity} pgp configure {card} --lang en,de --url https://example.com/virt.asc"
    )

    # A wrong subkey id must be detected before any pin is spent
    machine.fail(f"mind-the-gap {identity} -k other pgp check {card}")
  '';
}
