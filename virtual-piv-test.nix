# Provision a *virtual* PIV card end to end.
#
# The card is the trussed piv-authenticator -- the Nitrokey 3's PIV implementation --
# running as a host process against vsmartcard's vpcd, exactly like the OpenPGP twin in
# virtual-card-test.nix. Unlike that twin this path leans on Yubico vendor extensions
# (device reset, ECC key import with pin and touch policies, AES-256 management key,
# GET METADATA read-back, msroots), so it also proves the app's Yubico client
# compatibility. Touch prompts go through trussed's user-presence request, which the
# virtual platform grants automatically -- what stays uncovered is real readers and a
# human finger.
{ pkgs, piv-vpicc, ... }:

{
  name = "mind-the-virtual-piv";

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
    systemd.services.piv-vpicc = {
      wantedBy = [ "multi-user.target" ];
      requires = [ "pcscd.service" ];
      after = [ "pcscd.service" ];
      serviceConfig = {
        ExecStart = "${piv-vpicc}/bin/piv-vpicc";
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

    # The virtual card runs without a device uuid and so reports the app's fallback
    # serial. Written to a file rather than piped: under pipefail an early-exiting
    # grep -q would fail the pipeline even though the card is there.
    machine.wait_until_succeeds(
        "mind-the-gap piv status > /tmp/status && grep -q 'Serial: 5437251' /tmp/status",
        timeout=120,
    )

    # A fixed test mnemonic, never a real one: this seed is in the repository
    seed = (
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon art"
    )
    identity = f"-s '{seed}' -n 'Virt Test'"
    card = "-c 5437251"

    # Provision the virtual card: reset by pin exhaustion, derived AES-256 management
    # key (with required touch), user pin, four imported P-256 keys with their pin and
    # touch policies verified through metadata read-back, the certificate chain, and
    # the certificate authorities in msroots
    machine.succeed(
        f"mind-the-gap {identity} piv upload --pin 471120 --yes {card} -o /tmp/chain.pem"
    )
    machine.succeed("grep -q 'BEGIN CERTIFICATE' /tmp/chain.pem")

    # The card must hold exactly the derived chain, byte for byte -- including the slot
    # policies and msroots, whose mismatches only warn, so assert on the log
    machine.succeed(
        f"mind-the-gap {identity} piv check --pin 471120 {card} 2> /tmp/check.log"
    )
    machine.fail("grep -Eq 'Policy mismatch|WARN.*msroots' /tmp/check.log")

    # Re-provisioning must converge to the same card: a lost card is replaceable
    machine.succeed(
        f"mind-the-gap {identity} piv upload --pin 471120 --yes {card}"
    )
    machine.succeed(f"mind-the-gap {identity} piv check --pin 471120 {card}")

    # A wrong subkey id derives a different management key and chain, and must fail
    machine.fail(f"mind-the-gap {identity} -k other piv check --pin 471120 {card}")
  '';
}
