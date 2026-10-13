# Provision a *virtual* PIV card end to end.
#
# The card is the trussed piv-authenticator -- the Nitrokey 3's PIV implementation --
# running as a host process against vsmartcard's vpcd, exactly like the OpenPGP twin in
# virtual-pgp.nix. Unlike that twin this path leans on Yubico vendor extensions
# (device reset, ECC key import with pin and touch policies, AES-256 management key,
# GET METADATA read-back, msroots), so it also proves the app's Yubico client
# compatibility. Touch prompts go through trussed's user-presence request, which the
# virtual platform grants automatically -- what stays uncovered is real readers and a
# human finger.
#
# `algorithm` picks the chain the card is provisioned with: P-256, Curve25519 for the
# Ed25519 (0xE0) and X25519 (0xE1) import, or RSA-2048 through the Yubico import layout.
# After the command line round trip the card-level half of the destructive hardware suite
# runs against the same card, which is what proves the keys *work* -- `piv check` only
# reads them back.
{
  pkgs,
  piv-vpicc,
  piv-suite,
  algorithm ? "p256",
  ...
}:

{
  name = "mind-the-virtual-piv-${algorithm}";

  nodes.machine = { self, pkgs, ... }: {
    # Provide mind-the-gap derivation via overlay
    nixpkgs.overlays = [ self.overlays.default ];

    environment.systemPackages = [
      pkgs.mind-the-gap
      piv-suite
    ];

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
    # The algorithm is a backend option, so it sits behind the `piv` word
    piv = "piv --algorithm ${algorithm}"
    card = "-c 5437251"

    # Provision the virtual card: reset by pin exhaustion, derived AES-256 management
    # key (with required touch), user pin, four imported keys in the chosen algorithm with
    # their pin and touch policies verified through metadata read-back, the certificate
    # chain, and the certificate authorities in msroots
    machine.succeed(
        f"mind-the-gap {identity} {piv} upload --pin 471120 --yes {card} -o /tmp/chain.pem"
    )
    machine.succeed("grep -q 'BEGIN CERTIFICATE' /tmp/chain.pem")

    # The card must hold exactly the derived chain, byte for byte -- including the slot
    # policies and msroots, whose mismatches only warn, so assert on the log
    machine.succeed(
        f"mind-the-gap {identity} {piv} check --pin 471120 {card} 2> /tmp/check.log"
    )
    machine.fail("grep -Eq 'Policy mismatch|WARN.*msroots' /tmp/check.log")

    # Re-provisioning must converge to the same card: a lost card is replaceable
    machine.succeed(
        f"mind-the-gap {identity} {piv} upload --pin 471120 --yes {card}"
    )
    machine.succeed(f"mind-the-gap {identity} {piv} check --pin 471120 {card}")

    # A wrong subkey id derives a different management key and chain, and must fail
    machine.fail(f"mind-the-gap {identity} -k other {piv} check --pin 471120 {card}")

    # The card-level half of the destructive suite, against the same card: it provisions
    # its own identity, then has the card sign in 9A, 9C and 9E under their pin policies
    # and agree in 9D, and compares every result with the same computation off the card.
    # Touch goes through trussed's user-presence request, which the virtual platform
    # grants; the serial is the app's fallback. The entry point is ignored for `cargo
    # test`, where it would need a real token, so it is named here explicitly.
    machine.succeed(
        "MTG_HARDWARE_TEST_SERIAL=5437251 piv-suite --ignored --exact "
        "provision_and_verify_${algorithm}_card --nocapture > /tmp/suite.log 2>&1"
    )
    machine.succeed("grep -q 'test result: ok. 1 passed' /tmp/suite.log")
  '';
}
