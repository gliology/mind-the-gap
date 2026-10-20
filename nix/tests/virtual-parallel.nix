# Two hardware suites at once, on two virtual cards in one machine.
#
# A test host keeps several cards attached and runs a suite per card at the same time. What
# breaks that is a suite touching a card that is not its own: finding a card by serial or
# identifier asks every attached card who it is, an applet selected on another card throws
# off the suite working there, and gpg's scdaemon takes every reader. The suites guard
# against all three (they find their reader once under an exclusive lock, address their card
# by reader alone afterwards, and run gpg under the exclusive lock), and this check runs the
# PIV and the OpenPGP card-level suites side by side, so a regression shows here.
{
  pkgs,
  piv-vpicc,
  opcard-vpicc,
  piv-suite,
  pgp-suite,
  ...
}:

{
  name = "mind-the-virtual-parallel";

  nodes.machine = { self, pkgs, ... }: {
    nixpkgs.overlays = [ self.overlays.default ];

    environment.systemPackages = [
      pkgs.mind-the-gap
      piv-suite
      pgp-suite
    ];

    # One vpcd entry serves two readers, its slots, listening on 35963 and the next port
    services.pcscd.enable = true;
    services.pcscd.readerConfig = ''
      FRIENDLYNAME "Virtual PCD"
      DEVICENAME   /dev/null:0x8C7B
      LIBPATH      ${pkgs.vsmartcard-vpcd}/var/lib/pcsc/drivers/serial/libifdvpcd.so
      CHANNELID    0x8C7B
    '';

    # Both card examples connect to vpcd's default port and take no other. The OpenPGP card
    # runs as its own user, and its connections to the default port go to the second slot.
    users.users.opcard = {
      isSystemUser = true;
      group = "opcard";
    };
    users.groups.opcard = { };
    networking.firewall.extraCommands = ''
      iptables -t nat -A OUTPUT -p tcp -d 127.0.0.1 --dport 35963 \
        -m owner --uid-owner opcard -j REDIRECT --to-ports 35964
    '';

    # Restart until each wins the race with pcscd's socket activation: vpcd only listens
    # once the driver is loaded
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
    systemd.services.opcard = {
      wantedBy = [ "multi-user.target" ];
      requires = [ "pcscd.service" ];
      after = [
        "pcscd.service"
        "firewall.service"
      ];
      serviceConfig = {
        ExecStart = "${opcard-vpicc}/bin/opcard-vpicc";
        User = "opcard";
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

    # Both cards, each in its own reader
    machine.wait_until_succeeds(
        "mind-the-gap piv status > /tmp/piv-status && grep -q 'Serial: 5437251' /tmp/piv-status",
        timeout=120,
    )
    machine.wait_until_succeeds(
        "mind-the-gap pgp status > /tmp/pgp-status && grep -q 'Card 0000:00000000' /tmp/pgp-status",
        timeout=120,
    )

    # A card is addressable by its reader as well, here the OpenPGP one
    machine.succeed("grep -q \"Reader: Virtual PCD 00 01\" /tmp/pgp-status")

    # Both suites at the same time: the PIV card-level suite on two algorithms, and the
    # OpenPGP suite with its gpg step, which waits for the PIV suite to let go of the
    # readers and keeps it waiting while scdaemon runs. Each must pass as it does alone.
    machine.succeed(
        "MTG_HARDWARE_TEST_SERIAL=5437251 piv-suite --ignored --exact "
        "provision_and_verify_p256_card provision_and_verify_rsa2048_card --test-threads 1 "
        "--nocapture > /tmp/piv.log 2>&1 & piv=$!; "
        "MTG_HARDWARE_TEST_CARD=0000:00000000 pgp-suite --exact "
        "provision_and_verify_card provision_and_verify_p256_card --test-threads 1 "
        "--nocapture > /tmp/pgp.log 2>&1; pgp=$?; "
        "wait $piv; piv=$?; "
        "if [ $piv -ne 0 ] || [ $pgp -ne 0 ]; then cat /tmp/piv.log /tmp/pgp.log; exit 1; fi"
    )
    machine.succeed("grep -q 'test result: ok. 2 passed' /tmp/piv.log")
    machine.succeed("grep -q 'test result: ok. 2 passed' /tmp/pgp.log")
  '';
}
