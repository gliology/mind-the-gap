# Provision a *virtual* OpenPGP card end to end.
#
# The card is Nitrokey's opcard -- the Nitrokey 3's OpenPGP implementation -- running as a
# host process against vsmartcard's vpcd, so the whole PC/SC path (pcscd, the reader
# driver, APDUs, the card state machine) is exercised with no hardware and no USB. This is
# the automated half of what the destructive suites do to a real YubiKey: init, upload and
# check, driven through the real binary. Touch requests are granted unless the
# test refuses them through the file VPICC_USER_PRESENCE names, which the last step uses to
# prove the keys demand one. What it cannot cover is what the manual checklist exists for:
# real readers, a human finger and vendor extensions.
{
  pkgs,
  opcard-vpicc,
  pgp-suite,
  ...
}:

{
  name = "mind-the-virtual-pgp";

  nodes.machine = { self, pkgs, ... }: {
    # Provide mind-the-gap derivation via overlay
    nixpkgs.overlays = [ self.overlays.default ];

    environment.systemPackages = [
      pkgs.mind-the-gap
      pgp-suite
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
    systemd.services.opcard = {
      wantedBy = [ "multi-user.target" ];
      requires = [ "pcscd.service" ];
      after = [ "pcscd.service" ];
      # The card reads this file on every touch request: `deny` in it refuses, a missing
      # file grants, so only the touch test below ever sees a refusal
      environment.VPICC_USER_PRESENCE = "/run/vpicc-presence";
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

    # The virtual card announces itself with the FSIJ test identifier. Written to a file
    # rather than piped: under pipefail an early-exiting grep -q would fail the pipeline
    # even though the card is there.
    machine.wait_until_succeeds(
        "mind-the-gap list > /tmp/list && grep -q 'OpenPGP card 0000:00000000' /tmp/list",
        timeout=120,
    )

    # A fixed test mnemonic, never a real one: this seed is in the repository
    seed = (
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon art"
    )
    # The card seed's commands take the seed alone, the key seed's the identity's names too
    secret = f"-s '{seed}'"
    identity = f"{secret} -n 'Virt Test' -m virt@example.com"
    options = "--app pgp"
    card = "-c 0000:00000000"

    # Initialize and provision the virtual card without a pin, on purpose: opcard is reset
    # by recreating the VM, and the factory pins keep the test independent of pin handling.
    # A one-shot init warns about that instead of refusing.
    machine.succeed(f"mind-the-gap init {secret} {options} --yes {card}")
    machine.succeed(f"mind-the-gap upload {identity} {options} --yes {card}")
    machine.succeed(f"mind-the-gap publish {identity} {options} --to /tmp/cert.asc")
    machine.succeed("grep -q 'BEGIN PGP PUBLIC KEY BLOCK' /tmp/cert.asc")

    # The card must hold exactly the derived keys
    machine.succeed(f"mind-the-gap check {identity} {options} {card}")

    # Cardholder data goes on with an upload, the keys staying as they are
    machine.succeed(
        f"mind-the-gap upload {identity} {options} --yes {card} "
        "--lang en,de --url https://example.com/virt.asc"
    )

    # A mistyped password derives another card seed, which the card refuses before any pin
    # is spent; a wrong subkey id finds other keys under the right admin pin. As often as
    # the card has admin pin retries, and the derived admin pin still opens it afterwards.
    for _ in range(3):
        machine.fail(f"mind-the-gap check {identity} -p typo {options} {card}")
        machine.fail(f"mind-the-gap check {identity} -k other {options} {card}")
    machine.succeed(f"mind-the-gap upload {identity} {options} --yes {card} --lang de,en")

    # The same card takes a P-256 certificate: ECDSA signing and authentication keys and
    # an ECDH decryption key, which opcard imports on every slot. Another algorithm is a
    # new card from `init` on, so the Curve25519 keys above make way rather than clash.
    p256 = f"{identity} {options} --algorithm p256"
    machine.fail(f"mind-the-gap upload {p256} --yes {card}")
    machine.succeed(f"mind-the-gap init {secret} {options} --algorithm p256 --yes {card}")
    machine.succeed(f"mind-the-gap upload {p256} --yes {card}")
    machine.succeed(f"mind-the-gap check {p256} {card}")
    machine.fail(f"mind-the-gap check {identity} {options} {card}")

    # And RSA, at the smallest and the largest size: the 4096-bit import is the one that
    # needs extended length or chained APDUs to reach the card
    for algorithm in ["rsa2048", "rsa4096"]:
        rsa = f"{identity} {options} --algorithm {algorithm}"
        machine.succeed(f"mind-the-gap init {secret} {options} --yes {card}")
        machine.succeed(f"mind-the-gap upload {rsa} --yes {card}")
        machine.succeed(f"mind-the-gap check {rsa} {card}")
        machine.fail(f"mind-the-gap check {p256} {card}")

    # Then the OpenPGP half of the destructive suite against the same card, once per
    # algorithm: provisioning, the card read back independently, every key signing,
    # authenticating or decrypting with the result checked off the card, and gpg
    # signing and decrypting through it end to end
    machine.succeed(
        "MTG_HARDWARE_TEST_CARD=0000:00000000 pgp-suite --exact "
        "provision_and_verify_card provision_and_verify_p256_card provision_and_verify_rsa_cards "
        "--nocapture > /tmp/suite.log 2>&1 || { cat /tmp/suite.log; exit 1; }"
    )
    machine.succeed("grep -q 'test result: ok. 3 passed' /tmp/suite.log")

    # Touch is enforced, not only configured: with every touch refused the three keys
    # refuse to sign, authenticate and decrypt, and they work again once touches are granted
    machine.succeed(
        "MTG_HARDWARE_TEST_CARD=0000:00000000 MTG_TEST_USER_PRESENCE_FILE=/run/vpicc-presence "
        "pgp-suite --ignored --exact touch_is_enforced --nocapture > /tmp/touch.log 2>&1 "
        "|| { cat /tmp/touch.log; exit 1; }"
    )
    machine.succeed("grep -q 'test result: ok. 1 passed' /tmp/touch.log")

    # Uploaded to again, without a factory reset: another policy and cardholder data with
    # the keys untouched, and a team's decryption key from another key seed; then rotated to
    # a new generation, its user pin changed, blocked and reset under the admin pin, and the
    # card wiped
    machine.succeed(
        "MTG_HARDWARE_TEST_CARD=0000:00000000 "
        "pgp-suite --ignored --exact upload_in_place rotate_in_place change_user_pin "
          "--nocapture > /tmp/upload.log 2>&1 "
        "|| { cat /tmp/upload.log; exit 1; }"
    )
    machine.succeed("grep -q 'test result: ok. 3 passed' /tmp/upload.log")
  '';
}
