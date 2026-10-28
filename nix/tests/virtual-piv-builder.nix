# Provision a *virtual* PIV card as the identity card of a build server.
#
# The same card and machine as virtual-piv.nix -- the trussed piv-authenticator behind
# vsmartcard's vpcd -- provisioned with the build server profile from
# docs/unattended-host.md: every key on P-384, pin once and touch never on the person
# slots, and management access without a touch. yubikit then reads back what the card
# reports, so the policies are seen on the card rather than taken from our own log.
#
# `managementKey` is what `--management-algorithm` asks `upload` for, or null for the automatic
# choice, which is AES-256 on this card. The triple DES variant is what a YubiKey 4 or a
# YubiKey 5 before 5.4 takes, forced onto a card that would take either.
{
  pkgs,
  piv-vpicc,
  managementKey ? null,
  ...
}:

let
  variant = if managementKey == null then "builder" else "builder-${managementKey}";

  # The management key the card has to report, as yubikit and as our upload log name it
  management =
    if managementKey == "tdes" then
      {
        yubikit = "TDES";
        log = "ThreeDes";
      }
    else
      {
        yubikit = "AES256";
        log = "Aes256";
      };

  # What the card reports: its PIV version, then through GET METADATA one line per slot plus
  # the management key, for the test script to grep. ykman's own `piv info` leaves the slot
  # policies out, and on a card without the YubiKey management and OTP applets it has to
  # guess at the device first; yubikit's PIV session alone does neither.
  pivPolicies =
    pkgs.writers.writePython3Bin "piv-policies"
      {
        # ykman is packaged as an application; this exposes its yubikit library too
        libraries = [ (pkgs.python3Packages.toPythonModule pkgs.yubikey-manager) ];
        flakeIgnore = [ "E501" ];
      }
      ''
        from ykman.pcsc import list_devices
        from yubikit.core.smartcard import SmartCardConnection
        from yubikit.piv import PivSession, SLOT

        (device,) = list_devices("Virtual PCD 00 00")
        with device.open_connection(SmartCardConnection) as connection:
            piv = PivSession(connection)
            print(f"VERSION {piv.version}")
            for slot in (SLOT.AUTHENTICATION, SLOT.SIGNATURE,
                         SLOT.KEY_MANAGEMENT, SLOT.CARD_AUTH):
                data = piv.get_slot_metadata(slot)
                print(f"{slot.name} {data.key_type.name} "
                      f"pin={data.pin_policy.name} touch={data.touch_policy.name}")
            data = piv.get_management_key_metadata()
            print(f"MANAGEMENT {data.key_type.name} touch={data.touch_policy.name} "
                  f"default={data.default_value}")
      '';
in
{
  name = "mind-the-virtual-piv-${variant}";

  nodes.machine = { self, pkgs, ... }: {
    # Provide mind-the-gap derivation via overlay
    nixpkgs.overlays = [ self.overlays.default ];

    environment.systemPackages = [
      pkgs.mind-the-gap
      pkgs.yubikey-manager
      pivPolicies
    ];

    # pcscd with vpcd as its only reader, as in virtual-piv.nix
    services.pcscd.enable = true;
    services.pcscd.readerConfig = ''
      FRIENDLYNAME "Virtual PCD"
      DEVICENAME   /dev/null:0x8C7B
      LIBPATH      ${pkgs.vsmartcard-vpcd}/var/lib/pcsc/drivers/serial/libifdvpcd.so
      CHANNELID    0x8C7B
    '';

    # The virtual card itself. Restart until it wins the race with pcscd's socket
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

    machine.wait_until_succeeds(
        "mind-the-gap list > /tmp/list && grep -q 'PIV card 5437251' /tmp/list",
        timeout=120,
    )

    # A fixed test mnemonic, never a real one: this seed is in the repository
    seed = (
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon art"
    )
    # The card seed's commands take the seed alone, the key seed's the identity too
    secret = f"-s '{seed}'"
    identity = f"{secret} -n 'pavlov builder'"
    builder = f"{identity} -k pavlov-1"
    options = (
        "--app piv --algorithm p384 --policy once-pin${
          if managementKey == null then "" else " --management-algorithm ${managementKey}"
        }"
    )
    # What publishing derives with, without the card's policy
    chain = "--app piv --algorithm p384"
    card = "-c 5437251"
    pin = "--pin 471120"

    # The build server profile, as docs/unattended-host.md provisions it: initialized on
    # the air-gapped side with management access left touch-free, then the host's keys
    machine.succeed(f"mind-the-gap init {secret} {options} {card} {pin} --yes 2> /tmp/init.log")
    machine.succeed("grep -q 'Management access stays touch-free' /tmp/init.log")
    machine.succeed("grep -q 'derived ${management.log} management key' /tmp/init.log")
    machine.succeed(f"mind-the-gap upload {builder} {options} {card} --yes")
    machine.succeed(f"mind-the-gap publish {builder} {chain} --to /tmp/chain.pem")
    machine.succeed("grep -q 'BEGIN CERTIFICATE' /tmp/chain.pem")

    # What the card holds, read back through yubikit rather than this tool: every slot P-384
    # with the pin once and no touch, 9E without either, and the management key in the
    # algorithm asked for, no touch and not the default
    policies = machine.succeed("piv-policies")
    print(policies)
    info = machine.succeed("ykman --reader 'Virtual PCD 00 00' piv info 2>&1")
    print(info)
    assert "PIV version:              6.6.6" in info, info
    assert "Management key algorithm: ${management.yubikit}" in info, info
    for line in (
        "AUTHENTICATION ECCP384 pin=ONCE touch=NEVER",
        "SIGNATURE ECCP384 pin=ONCE touch=NEVER",
        "KEY_MANAGEMENT ECCP384 pin=ONCE touch=NEVER",
        "CARD_AUTH ECCP384 pin=NEVER touch=NEVER",
        "MANAGEMENT ${management.yubikit} touch=NEVER default=False",
    ):
        assert line in policies, f"{line!r} missing from:\n{policies}"

    # check agrees, without a policy warning or a key it could not prove
    machine.succeed(f"mind-the-gap check {builder} {options} {card} {pin} 2> /tmp/check.log")
    machine.fail("grep -Eq 'Policy mismatch|WARN.*msroots|without --pin' /tmp/check.log")

    # Another host's subkey id derives other keys, and check names the slot that differs
    machine.succeed(
        f"! mind-the-gap check {identity} -k pavlov-2 {options} {card} {pin} "
        "2> /tmp/other-host.log"
    )
    machine.succeed(
        "grep -q 'Authentication slot: public key is not the derived one' /tmp/other-host.log"
    )

    # Initializing again converges on the same card
    machine.succeed(f"mind-the-gap init {secret} {options} {card} {pin} --yes")
    machine.succeed(f"mind-the-gap upload {builder} {options} {card} --yes")
    machine.succeed(f"mind-the-gap check {builder} {options} {card} {pin}")

    # Another card seed does not administer the card, and says so before trying a key
    machine.succeed(
        f"! mind-the-gap check {builder} -p typo {options} {card} {pin} 2> /tmp/other.log"
    )
    machine.succeed("grep -q 'not initialized by this card seed' /tmp/other.log")

    # The host rotates its own pin in plumbing mode, with the current pin and no seed, and
    # gets a report it can read
    machine.succeed(
        f"mind-the-gap pin --plumbing --app piv {card} --current-pin 471120 --pin 582231 "
        "> /tmp/pin.json"
    )
    machine.succeed("grep -q '\"ok\":true' /tmp/pin.json")
    machine.succeed(f"mind-the-gap check {builder} {options} {card} --pin 582231")
  '';
}
