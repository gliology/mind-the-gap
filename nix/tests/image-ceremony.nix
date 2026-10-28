# An image with a ceremony and defaults configured through the NixOS module, run against a
# virtual PIV card.
#
# programs.mind-the-gap.{config,ceremony} write /etc/mind-the-gap/, read-only in the store.
# A bare `mind-the-gap` then runs the ceremony's first recipe: each step shown before it
# runs, dependencies first, the card initialized from the seed in the environment and the
# chain published. A dry run shows the steps and touches nothing, a recorded run keeps a
# transcript without a secret in it, and plumbing mode reports each step as JSON.
{
  pkgs,
  piv-vpicc,
  ...
}:

{
  name = "mind-the-image-ceremony";

  nodes.machine = { self, pkgs, ... }: {
    imports = [ ../module.nix ];
    nixpkgs.overlays = [ self.overlays.default ];

    programs.mind-the-gap = {
      enable = true;
      config = {
        name = "Ceremony Test";
        emails = [ "ceremony@example.com" ];
        app = "piv";
        # An applet's own default, which this PIV-only ceremony never reaches
        pgp.algorithm = "rsa2048";
      };
      ceremony = ''
        # A personal card: the card seed's credentials, then the key seed's keys
        card: init keys

        init:
            init --yes

        keys: init
            upload --yes
            publish --to /tmp/certs/

        # Shown only on request
        listing:
            list

        defaults:
            set
      '';
    };

    # pcscd with vpcd as its only reader, and the trussed PIV app behind it, as in
    # virtual-piv.nix
    services.pcscd.enable = true;
    services.pcscd.readerConfig = ''
      FRIENDLYNAME "Virtual PCD"
      DEVICENAME   /dev/null:0x8C7B
      LIBPATH      ${pkgs.vsmartcard-vpcd}/var/lib/pcsc/drivers/serial/libifdvpcd.so
      CHANNELID    0x8C7B
    '';
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

    # The module's files are store paths, which nothing on the machine can change
    for name in ("config.toml", "ceremony"):
        machine.succeed(f"readlink -f /etc/mind-the-gap/{name} | grep -q '^/nix/store/'")
    print(machine.succeed("cat /etc/mind-the-gap/config.toml"))

    # A fixed test mnemonic, never a real one: this seed is in the repository. It comes
    # from the environment, as a ceremony holds no secret
    seed = (
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon art"
    )
    env = f"MIND_THE_SEED='{seed}'"

    # The image's defaults are every command's, and show where they come from: the image's
    # file read, and each default behind its layer
    defaults = machine.succeed("mind-the-gap run defaults")
    listed = [" ".join(line.split()) for line in defaults.splitlines()]
    assert "image /etc/mind-the-gap/config.toml (read)" in listed, defaults
    assert "image name = Ceremony Test" in listed, defaults
    assert "image pgp.algorithm = rsa2048" in listed, defaults

    # A dry run of the first step shows it and writes nothing
    dry = machine.succeed(f"{env} mind-the-gap run init --dry-run 2>&1")
    print(dry)
    assert "[1/1] init: init --yes" in dry, dry
    assert "Initializing resets" in dry, dry
    machine.succeed(f"{env} mind-the-gap list > /tmp/before")
    machine.fail("grep -q '^ *initialized by this card seed' /tmp/before")

    # A bare invocation runs the first recipe, dependencies first, then carries on as a
    # session, here one with nothing more to read
    machine.succeed(f"{env} mind-the-gap < /dev/null 2> /tmp/ceremony.log")
    print(machine.succeed("cat /tmp/ceremony.log"))
    for step in ("[1/3] init: init --yes", "[2/3] keys: upload --yes", "[3/3] keys: publish"):
        machine.succeed(f"grep -qF '{step}' /tmp/ceremony.log")
    machine.succeed("grep -q 'BEGIN CERTIFICATE' /tmp/certs/piv-chain.pem")
    machine.succeed(f"{env} mind-the-gap list > /tmp/after")
    machine.succeed("grep -q '^ *initialized by this card seed' /tmp/after")
    machine.succeed(f"{env} mind-the-gap check --pin 123456 -c 5437251")

    # Run again as a dry run, the upload finds nothing to change and nothing is published
    machine.succeed("rm -r /tmp/certs")
    dry = machine.succeed(f"{env} mind-the-gap run keys --dry-run 2>&1")
    print(dry)
    assert "nothing to change" in dry, dry
    assert "not run in a dry run" in dry, dry
    machine.fail("test -e /tmp/certs")

    # A recorded run: the transcript names every step and its outcome, and holds no word
    # of the phrase
    machine.succeed(f"{env} mind-the-gap run --record /tmp/record")
    machine.succeed("grep -q 'step \\[1/3\\] init: init --yes' /tmp/record/ceremony-*.log")
    machine.succeed("grep -q 'ceremony finished' /tmp/record/ceremony-*.log")
    machine.fail("grep -q abandon /tmp/record/ceremony-*.log")

    # A named recipe, in plumbing mode: one JSON object per step on stdout
    machine.succeed(f"{env} mind-the-gap run listing --plumbing > /tmp/plumbing.json")
    print(machine.succeed("cat /tmp/plumbing.json"))
    # The listing comes as data: the card, whose card seed initialized it, and the key seed's
    # keys on it
    import json
    report = json.loads(machine.succeed("head -n1 /tmp/plumbing.json"))
    assert report["command"] == "list" and report["ok"], report
    piv = [a for card in report["cards"] for a in card["applets"] if a["applet"] == "PIV"]
    assert piv and piv[0]["card"] == "5437251", report
    assert piv[0]["owner"] == "initialized by this card seed", report
    assert any(key["ours"] for key in piv[0]["keys"]), report

    # A failing step stops the ceremony and names where: without a seed, nothing runs past
    # the first step that needs it
    machine.fail("mind-the-gap run keys 2> /tmp/failed.log")
    machine.succeed("grep -q 'Step 1 of the ceremony failed' /tmp/failed.log")
  '';
}
