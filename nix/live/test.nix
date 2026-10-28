# NixOS test configuration
{ pkgs, ... }:

{
  name = "mind-the-test";

  nodes.machine = { self, pkgs, ... }: {
    # Install additional shells to check completions. Zsh through its module, which is what
    # puts the vendor completion directory the package installs to on `fpath`.
    environment.systemPackages = with pkgs; [
      fish
    ];
    programs.zsh.enable = true;

    # Link additional completion files
    environment.pathsToLink = [
      "/share/fish"
      "/share/zsh"
    ];

    # Provide mind-the-gap derivation via overlay
    nixpkgs.overlays = [ self.overlays.default ];

    # Import the same live system configuration to ensure consistency
    imports = [ ./system.nix ];
  };

  testScript = ''
    start_all()

    # Wait for the machine to boot
    machine.wait_for_unit("multi-user.target")

    # Verify the binary exists
    machine.succeed("test -x /run/current-system/sw/bin/mind-the-gap")

    # Ensure all needed shared libraries are available
    machine.fail("ldd /run/current-system/sw/bin/mind-the-gap | grep -q 'not found'")

    # Test that binary works properly with basic commands
    machine.succeed("/run/current-system/sw/bin/mind-the-gap --help")

    # Test that the binary in PATH
    machine.succeed("mind-the-gap --help")

    # Test that it can print help without errors
    output = machine.succeed("mind-the-gap --help")
    assert "mind-the-gap" in output, "Help output doesn't contain expected content"

    # Test that man pages are accessible
    machine.succeed("man -P cat mind-the-gap")

    # The air gap is enforced by configuration: no DHCP client may be running. NixOS puts
    # curl on every system, so the gap rests on the firewall below rather than on the tools
    machine.fail("systemctl is-active dhcpcd")

    # The nftables air gap holds: input, output and forward all drop by default, so even a
    # deliberately configured interface moves nothing
    policies = machine.succeed("nft list table inet airgap | grep -c 'policy drop'")
    assert policies.strip() == "3", f"expected 3 drop policies, got {policies.strip()}"

    # The module lock holds after boot; the tethering drivers are blacklisted besides.
    # The lock service orders itself after multi-user.target and runs `udevadm settle`
    # first, so wait for it rather than race the settle -- kmscon's graphics bring-up
    # gives udev more to settle.
    machine.wait_for_unit("disable-kernel-module-loading.service")
    machine.fail("modprobe cdc_ether")

    # The radio and tethering stacks cannot arrive as another driver's dependency either:
    # modprobe refuses them by name, whichever module asks, and none is loaded
    for stack in ("bluetooth", "cfg80211", "mac80211", "usbnet"):
        machine.succeed(f"modprobe -n --show-depends {stack} | grep -q '^install .*false'")
        machine.fail(f"lsmod | grep -qw {stack}")

    # No shell keeps a history file for `forget` to miss
    machine.succeed("su - alice -c 'bash -ic \"test -z \\$HISTFILE\"'")

    # The kernel that booted keeps running, with the retired hardened profile's leftovers
    # and the interfaces nothing here uses switched off; the lid and the sleep states no
    # longer offer a dark screen with the seed still in RAM behind it
    machine.succeed("test $(sysctl -n kernel.kexec_load_disabled) = 1")
    machine.succeed("test $(sysctl -n kernel.io_uring_disabled) = 2")
    machine.succeed("test $(sysctl -n dev.tty.ldisc_autoload) = 0")
    machine.succeed("grep -qw randomize_kstack_offset=on /proc/cmdline")
    machine.succeed("grep -qw nohibernate /proc/cmdline")
    machine.succeed("grep -q '^AllowSuspend=no' /etc/systemd/sleep.conf")
    machine.succeed("grep -q '^HandleLidSwitch=ignore' /etc/systemd/logind.conf")
    machine.fail("systemctl suspend")

    # The memlock limit is gone for logins (a login shell prints the banner first, hence
    # the last line only) and for everything systemd spawns, so the tool's mlockall
    # actually takes
    machine.succeed("test $(su - alice -c 'ulimit -l' | tail -n1) = unlimited")
    machine.succeed("test $(systemctl show -p DefaultLimitMEMLOCK --value) = infinity")

    # debugfs=off and friends must not have left a failed unit behind. The one exception
    # is the test driver's own store registration, which fails because the image has no
    # nix daemon to register anything with
    machine.succeed(
        "test -z \"$(systemctl list-units --failed --plain --no-legend"
        " | grep -v register-nix-paths)\""
    )

    # And prove it end to end: give the test VM's NIC an address by hand, the way anyone
    # with console access would, and check that not a single packet leaves
    machine.succeed(
        "nic=$(ip -o link show | awk -F ': ' '$2 != \"lo\" { print $2; exit }');"
        " test -n \"$nic\" && ip addr add 10.0.2.15/24 dev $nic && ip link set $nic up"
    )
    machine.fail("ping -c 1 -W 2 10.0.2.2")

    # Test that bash completion is functional
    machine.succeed("bash -c 'source ${pkgs.bash-completion}/share/bash-completion/bash_completion; _comp_load mind-the-gap && complete -p mind-the-gap'")

    # Fish and zsh find the completions on their own and offer the subcommands. Asked of the
    # shells' completion machinery rather than by listing a definition, which either shell
    # accepts for a command it knows nothing about.
    machine.succeed("fish -c \"complete -C'mind-the-gap ' | grep -q upload\"")
    machine.succeed("zsh -c 'autoload -U compinit && compinit -u && (( $+_comps[mind-the-gap] ))'")

    # Each shell completes `run` with the recipes of the ceremony file it would read, the
    # user's, then the one a `ceremony` default in the user's config names: read from the
    # files, nothing run. zsh's recipe function is called with its completion system's
    # `_describe` standing in, which needs a terminal to show anything. grep reads every
    # candidate rather than stop at the first (`-q`): the driver runs with pipefail, and a
    # shell still writing to a closed pipe would fail the check at random
    def recipes_complete(recipe):
        machine.succeed(
            f"fish -c \"complete -C'mind-the-gap run '\" | grep -x '{recipe}' > /dev/null"
        )
        machine.succeed(
            "bash -c 'source ${pkgs.bash-completion}/share/bash-completion/bash_completion;"
            " _comp_load mind-the-gap; COMP_WORDS=(mind-the-gap run \"\"); COMP_CWORD=2;"
            " _mind__the__gap__with__recipes mind-the-gap \"\" run;"
            f" printf \"%s\\n\" \"''${{COMPREPLY[@]}}\"' | grep -x {recipe} > /dev/null"
        )
        machine.succeed(
            "zsh -c 'autoload -U compinit && compinit -u;"
            " source /run/current-system/sw/share/zsh/vendor-completions/_mind-the-gap;"
            " _describe() { print -l -- ''${(P)4} }; words=(run \"\"); CURRENT=2;"
            f" _mind-the-gap_recipes' | grep -x {recipe} > /dev/null"
        )

    machine.succeed(
        "mkdir -p /root/.config/mind-the-gap"
        " && printf 'device: card\\ncard:\\n    init\\n' > /root/.config/mind-the-gap/ceremony"
    )
    recipes_complete("card")
    machine.succeed(
        "printf 'team-card:\\n    init\\n' > /root/team.mtg"
        " && printf 'ceremony = \"/root/team.mtg\"\\n' > /root/.config/mind-the-gap/config.toml"
    )
    recipes_complete("team-card")
    machine.succeed("rm /root/.config/mind-the-gap/config.toml")

    # The point of the live image is deriving keys on an air-gapped machine, so check that it
    # actually can. A fixed test mnemonic, never a real one: this seed is in the repository.
    seed = (
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon art"
    )
    identity = f"-s '{seed}' -n 'Test User' -m test@example.com"

    # An OpenPGP certificate, which has to be armored and parseable
    machine.succeed(
        f"mind-the-gap publish {identity} --app pgp -d 2026-01-01 --to /tmp/cert.asc"
    )
    machine.succeed("grep -q 'BEGIN PGP PUBLIC KEY BLOCK' /tmp/cert.asc")

    # A PIV chain, which has to carry a leaf per key plus the root authority
    machine.succeed(
        f"mind-the-gap publish {identity} --app piv -d 2026-01-01 --to /tmp/chain.pem"
    )
    certs = machine.succeed("grep -c 'BEGIN CERTIFICATE' /tmp/chain.pem")
    assert certs.strip() == "4", f"expected three slot certificates and a root, got {certs.strip()}"

    # The memory lock takes: a piped session holds the seed and waits for input, long
    # enough to read its locked page count, and the debug log carries no refusal
    machine.succeed(
        f"(sleep 5 | mind-the-gap --log-level debug -s '{seed}' > /tmp/session.log 2>&1) &"
        " sleep 2; lck=$(for p in $(pgrep -P $!); do awk '/VmLck/ { print $2 }' /proc/$p/status; done"
        " | sort -n | tail -n1); wait; test \"$lck\" -gt 0"
    )
    machine.fail("grep -q 'Memory not locked' /tmp/session.log")

    # Derivation is deterministic, which is what makes a lost card replaceable
    machine.succeed(
        f"mind-the-gap publish {identity} --app piv -d 2026-01-01 --to /tmp/again.pem"
    )
    machine.succeed("cmp /tmp/chain.pem /tmp/again.pem")

    # Without a ceremony configured, the banner offers the interactive session
    machine.succeed("su - alice -c true | grep -q 'opens an interactive session'")
  '';
}
