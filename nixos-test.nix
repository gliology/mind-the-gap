# NixOS test configuration
{ pkgs, ... }:

{
  name = "mind-the-test";

  nodes.machine = { self, pkgs, ... }: {
    # Install additional shells to check completions
    environment.systemPackages = with pkgs; [ fish zsh ];

    # Link additional completion files
    environment.pathsToLink = [ "/share/fish" "/share/zsh" ];

    # Provide mind-the-gap derivation via overlay
    nixpkgs.overlays = [ self.overlays.default ];

    # Import the same live system configuration to ensure consistency
    imports = [ ./live-system.nix ];
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

    # The air gap is enforced by configuration: no DHCP client may be running, and no
    # downloader may be on board
    machine.fail("systemctl is-active dhcpcd")
    machine.fail("command -v wget")

    # The nftables air gap holds: input, output and forward all drop by default, so even a
    # deliberately configured interface moves nothing
    policies = machine.succeed("nft list table inet airgap | grep -c 'policy drop'")
    assert policies.strip() == "3", f"expected 3 drop policies, got {policies.strip()}"

    # The module lock holds after boot; the tethering drivers are blacklisted besides
    machine.fail("modprobe cdc_ether")

    # And prove it end to end: give the test VM's NIC an address by hand, the way anyone
    # with console access would, and check that not a single packet leaves
    machine.succeed(
        "nic=$(ip -o link show | awk -F ': ' '$2 != \"lo\" { print $2; exit }');"
        " test -n \"$nic\" && ip addr add 10.0.2.15/24 dev $nic && ip link set $nic up"
    )
    machine.fail("ping -c 1 -W 2 10.0.2.2")

    # Test that bash completion is functional
    machine.succeed("bash -c 'source ${pkgs.bash-completion}/share/bash-completion/bash_completion; _comp_load mind-the-gap && complete -p mind-the-gap'")

    # Test that fish completion is functional
    machine.succeed("fish -c 'complete -c mind-the-gap'")

    # Test that zsh completion is functional
    machine.succeed("zsh -c 'compctl -p mind-the-gap'")

    # The point of the live image is deriving keys on an air-gapped machine, so check that it
    # actually can. A fixed test mnemonic, never a real one: this seed is in the repository.
    seed = (
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon art"
    )
    identity = f"-s '{seed}' -n 'Test User' -m test@example.com"

    # An OpenPGP certificate, which has to be armored and parseable
    machine.succeed(f"mind-the-gap {identity} pgp -d 2026-01-01 certify --kind full -o /tmp/cert.asc")
    machine.succeed("grep -q 'BEGIN PGP PUBLIC KEY BLOCK' /tmp/cert.asc")

    # A PIV chain, which has to carry a leaf per slot plus the root authority
    machine.succeed(f"mind-the-gap {identity} piv -d 2026-01-01 certify --kind chain -o /tmp/chain.pem")
    certs = machine.succeed("grep -c 'BEGIN CERTIFICATE' /tmp/chain.pem")
    assert certs.strip() == "5", f"expected four slot certificates and a root, got {certs.strip()}"

    # Derivation is deterministic, which is what makes a lost card replaceable
    machine.succeed(f"mind-the-gap {identity} piv -d 2026-01-01 certify --kind chain -o /tmp/again.pem")
    machine.succeed("cmp /tmp/chain.pem /tmp/again.pem")
  '';
}
