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

    # Test that bash completion is functional
    machine.succeed("bash -c 'source ${pkgs.bash-completion}/share/bash-completion/bash_completion; _comp_load mind-the-gap && complete -p mind-the-gap'")

    # Test that fish completion is functional
    machine.succeed("fish -c 'complete -c mind-the-gap'")

    # Test that zsh completion is functional
    machine.succeed("zsh -c 'compctl -p mind-the-gap'")
  '';
}
