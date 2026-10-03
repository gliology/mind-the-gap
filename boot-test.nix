# Boot the real iso in qemu, over both firmware paths.
#
# The nixos vm test boots its kernel directly and skips the bootloader entirely, so it can
# never catch the one regression that historically forced the nixpkgs pin: an iso that
# builds but does not boot. These checks take the actual image through grub (bios) and
# through OVMF (uefi) all the way to the multi-user target, on an iso variant that differs
# from the shipped one only by carrying the test driver's backdoor console.
#
# Modeled on nixpkgs' own nixos/tests/boot.nix.
{ pkgs, nixos-lib, iso }:

let
  lib = pkgs.lib;
  qemu-common = import (pkgs.path + "/nixos/lib/qemu-common.nix") {
    inherit lib;
    inherit (pkgs) stdenv;
  };

  makeBootTest =
    name:
    { uefi ? false }:
    let
      flags = [
        "-m"
        "2048"
        "-cdrom"
        "${iso}/iso/${iso.isoName}"
      ]
      ++ lib.optionals uefi [
        "-drive"
        "if=pflash,format=raw,unit=0,readonly=on,file=${pkgs.OVMF.firmware}"
        "-drive"
        "if=pflash,format=raw,unit=1,readonly=on,file=${pkgs.OVMF.variables}"
      ];

      startCommand = "${qemu-common.qemuBinary pkgs.qemu_test} " + lib.concatStringsSep " " flags;
    in
    (nixos-lib.runTest {
      name = "mind-the-boot-${name}";
      hostPkgs = pkgs;
      nodes = { };

      # Booting the real iso through the bootloader is minutes under kvm but can take
      # hours under TCG emulation -- the arm runners have no kvm, and a local x86 machine
      # emulating the arm image is slower still. The driver's default of one hour kills
      # exactly those runs; the generous ceiling costs the fast paths nothing.
      globalTimeout = 4 * 60 * 60;
      testScript = ''
        machine = create_machine("${startCommand}")
        machine.start()

        # Reaching multi-user means the bootloader, stage 1, the squashfs and the
        # autologin all worked; the binary check proves the image is the right one.
        # The explicit timeout matches the global one: the default 900s dies under TCG.
        machine.wait_for_unit("multi-user.target", timeout=4 * 60 * 60)
        machine.succeed("mind-the-gap --help")

        machine.shutdown()
      '';
    }).config.result;
in
{
  boot-bios = makeBootTest "bios" { };
  boot-uefi = makeBootTest "uefi" { uefi = true; };
}
