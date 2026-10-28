# Provision CanoKey, emulated by QEMU, as a third PIV and OpenPGP card.
#
# CanoKey's applets (canokey-core) are C on mbed TLS, written apart from trussed and from
# Gnuk, so its PIV is the first one here that is not piv-authenticator. QEMU builds the
# firmware in as a USB device of the VM itself: the guest's kernel enumerates it, and pcscd
# reaches its CCID interface through libccid, which knows its USB id. It sits on a UHCI
# controller of its own on purpose: behind xHCI, QEMU hands a whole reply over in one
# transfer, and when the CCID message fills its last 64-byte packet, the zero-length packet
# the key sends after it is left for the next command to read, which libccid takes for an
# empty reply. UHCI takes the reply packet by packet, so the zero-length one ends the reply
# it belongs to.
#
# CanoKey takes every algorithm mind-the-gap derives, so nothing is refused up front, but it
# answers some requests differently from a YubiKey, and the check runs around those:
#
# - PIV reports firmware 5.7.0 yet takes a triple DES management key only, and no touch
#   requirement for management access. `init` falls back from AES-256 to triple DES, which
#   the command line run asserts; the suite is told to expect triple DES.
# - PIV has no msroots object (its write answers 6A82). `upload` warns and leaves it out,
#   which the command line run asserts once; everything else runs without it.
# - PIV has no key history object either, so a key kept in a retired slot cannot be
#   counted; the suite's in-place tests, which keep one, stay out.
# - PIV computes an imported X25519 key without clamping it, where RFC 7748 has every
#   implementation clamp before use. mind-the-gap imports X25519 keys clamped, which is the
#   same key with the same public half, so Curve25519 runs like every other algorithm.
# - OpenPGP keeps no private-use data objects (0102 holds CanoKey's touch cache time), no
#   KDF data object and no cached touch.
# - Under QEMU the key never asks for a touch, as if it were held to an NFC reader: the
#   policies are written and read back, but not enforced, so the suites run touch-free.
{
  pkgs,
  piv-suite,
  pgp-suite,
  ...
}:

{
  name = "mind-the-canokey";

  # QEMU with the CanoKey device built in, as nixpkgs' own FIDO2 test uses it
  qemu.package = pkgs.qemu_test.override { canokeySupport = true; };

  nodes.machine =
    { self, pkgs, ... }:
    {
      # Provide mind-the-gap derivation via overlay
      nixpkgs.overlays = [ self.overlays.default ];

      environment.systemPackages = [
        pkgs.mind-the-gap
        piv-suite
        pgp-suite
        # scriptor, to give the key a serial through its admin applet
        pkgs.pcsc-tools
      ];

      services.pcscd.enable = true;

      # The key keeps its flash in a file in the machine's state directory, which every run
      # starts without, so the key is fabricated afresh
      virtualisation.qemu.options = [
        "-device piix3-usb-uhci,id=uhci"
        "-device canokey,bus=uhci.0,file=canokey"
      ];
    };

  testScript = ''
    start_all()

    machine.wait_for_unit("multi-user.target")
    machine.systemctl("start pcscd.service")
    machine.wait_for_unit("pcscd.service")

    # Written to a file rather than piped: under pipefail an early-exiting grep -q would
    # fail the pipeline even though the card is there
    machine.wait_until_succeeds(
        "mind-the-gap list > /tmp/list && grep -q 'PIV card 0$' /tmp/list", timeout=60
    )

    # A fabricated key has serial 0, which a real one never ships with. The admin applet
    # writes one once, under its factory pin: 0x5EED5EED, which is PIV serial 1592614637
    # and OpenPGP card F1D0:5EED5EED
    machine.succeed(
        "printf '00 A4 04 00 05 F0 00 00 00 00\\n00 20 00 00 06 31 32 33 34 35 36\\n"
        "00 30 00 00 04 5E ED 5E ED\\n' | scriptor > /tmp/serial"
    )
    machine.succeed("test $(grep -c '^< 90 00' /tmp/serial) = 3")
    machine.succeed("mind-the-gap list > /tmp/list && grep -q 'PIV card 1592614637' /tmp/list")
    machine.succeed("grep -q 'OpenPGP card F1D0:5EED5EED' /tmp/list")

    # A fixed test mnemonic, never a real one: this seed is in the repository
    seed = (
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon art"
    )
    # The card seed's commands take the seed alone, the key seed's the identity's names too
    secret = f"-s '{seed}'"
    identity = f"{secret} -n 'Cano Test'"
    options = "--app piv"
    # What the card writes and compares: no msroots, and no touch it would not ask for
    fit = "--no-msroots --policy never-touch"
    card = "-c 1592614637"

    # PIV, as in virtual-piv: initialize and provision, read back byte for byte without
    # warnings, converge on a second upload, refuse a wrong subkey id. The management key
    # is left to `init`, which tries AES-256 for the firmware the key reports and settles
    # on triple DES when the key refuses it
    machine.succeed(
        f"mind-the-gap init {secret} {options} {fit} --pin 471120 --yes {card} 2> /tmp/init.log"
    )
    machine.succeed("grep -q 'refused an Aes256 management key' /tmp/init.log")
    machine.succeed(f"mind-the-gap upload {identity} {options} {fit} --yes {card}")
    machine.succeed(f"mind-the-gap publish {identity} {options} --to /tmp/chain.pem")
    machine.succeed("grep -q 'BEGIN CERTIFICATE' /tmp/chain.pem")
    machine.succeed(
        f"mind-the-gap check {identity} {options} {fit} --pin 471120 {card} 2> /tmp/check.log"
    )
    machine.fail("grep -Eq 'Policy mismatch|WARN.*msroots' /tmp/check.log")
    machine.succeed(f"mind-the-gap upload {identity} {options} {fit} --dry-run {card} > /tmp/again")
    machine.succeed("grep -q 'nothing to change' /tmp/again")
    machine.succeed(f"mind-the-gap list {secret} --app piv > /tmp/owned")
    machine.succeed("grep -q '^ *initialized by this card seed' /tmp/owned")
    machine.fail(f"mind-the-gap check {identity} -k other {options} {fit} --pin 471120 {card}")

    # With msroots asked for, the card refuses the object: the upload says so and names the
    # way out, rather than failing after the keys are written
    machine.succeed(
        f"mind-the-gap upload {identity} {options} --policy never-touch --yes {card} "
        "2> /tmp/msroots.log"
    )
    machine.succeed("grep -q 'refused the msroots object' /tmp/msroots.log")
    machine.succeed("grep -q -- '--no-msroots' /tmp/msroots.log")

    # Curve25519 through the command line too: the X25519 key goes on clamped and reads back
    # as the one certified
    curve25519 = f"{options} {fit} --algorithm curve25519"
    machine.succeed(f"mind-the-gap init {secret} {curve25519} --pin 471120 --yes {card}")
    machine.succeed(f"mind-the-gap upload {identity} {curve25519} --yes {card}")
    machine.succeed(f"mind-the-gap check {identity} {curve25519} --pin 471120 {card}")

    # The card-level half of the destructive suite on every other algorithm: the card signs
    # in 9A, 9C and 9E and agrees or decrypts in 9D, each result compared with the same
    # computation off the card. Then its user pin changed, reset with the derived puk, and
    # the card wiped
    suite = (
        "MTG_HARDWARE_TEST_SERIAL=1592614637 MTG_HARDWARE_TEST_TOUCH=never "
        "MTG_HARDWARE_TEST_MSROOTS=off MTG_HARDWARE_TEST_MANAGEMENT_ALGORITHM=tdes piv-suite"
    )
    for test in [
        "provision_and_verify_p256_card",
        "provision_and_verify_curve25519_card",
        "provision_and_verify_p384_card",
        "provision_and_verify_rsa2048_card",
        "provision_and_verify_rsa3072_card",
        "provision_and_verify_rsa4096_card",
        "change_user_pin",
    ]:
        machine.succeed(
            f"{suite} --ignored --exact {test} --nocapture > /tmp/suite.log 2>&1 "
            "|| { cat /tmp/suite.log; exit 1; }"
        )
        machine.succeed("grep -q 'test result: ok. 1 passed' /tmp/suite.log")

    # OpenPGP, as in virtual-pgp: provisioned and checked through the command line
    identity = f"{secret} -n 'Cano Test' -m cano@example.com"
    options = "--app pgp"
    card = "-c F1D0:5EED5EED"
    machine.succeed(f"mind-the-gap init {secret} {options} --pin 471120 --yes {card}")
    machine.succeed(f"mind-the-gap upload {identity} {options} --yes {card}")
    machine.succeed(f"mind-the-gap publish {identity} {options} --to /tmp/cert.asc")
    machine.succeed("grep -q 'BEGIN PGP PUBLIC KEY BLOCK' /tmp/cert.asc")
    machine.succeed(
        f"mind-the-gap check {identity} {options} --pin 471120 {card} > /tmp/pgp-check 2>&1"
    )
    # CanoKey has no private-use data objects, and answers for 0102 with its touch cache
    # time; read as an identifier, that made the card a stranger's. It holds this key seed's
    # keys and cannot say who administers it
    machine.succeed("grep -q 'holds keys of this seed, administrator unknown' /tmp/pgp-check")
    machine.fail(f"mind-the-gap check {identity} -k other {options} {card}")

    # Then the OpenPGP suite on every algorithm, gpg end to end included; and uploaded to
    # again, rotated, its user pin changed, blocked and reset, and wiped
    machine.succeed(
        "MTG_HARDWARE_TEST_CARD=F1D0:5EED5EED pgp-suite --exact "
        "provision_and_verify_card provision_and_verify_p256_card provision_and_verify_rsa_cards "
        "--nocapture > /tmp/pgp-suite.log 2>&1 || { cat /tmp/pgp-suite.log; exit 1; }"
    )
    machine.succeed("grep -q 'test result: ok. 3 passed' /tmp/pgp-suite.log")
    machine.succeed(
        "MTG_HARDWARE_TEST_CARD=F1D0:5EED5EED pgp-suite --ignored --exact "
        "upload_in_place rotate_in_place change_user_pin "
        "--nocapture > /tmp/pgp-upload.log 2>&1 || { cat /tmp/pgp-upload.log; exit 1; }"
    )
    machine.succeed("grep -q 'test result: ok. 3 passed' /tmp/pgp-upload.log")
  '';
}
