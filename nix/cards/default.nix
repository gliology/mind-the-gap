# The cards the VM checks provision, built for the host from Nitrokey's card
# applications. Upstream tracks no Cargo.lock for the two apps, and the firmware's
# own lock does not know our overrides, so each card's lock lives next to it.
{
  pkgs,
  craneLib,
  opcard,
  piv-authenticator,
  nitrokey-3-firmware,
  usbip-device,
}:

{
  opcard-vpicc = import ./opcard.nix { inherit pkgs craneLib opcard; };
  piv-vpicc = import ./piv-authenticator.nix { inherit pkgs craneLib piv-authenticator; };
  nk3-usbip = import ./nitrokey-3.nix {
    inherit
      pkgs
      craneLib
      piv-authenticator
      nitrokey-3-firmware
      usbip-device
      ;
  };
}
