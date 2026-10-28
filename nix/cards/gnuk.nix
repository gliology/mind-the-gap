# Gnuk's GNU/Linux emulation: the token firmware compiled for the host, serving itself as
# a USB device over USB/IP on port 3240, with its flash kept in a file
{ pkgs, gnuk }:

pkgs.stdenv.mkDerivation {
  pname = "gnuk-usbip";
  version = "2.2";
  src = gnuk;

  # configure and its helper scripts are bash scripts with a /bin/bash shebang
  nativeBuildInputs = [
    pkgs.bash
    pkgs.makeWrapper
  ];

  # Life cycle management, so mind-the-gap can factory-reset the applet as on any card.
  # The KDF data object stays required, as in a stock build: no key import before `init`
  # has set it up
  configurePhase = ''
    runHook preConfigure
    cd src
    bash ./configure --target=GNU_LINUX --enable-factory-reset
    runHook postConfigure
  '';

  enableParallelBuilding = true;

  installPhase = ''
    runHook preInstall
    install -D build/gnuk $out/bin/gnuk
    makeWrapper ${pkgs.python3.interpreter} $out/bin/gnuk-with-button \
      --add-flags "${./gnuk-button.py} $out/bin/gnuk"
    runHook postInstall
  '';
}
