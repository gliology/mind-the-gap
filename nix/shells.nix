# The development shells: the default one for working on the crate, and the one the
# mark's asset exporter runs in
{ pkgs, toolchain }:

{
  default = pkgs.mkShell {
    nativeBuildInputs =
      # Tools the integration tests shell out to. Without them the affected tests
      # report as ignored rather than silently passing, see build.rs.
      (with pkgs; [
        sequoia-sq
        gnupg
        openssl
      ])
      # Tools for the PIV hardware checklist and its automated end-use steps,
      # see docs/piv-hardware-tests.md
      ++ (with pkgs; [
        opensc
        yubikey-manager
        nss.tools
        openssh
        pkcs11-provider
      ])
      # Documentation site, `mdbook serve --open` from the repository root
      ++ (with pkgs; [ mdbook ])
      ++ (with pkgs; [
        cargo-deny
        cargo-machete
        typos
        nixfmt
        pkg-config
        rustPlatform.bindgenHook
      ])
      # The rust-toolchain.toml toolchain; rust-analyzer locates rust-src
      # through its own sysroot, so no RUST_SRC_PATH is needed
      ++ [ toolchain ];

    buildInputs = with pkgs; [
      gmp
      nettle
      pcsclite
    ];

    # Module paths for the PKCS#11 steps of the hardware suite and the manual
    # checklist: the OpenSC module that talks to the card, and OpenSSL's pkcs11
    # provider that lets `openssl s_client`/`cms` use keys living on it
    PKCS11_MODULE = "${pkgs.opensc}/lib/opensc-pkcs11.so";
    OPENSSL_PKCS11_PROVIDER = "${pkgs.pkcs11-provider}/lib/ossl-modules/pkcs11.so";

    # Expose shared libraries so `cargo test` can load them at runtime
    shellHook = with pkgs; ''
      export LD_LIBRARY_PATH=${
        lib.makeLibraryPath [
          gmp
          nettle
          pcsclite
        ]
      }:$LD_LIBRARY_PATH
    '';
  };

  # Everything assets/export.py needs to regenerate the mark: shaping and
  # outline tracing (harfbuzz + fontTools), rasterising (resvg), compression
  # (oxipng) and the ico assembly (imagemagick). The word font is commercial
  # and not packaged: point MTG_FONT at it when running the exporter.
  assets = pkgs.mkShell {
    nativeBuildInputs = with pkgs; [
      (python3.withPackages (p: [
        p.fonttools
        p.uharfbuzz
      ]))
      resvg
      oxipng
      imagemagick
    ];
  };
}
