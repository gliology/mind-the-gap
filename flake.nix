{
  description = "Mind-the-Gap tools and live image";

  inputs = {
    # Pinned, as current unstable iso with grub does not boot
    nixpkgs.url = "github:NixOS/nixpkgs/release-24.05";

    # Pinned nixpkgs rust is to currently to old
    fenix.url = "github:nix-community/fenix";
    fenix.inputs.nixpkgs.follows = "nixpkgs";

    # Cargo nix integration
    naersk.url = "github:nix-community/naersk";
    naersk.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, fenix, naersk }:
  let
    # List of all supported system architectures
    allSystems = [ "x86_64-linux" "aarch64-linux" ];

    # Helper to generate attrset entry for each system
    forEachSystem = nixpkgs.lib.genAttrs allSystems;

    # Helper to generate nameable attrset entry for each system
    forEachSystem' = f: builtins.listToAttrs (map f allSystems);

    # Provide newer version of rust
    toolchain = system: fenix.packages.${system}.stable;

    # Wrapper to turn config module to system config
    liveConfig = system: nixpkgs.lib.nixosSystem {
      inherit system;
      modules = [
        # Add mind-the-gap through a nixpkgs overlay
        { nixpkgs.overlays = [ (_: _: { inherit (self.packages.${system}) mind-the-gap; }) ]; }
        # Add live system config module
        (import ./live-system.nix)
      ];
    };
  in {
    # Shell to be used for development
    devShell = forEachSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        rust = toolchain system;
      in pkgs.mkShell {
        nativeBuildInputs = (with pkgs; [ pkg-config clang ])
          ++ (with rust; [ cargo rustc rust-analyzer rustfmt ]);

        buildInputs = with pkgs; [ nettle pcsclite ];

        RUST_SRC_PATH = "${rust.rust-src}/lib/rustlib/src/rust/library";

        LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
      }
    );

    # Bootable iso with live system to run on air-gapped device
    nixosConfigurations = forEachSystem' (system: {
      name = "live-${system}";
      value = liveConfig system;
    });

    # Buildable outputs
    packages = forEachSystem (system: {
      # - Provide command line interface as default package
      default = self.packages.${system}.mind-the-gap;

      # - Provide live iso image as derivation
      iso = self.nixosConfigurations."live-${system}".config.system.build.isoImage;

      # = Build the command line interface with naersk
      mind-the-gap = (naersk.lib.${system}.override {
        inherit (toolchain system) cargo rustc;
      }).buildPackage (
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in {
          src = ./.;

          nativeBuildInputs = with pkgs; [ pkg-config clang ];

          buildInputs = with pkgs; [ nettle pcsclite ];

          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

          # Man pages and completion support are provided by additional binary
          postInstall = ''
            $out/bin/mind-the-build $out
            rm $out/bin/mind-the-build
          '';
        });
    });
  };
}
