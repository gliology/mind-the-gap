{
  description = "Mind-the-Gap tools and live image";

  inputs = {
    naersk = {
      url = github:nix-community/naersk;
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, naersk }:
  let
    # List of all supported system architectures
    allSystems = [ "x86_64-linux" "aarch64-linux" ];

    # Helper to generate attrset entry for each system
    forEachSystem = nixpkgs.lib.genAttrs allSystems;

    # Helper to generate nameable attrset entry for each system
    forEachSystem' = f: builtins.listToAttrs (map f allSystems);

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
    devShell = forEachSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in pkgs.mkShell {
        nativeBuildInputs = with pkgs; [ cargo pkg-config clang ];

        buildInputs = [ pkgs.nettle ];

        LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
      }
    );

    nixosConfigurations = forEachSystem' (system: {
      name = "live-${system}";
      value = liveConfig system;
    });

    apps = forEachSystem (system: 
      let
        pkgs = self.packages.${system};
      in {
        mnemonic2pgp = {
          type = "app";
          program = "${pkgs.mind-the-gap}/bin/mnemonic2pgp";
        };
    });
    defaultApp = forEachSystem (system: self.apps.${system}.mnemonic2pgp);

    packages = forEachSystem (system: {
      # Provide iso derivation
      iso = self.nixosConfigurations."live-${system}".config.system.build.isoImage;

      # Build mind the gap with naersk
      mind-the-gap = naersk.lib.${system}.buildPackage (
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in {
          src = ./.;

          nativeBuildInputs = with pkgs; [ pkg-config clang ];
          buildInputs = [ pkgs.nettle ];

          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
        });
    });

    defaultPackage = forEachSystem (system: self.packages.${system}.mind-the-gap);
  };
}
