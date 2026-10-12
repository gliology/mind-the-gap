{
  description = "Mind-the-Gap tools and live image";

  inputs = {
    # Pinned to a stable release; bumps are verified by the boot-bios/boot-uefi checks,
    # since an iso that builds but does not boot is exactly what a bump once broke
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

    # Provides the exact toolchain named in rust-toolchain.toml, newer than nixpkgs' rust
    fenix.url = "github:nix-community/fenix";
    fenix.inputs.nixpkgs.follows = "nixpkgs";

    # Cargo nix integration; deliberately has no nixpkgs input to follow
    crane.url = "github:ipetkov/crane";

    # Nitrokey's OpenPGP card implementation, run as the virtual card in the
    # virtual-pgp check; not a flake, we build its vpicc example with crane
    opcard = {
      url = "github:Nitrokey/opcard-rs";
      flake = false;
    };

    # The trussed PIV implementation (Nitrokey 3), run as the virtual card in the
    # virtual-piv checks and inside the simulated Nitrokey 3. The fork's mind-the-gap
    # branch is trussed-dev's main plus every pending PR, rebuilt by the generator in
    # ~/Gli.al/upstreaming/stacks; `nix flake update piv-authenticator` follows it
    piv-authenticator = {
      url = "github:FlorianFranzen/piv-authenticator/mind-the-gap";
      flake = false;
    };

    # Nitrokey's firmware, built as its USB/IP runner for the usbip-nk3 check: a whole
    # Nitrokey 3 as a host process, attached as a USB device; not a flake either
    nitrokey-3-firmware = {
      url = "github:Nitrokey/nitrokey-3-firmware";
      flake = false;
    };

    # The USB/IP device emulation the runner is built on: Sawchord/usbip-device's master
    # plus the transfer handling the kernel needs (#10), from the same generator
    usbip-device = {
      url = "github:FlorianFranzen/usbip-device/mind-the-gap";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      fenix,
      crane,
      opcard,
      piv-authenticator,
      nitrokey-3-firmware,
      usbip-device,
    }:
    let
      # List of all supported system architectures
      allSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      # Helper to generate attrset entry for each system
      forEachSystem = nixpkgs.lib.genAttrs allSystems;

      # Helper to generate nameable attrset entry for each system
      forEachSystem' = f: builtins.listToAttrs (map f allSystems);

      # Everything built for one system, assembled from the files under nix/
      perSystem = forEachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          nixos-lib = import (pkgs.path + "/nixos/lib") { };
          toolchain = import ./nix/toolchain.nix { inherit fenix system; };
          craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;
          rust = import ./nix/rust.nix { inherit pkgs craneLib; };
        in
        {
          inherit pkgs toolchain rust;
          docs = import ./nix/docs.nix {
            inherit pkgs;
            rustdoc = rust.doc;
          };
          live = import ./nix/live {
            inherit
              nixpkgs
              self
              system
              pkgs
              nixos-lib
              ;
          };
          cards = import ./nix/cards {
            inherit
              pkgs
              craneLib
              opcard
              piv-authenticator
              nitrokey-3-firmware
              usbip-device
              ;
          };
        }
      );
    in
    {
      # Checks: cargo fmt, clippy and tests, the source and documentation checks, the
      # live system environment, the iso boot path -- bios and uefi on x86, uefi on
      # aarch64, which has no bios to test -- and the cards provisioned end to end
      checks = forEachSystem (
        system:
        let
          inherit (perSystem.${system})
            pkgs
            rust
            docs
            live
            cards
            ;
        in
        rust.checks
        // import ./nix/lint.nix { inherit pkgs; }
        // docs.checks
        // live.checks
        // import ./nix/tests {
          inherit pkgs self cards;
          piv-suite = rust.pivSuite;
        }
      );

      # Shells used for development
      # `nix fmt`: nixfmt over the whole tree, through the treefmt wrapper nixpkgs ships
      # for exactly this, so it needs no file arguments
      formatter = forEachSystem (system: perSystem.${system}.pkgs.nixfmt-tree);

      devShells = forEachSystem (
        system: import ./nix/shells.nix { inherit (perSystem.${system}) pkgs toolchain; }
      );

      # Bootable iso with live system to run on air-gapped device
      nixosConfigurations = forEachSystem' (system: {
        name = "live-${system}";
        value = perSystem.${system}.live.configuration;
      });

      # Simple overlay to provide command line derivation
      overlays.default = final: prev: {
        inherit (self.packages.${prev.stdenv.hostPlatform.system}) mind-the-gap;
      };

      # Buildable outputs are:
      packages = forEachSystem (
        system:
        let
          inherit (perSystem.${system}) rust docs;
        in
        {
          # - Provide command line interface as default package
          default = self.packages.${system}.mind-the-gap;

          # - Provide live iso image as derivation
          iso = self.nixosConfigurations."live-${system}".config.system.build.isoImage;

          # - Render the documentation site from docs/, and bundle what the pages
          #   workflow publishes: the book at the root, the developer reference under
          #   /rustdoc
          inherit (docs) book site;

          # - Expose the developer reference built by crane
          rustdoc = rust.doc;

          # - Build the command line interface with crane
          mind-the-gap = rust.package;
        }
      );
    };
}
