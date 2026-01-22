{
  description = "oauth3 - Reproducible Rust build with Nix";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        # Use Rust 1.92 to match rust-toolchain.toml
        rustToolchain = pkgs.rust-bin.stable."1.92.0".default.override {
          extensions = [ "rust-src" ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Build-time dependencies
        nativeBuildInputs = with pkgs; [
          pkg-config
          rustToolchain
        ];

        # Runtime dependencies
        buildInputs = with pkgs; [
          postgresql
          openssl
        ];

        # Filter source to include views directory
        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            (craneLib.filterCargoSources path type) ||
            (builtins.match ".*views/.*\\.html$" path != null) ||
            (builtins.match ".*/migrations/.*" path != null) ||
            (builtins.match ".*/diesel\\.toml$" path != null);
        };

        # Common args for crane
        commonArgs = {
          inherit src;
          strictDeps = true;
          inherit nativeBuildInputs buildInputs;

          # Postgres-only build to match production
          cargoExtraArgs = "--no-default-features --features pg";

          # Don't run tests during build
          doCheck = false;

          # Ensure reproducible builds
          CARGO_INCREMENTAL = "0";
          CARGO_PROFILE_RELEASE_LTO = "true";
          CARGO_PROFILE_RELEASE_CODEGEN_UNITS = "1";
        };

        # Build dependencies first (for caching)
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # Build the actual application
        oauth3 = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;

          # Install migrations and diesel.toml alongside binary
          postInstall = ''
            mkdir -p $out/share/oauth3
            cp -r ${src}/migrations $out/share/oauth3/
            cp ${src}/diesel.toml $out/share/oauth3/
          '';
        });

        # Docker image - fully reproducible
        dockerImage = pkgs.dockerTools.buildLayeredImage {
          name = "oauth3";
          tag = "nix";

          contents = with pkgs; [
            oauth3
            cacert
            postgresql
            bashInteractive
            coreutils
          ];

          config = {
            Cmd = [ "${oauth3}/bin/oauth3" ];
            Env = [
              "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
            ];
            ExposedPorts = {
              "8080/tcp" = {};
            };
            WorkingDir = "${oauth3}/share/oauth3";
          };

          # Reproducibility - fixed timestamp
          created = "1970-01-01T00:00:01Z";
          maxLayers = 100;
        };

      in
      {
        packages = {
          default = oauth3;
          inherit oauth3 dockerImage;
        };

        apps.default = {
          type = "app";
          program = "${oauth3}/bin/oauth3";
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ oauth3 ];
          packages = with pkgs; [
            rustToolchain
            rust-analyzer
            diesel-cli
            postgresql
          ];
        };
      }
    );
}
