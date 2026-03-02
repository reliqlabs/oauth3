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
          # CUDA runtime (libcudart.so) needed for SP1 GPU proving
          config.allowUnfree = true;
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
          # SP1 Groth16 native proving (gnark FFI via cgo)
          go
          llvmPackages.libclang
          # sp1-prover-types builds protobuf definitions
          protobuf
        ];

        # Runtime dependencies
        buildInputs = with pkgs; [
          postgresql
          openssl
        ];

        # Filter source to include views, migrations, and SP1 guest ELF
        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            (craneLib.filterCargoSources path type) ||
            (builtins.match ".*views/.*\\.html$" path != null) ||
            (builtins.match ".*/migrations/.*" path != null) ||
            (builtins.match ".*/diesel\\.toml$" path != null) ||
            (builtins.match ".*/zkdcap/elf/.*" path != null);
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

          # bindgen needs LIBCLANG_PATH for SP1 native-gnark FFI
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

          # bindgen needs clang resource dir for stddef.h etc
          BINDGEN_EXTRA_CLANG_ARGS = "-isystem ${pkgs.llvmPackages.libclang.lib}/lib/clang/${pkgs.lib.versions.major pkgs.llvmPackages.libclang.version}/include";

          # Go needs writable cache dirs (sp1-recursion-gnark-ffi builds Go code)
          GOCACHE = "/tmp/go-cache";
          GOPATH = "/tmp/go-path";

          # Reproducible builds with CI-friendly resource usage
          CARGO_INCREMENTAL = "0";
          CARGO_PROFILE_RELEASE_LTO = "thin";
          CARGO_PROFILE_RELEASE_CODEGEN_UNITS = "16";
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

            # Make files writable so crane's postInstall can strip references
            chmod -R u+w $out/share/oauth3
          '';
        });

        # SP1 CUDA proving artifacts (x86_64-linux only, bundled into Docker image)
        sp1GpuServerTarball = pkgs.fetchurl {
          url = "https://github.com/succinctlabs/sp1/releases/download/v6.0.2/sp1_gpu_server_v6.0.2_x86_64.tar.gz";
          hash = "sha256-KrrwWTfOSl8Ct0okDxTk68hSIOYrciGybPUyf1N7/8c=";
        };

        groth16ArtifactsTarball = pkgs.fetchurl {
          url = "https://sp1-circuits.s3-us-east-2.amazonaws.com/v6.0.0-groth16.tar.gz";
          hash = "sha256-AMDTmxwf3IyKc86NTpxQyVVUs9m//FHL8+TC7Lg3D8M=";
        };

        # Pre-extract SP1 artifacts into a derivation at /sp1/
        sp1Artifacts = pkgs.stdenv.mkDerivation {
          name = "sp1-artifacts";
          dontUnpack = true;
          nativeBuildInputs = [ pkgs.gnutar pkgs.gzip pkgs.autoPatchelfHook ];
          buildInputs = [
            pkgs.stdenv.cc.cc.lib # libstdc++ for sp1-gpu-server
            pkgs.cudaPackages.cuda_cudart.lib # libcudart.so for CUDA runtime
          ];
          # libcuda.so + libnvidia-ml.so provided at runtime by nvidia-container-toolkit
          autoPatchelfIgnoreMissingDeps = [ "libcuda.so.*" "libnvidia-ml.so.*" ];
          installPhase = ''
            mkdir -p $out/sp1/bin
            mkdir -p $out/sp1/circuits/groth16/v6.0.0

            # sp1-gpu-server binary (tarball contains bare "sp1-gpu-server")
            tar -xzf ${sp1GpuServerTarball} -C $out/sp1/bin
            chmod +x $out/sp1/bin/sp1-gpu-server

            # Groth16 circuit artifacts (~8.5GB extracted)
            tar -xzf ${groth16ArtifactsTarball} -C $out/sp1/circuits/groth16/v6.0.0
          '';
        };

        # Wrapper: version shim so SP1 SDK skips re-download, delegates to real binary
        sp1GpuServerWrapper = pkgs.writeShellScriptBin "sp1-gpu-server" ''
          if [ "$1" = "--version" ]; then
            echo "6.0.2"
            exit 0
          fi
          # nvidia-container-toolkit mounts CUDA libs to /usr/lib64/ (Yocto host)
          export LD_LIBRARY_PATH="/usr/lib64:/usr/lib/x86_64-linux-gnu:''${LD_LIBRARY_PATH:-}"
          exec "${sp1Artifacts}/sp1/bin/sp1-gpu-server" "$@"
        '';

        oauth3Entrypoint = pkgs.writeShellScript "oauth3-entrypoint" ''
          mkdir -p "$HOME/.sp1/bin"
          ln -sf "${sp1GpuServerWrapper}/bin/sp1-gpu-server" "$HOME/.sp1/bin/sp1-gpu-server"
          # GPU diagnostics
          echo "GPU: $(ls /dev/nvidia* 2>/dev/null | wc -l) devices, LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
          echo "--- ldd sp1-gpu-server ---"
          LD_LIBRARY_PATH="/usr/lib64:/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH" ldd "${sp1Artifacts}/sp1/bin/sp1-gpu-server" 2>&1 | head -30
          echo "--- test sp1-gpu-server launch ---"
          timeout 5 "${sp1GpuServerWrapper}/bin/sp1-gpu-server" --help 2>&1 || echo "exit code: $?"
          echo "--- end diagnostics ---"
          exec "${oauth3}/bin/oauth3"
        '';

        # Docker image - fully reproducible
        dockerImage = pkgs.dockerTools.buildLayeredImage {
          name = "oauth3";
          tag = "nix";

          contents = with pkgs; [
            oauth3
            sp1Artifacts
            cacert
            postgresql
            bashInteractive
            coreutils
            gnutar
            gzip
            # glibc + libstdc++ needed at runtime for sp1-gpu-server (patched by autoPatchelfHook)
            stdenv.cc.cc.lib
          ];

          # nvidia-container-toolkit bind-mounts CUDA libs + binaries into these paths.
          # Must be real directories in the image root (not Nix store symlinks).
          # Yocto dstack uses /usr/lib64/, Debian uses /usr/lib/x86_64-linux-gnu/.
          extraCommands = ''
            mkdir -p usr/lib/x86_64-linux-gnu
            mkdir -p usr/lib64
            mkdir -p usr/bin
          '';

          config = {
            Cmd = [ oauth3Entrypoint ];
            Env = [
              "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
              "HOME=/tmp"
              # Point SP1 at pre-bundled Groth16 circuit artifacts (read-only is fine)
              "SP1_GROTH16_CIRCUIT_PATH=${sp1Artifacts}/sp1/circuits/groth16"
              # nvidia-container-toolkit mounts CUDA libs from host
              # Yocto-based dstack host uses /usr/lib64/, Debian uses /usr/lib/x86_64-linux-gnu/
              "LD_LIBRARY_PATH=/usr/lib64:/usr/lib/x86_64-linux-gnu"
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
            # SP1 Groth16 native proving (gnark FFI)
            go
            llvmPackages.libclang
          ];

          # bindgen needs LIBCLANG_PATH to find libclang
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
        };
      }
    );
}
