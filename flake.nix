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

        # gnark DCAP circuit — prove and setup binaries
        gnarkSrc = pkgs.lib.cleanSourceWith {
          src = ./circuits/dcap-gnark;
          filter = path: type:
            # Include Go source, go.mod/sum, and vendor/
            (builtins.match ".*\\.go$" path != null) ||
            (builtins.match ".*/go\\.(mod|sum)$" path != null) ||
            (builtins.match ".*/vendor(/.*)?$" path != null) ||
            (type == "directory");
        };

        gnarkBinaries = pkgs.buildGoModule {
          pname = "gnark-dcap";
          version = "0.1.0";
          src = gnarkSrc;
          vendorHash = null; # uses committed vendor/
          subPackages = [ "cmd/prove" "cmd/setup" ];
          # Rename output binaries for clarity
          postInstall = ''
            mv $out/bin/prove $out/bin/gnark-prove
            mv $out/bin/setup $out/bin/gnark-setup
          '';
        };

        # Icicle v3.2.2 — Go wrapper CGO header files (not vendored by `go mod vendor`)
        icicleGnarkHeaders = pkgs.fetchFromGitHub {
          owner = "ingonyama-zk";
          repo = "icicle-gnark";
          rev = "v3.2.2";
          hash = "sha256-kbXwg1cF72flzpl1+20D+smYKgl7Aslbf1KSCi6ur34=";
        };

        # Icicle v3.2.0 — core shared libs (CPU) for CGO linking + runtime.
        # Libs placed at $out/lib/ (standard Nix path) so autoPatchelfHook resolves them.
        icicleCoreLibs = pkgs.stdenv.mkDerivation {
          name = "icicle-core-libs-3.2.0";
          dontUnpack = true;
          nativeBuildInputs = [ pkgs.gnutar pkgs.gzip pkgs.autoPatchelfHook ];
          buildInputs = [ pkgs.stdenv.cc.cc.lib ];
          installPhase = ''
            mkdir -p $out/lib
            tar -xzf ${pkgs.fetchurl {
              url = "https://github.com/ingonyama-zk/icicle/releases/download/v3.2.0/icicle_3_2_0-ubuntu22.tar.gz";
              hash = "sha256-dJRf72/qlMr6KfNdnVq6+DEif3O3t4LCMc33fs2sgfs=";
            }} -C $out
            mv $out/icicle/lib/*.so $out/lib/
            rm -rf $out/icicle
          '';
        };

        # Icicle v3.2.0 — CUDA backend plugins for GPU proving (loaded at runtime via dlopen)
        icicleCudaBackend = pkgs.stdenv.mkDerivation {
          name = "icicle-cuda-backend-3.2.0";
          dontUnpack = true;
          nativeBuildInputs = [ pkgs.gnutar pkgs.gzip pkgs.autoPatchelfHook ];
          buildInputs = [
            pkgs.stdenv.cc.cc.lib
            pkgs.cudaPackages.cuda_cudart.lib
            icicleCoreLibs # CUDA plugins link against core icicle libs (found at lib/)
          ];
          autoPatchelfIgnoreMissingDeps = [ "libcuda.so.*" "libnvidia-ml.so.*" ];
          installPhase = ''
            mkdir -p $out/lib
            tar -xzf ${pkgs.fetchurl {
              url = "https://github.com/ingonyama-zk/icicle/releases/download/v3.2.0/icicle_3_2_0-ubuntu22-cuda122.tar.gz";
              hash = "sha256-JH8LgXGae7jMK8IkPjYrBeVBOSxRfMKO3tOss7JUmMg=";
            }} -C $out
            mv $out/icicle/lib/backend $out/lib/backend
            rm -rf $out/icicle
          '';
        };

        # Icicle-enabled gnark prove binary (supports CPU fallback + GPU with -gpu flag).
        # Setup binary stays in gnarkBinaries (no icicle) to avoid CUDA device init on boot.
        gnarkProveIcicle = pkgs.buildGoModule {
          pname = "gnark-dcap-icicle";
          version = "0.1.0";
          src = gnarkSrc;
          vendorHash = null;
          subPackages = [ "cmd/prove" ];
          tags = [ "icicle" ];
          nativeBuildInputs = [ pkgs.autoPatchelfHook ];
          buildInputs = [ icicleCoreLibs pkgs.stdenv.cc.cc.lib ];
          CGO_LDFLAGS = "-L${icicleCoreLibs}/lib";
          preBuild = ''
            # Copy icicle-gnark Go wrapper CGO headers into vendor tree.
            # go mod vendor doesn't copy .h files from include/ subdirectories
            # because they don't contain .go files.
            local vendorBase="vendor/github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang"
            local srcBase="${icicleGnarkHeaders}/wrappers/golang"
            for reldir in \
              runtime \
              runtime/config_extension \
              curves/bn254 \
              curves/bn254/g2 \
              curves/bn254/msm \
              curves/bn254/ntt \
              curves/bn254/vecOps; do
              if [ -d "$srcBase/$reldir/include" ]; then
                mkdir -p "$vendorBase/$reldir/include"
                cp "$srcBase/$reldir/include/"*.h "$vendorBase/$reldir/include/"
              fi
            done
          '';
          postInstall = ''
            mv $out/bin/prove $out/bin/gnark-prove
          '';
        };

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
          echo "SP1_PROVER=$SP1_PROVER, GPU: $(ls /dev/nvidia* 2>/dev/null | wc -l) devices"

          # gnark proving key setup (one-time, ~2-3 min)
          GNARK_DATA_DIR="''${GNARK_DATA_DIR:-$HOME/gnark}"
          mkdir -p "$GNARK_DATA_DIR"
          if [ ! -f "$GNARK_DATA_DIR/pk.bin" ]; then
            echo "gnark: generating proving key (first run)..."
            "${gnarkBinaries}/bin/gnark-setup" -pk "$GNARK_DATA_DIR/pk.bin" -vk "$GNARK_DATA_DIR/vk.bin" && \
              echo "gnark: proving key generated" || \
              echo "gnark: setup failed (gnark-cpu proving will be unavailable)"
          else
            echo "gnark: proving key found at $GNARK_DATA_DIR/pk.bin"
          fi
          export GNARK_PROVE_BINARY="${gnarkBinaries}/bin/gnark-prove"
          export GNARK_PROVE_GPU_BINARY="${gnarkProveIcicle}/bin/gnark-prove"
          export GNARK_PK_PATH="$GNARK_DATA_DIR/pk.bin"

          exec "${oauth3}/bin/oauth3"
        '';

        # Docker image - fully reproducible
        dockerImage = pkgs.dockerTools.buildLayeredImage {
          name = "oauth3";
          tag = "nix";

          contents = with pkgs; [
            oauth3
            gnarkBinaries
            gnarkProveIcicle
            sp1Artifacts
            icicleCoreLibs
            icicleCudaBackend
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
              # sp1-gpu-server requires CUDA_VISIBLE_DEVICES as a single numeric device ID
              "CUDA_VISIBLE_DEVICES=0"
              # Icicle CUDA backend plugins for gnark GPU proving
              "ICICLE_BACKEND_INSTALL_DIR=${icicleCudaBackend}/lib/backend"
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
