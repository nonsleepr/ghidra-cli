{
  description = "Ghidra CLI - Rust CLI for automating Ghidra reverse engineering tasks";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane = {
      url = "github:ipetkov/crane";
    };
  };

  outputs = { self, nixpkgs, rust-overlay, crane }:
    let
      ghidraVersion = nixpkgs.lib.removeSuffix "\n" (builtins.readFile ./ghidra-version);
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pkgsFor = system: import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };
      ghidraFor = pkgs: system:
        let
          # The upstream ZIP only supplies Linux x86_64 and Windows natives.
          # Build the native decompiler for Linux ARM and Apple Silicon.
          package = if system == "x86_64-linux" then pkgs.ghidra-bin else pkgs.ghidra;
        in assert package.version == ghidraVersion; package;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          lib = pkgs.lib;
          ghidra = ghidraFor pkgs system;
          rustToolchain = pkgs.rust-bin.stable.latest.default;
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

          commonArgs = {
            src = lib.cleanSourceWith {
              src = ./.;
              filter = path: type:
                (craneLib.filterCargoSources path type) ||
                (lib.hasSuffix ".java" path) ||
                (lib.hasSuffix ".pest" path) ||
                (lib.hasSuffix ".1" path);   # man page sources
            };
            strictDeps = true;
            buildInputs = [
              pkgs.openssl
            ] ++ lib.optionals pkgs.stdenv.isDarwin [
              pkgs.libiconv
            ];
            nativeBuildInputs = [ pkgs.pkg-config ];
          };

          cargoArtifacts = craneLib.buildDepsOnly commonArgs;

          ghidra-cli = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;
            doCheck = false;
            postInstall = ''
              install -Dm644 docs/ghidra-cli.1 "$out/share/man/man1/ghidra-cli.1"
            '';
          });

          ghidra-cli-wrapped = pkgs.symlinkJoin {
            name = "ghidra-cli-wrapped";
            paths = [ ghidra-cli ];
            buildInputs = [ pkgs.makeWrapper ];
            postBuild = ''
              wrapProgram $out/bin/ghidra-cli \
                --set-default GHIDRA_INSTALL_DIR "${ghidra}/lib/ghidra" \
                --set-default JAVA_HOME "${pkgs.jdk21}" \
                --prefix PATH : "${pkgs.jdk21}/bin"
            '';
          };
        in
        {
          default = ghidra-cli-wrapped;
          inherit ghidra-cli ghidra-cli-wrapped;
        });

      devShells = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          lib = pkgs.lib;
          ghidra = ghidraFor pkgs system;
          rustToolchain = pkgs.rust-bin.stable.latest.default.override {
            extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
          };
        in
        {
          default = pkgs.mkShell {
            buildInputs = [
              rustToolchain
              pkgs.openssl
              pkgs.pkg-config
              ghidra
              pkgs.jdk21
            ] ++ lib.optionals pkgs.stdenv.isDarwin [
              pkgs.libiconv
            ];
            shellHook = ''
              export GHIDRA_INSTALL_DIR="''${GHIDRA_INSTALL_DIR:-${ghidra}/lib/ghidra}"
            '';
          };
        });
    };
}
