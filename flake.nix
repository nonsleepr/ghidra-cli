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
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          lib = pkgs.lib;
          rustToolchain = pkgs.rust-bin.stable.latest.default;
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

          commonArgs = {
            src = lib.cleanSourceWith {
              src = ./.;
              filter = path: type:
                (craneLib.filterCargoSources path type) ||
                (lib.hasSuffix ".java" path) ||
                (lib.hasSuffix ".pest" path);
            };
            strictDeps = true;
            buildInputs = [
              pkgs.openssl
            ] ++ lib.optionals pkgs.stdenv.isDarwin [
              pkgs.libiconv
              pkgs.darwin.apple_sdk.frameworks.Security
              pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
            ];
            nativeBuildInputs = [ pkgs.pkg-config ];
          };

          cargoArtifacts = craneLib.buildDepsOnly commonArgs;

          ghidra-cli = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;
            doCheck = false;
          });

          ghidra-cli-wrapped = pkgs.symlinkJoin {
            name = "ghidra-cli-wrapped";
            paths = [ ghidra-cli ];
            buildInputs = [ pkgs.makeWrapper ];
            postBuild = ''
              wrapProgram $out/bin/ghidra \
                --set GHIDRA_INSTALL_DIR "${pkgs.ghidra}/lib/ghidra" \
                --prefix PATH : "${pkgs.jdk}/bin"
              mv $out/bin/ghidra $out/bin/ghidra-cli
            '';
          };
        in
        {
          default = ghidra-cli-wrapped;
          inherit ghidra-cli ghidra-cli-wrapped;
        });

      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          lib = pkgs.lib;
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
              pkgs.ghidra
              pkgs.jdk
            ] ++ lib.optionals pkgs.stdenv.isDarwin [
              pkgs.libiconv
              pkgs.darwin.apple_sdk.frameworks.Security
              pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
            ];
            shellHook = ''
              export GHIDRA_INSTALL_DIR="${pkgs.ghidra}/lib/ghidra"
            '';
          };
        });
    };
}
