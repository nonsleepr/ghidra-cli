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
          rustToolchain = pkgs.rust-bin.stable.latest.default;
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

          commonArgs = {
            src = craneLib.cleanCargoSource ./.;
            strictDeps = true;
            buildInputs = pkgs.lib.optionals pkgs.stdenv.isDarwin [
              pkgs.libiconv
              pkgs.darwin.apple_sdk.frameworks.Security
              pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
            ];
            nativeBuildInputs = [ pkgs.pkg-config ];
          };

          cargoArtifacts = craneLib.buildDepsOnly commonArgs;

          ghidra-cli = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;
          });
        in
        {
          default = ghidra-cli;
          inherit ghidra-cli;
        });

      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          rustToolchain = pkgs.rust-bin.stable.latest.default.override {
            extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
          };
        in
        {
          default = pkgs.mkShell {
            buildInputs = [
              rustToolchain
              pkgs.pkg-config
            ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
              pkgs.libiconv
              pkgs.darwin.apple_sdk.frameworks.Security
              pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
            ];
          };
        });
    };
}
