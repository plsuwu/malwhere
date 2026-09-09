{
  description = "Build a cargo project with a custom toolchain";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      flake-utils,
      rust-overlay,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        # craneLib = crane.mkLib pkgs;
        rustToolchainFor =
          p:
          p.rust-bin.selectLatestNightlyWith (
            toolchain:
            toolchain.default.override {
              extensions = [ "rust-src" ];
              targets = [ "x86_64-unknown-linux-gnu" ];
            }
          );

        # rustToolchain = rustToolchainFor pkgs;
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchainFor;
      in
      {
        devShells.default = craneLib.devShell {
          # buildInputs = with pkgs; [
          #   clang
          #   bear
          #   valgrind
          # ];
          packages = with pkgs; [
            clang
            clang-tools
            bear
            valgrind
            pkg-config
          ];
        };
      }
    );
}
