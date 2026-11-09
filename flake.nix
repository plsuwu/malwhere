{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };

      mingw = pkgs.pkgsCross.mingwW64;
      mingwCC = mingw.stdenv.cc;

      rust = pkgs.rust-bin.stable.latest.default.override {
        targets = [ "x86_64-pc-windows-gnu" ];
      };
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        packages = [
          mingwCC
          rust
          pkgs.wineWow64Packages.stable
        ];

        CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = "${mingwCC}/bin/x86_64-w64-mingw32-gcc";
        CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER = "wine";
        CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS = "-L native=${mingw.windows.pthreads}/lib";

        WINEDEBUG = "-all";
        shellHook = ''
          # export WINEPREFIX="$PWD/.wine"
          export WINEPREFIX="$(git rev-parse --show-toplevel 2>/dev/null || pwd)/.wine"
        '';
      };
    };
}
