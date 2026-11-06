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

      # `MinGW-w64` -> `x86_64-w64-mingw32-gcc/g++`/`windows.h`/import libs
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
          pkgs.wineWowPackages.stable
          pkgs.cmake
          pkgs.meson
          pkgs.ninja
        ];

        CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = "${mingwCC}/bin/x86_64-w64-mingw32-gcc";
        CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER = "wine";
        CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS = "-L native=${mingw.windows.pthreads}/lib";
        shellHook = ''
          export WINEPREFIX="$PWD/.wine"
          export WINEDEBUG=-all
        '';
      };
    };
}
