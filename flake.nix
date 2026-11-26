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

      llvm = pkgs.llvmPackages; # probably pin this to a version (i.e. `.llvmPackages_<VERSION>`)

      rust = pkgs.rust-bin.selectLatestNightlyWith (
        tc:
        tc.default.override {
          extensions = [ "rust-src" ];
          targets = [
            "x86_64-pc-windows-gnu"
            "x86_64-pc-windows-msvc"
            "x86_64-unknown-linux-gnu"
          ];
        }
      );
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        packages = [
          mingwCC
          rust
          llvm.clang-unwrapped
          llvm.lld
          llvm.llvm

          pkgs.cargo-xwin
          pkgs.wineWow64Packages.stable
          pkgs.uv
        ];

        CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = "${mingwCC}/bin/x86_64-w64-mingw32-gcc";
        CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS = "-L native=${mingw.windows.pthreads}/lib";
        CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER = "wine";

        # `cargo-xwin` sets linker + SDK library paths for MSVC
        CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUNNER = "wine";

        WINEDEBUG = "-all";
        shellHook = ''
          export GIT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
          export WINEPREFIX="$GIT_ROOT/.wine"
          export XWIN_CACHE_DIR="$GIT_ROOT/.xwin"
        '';

        # NOTE that it looks like we can't use `cargo-xwin` during a nix package build
        # as it downloads CRT/SDK libs at the "point-of-build", and the nix build
        # sandbox doesn't have a network connection

      };
    };
}
