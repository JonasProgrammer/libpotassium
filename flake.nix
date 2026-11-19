# SPDX-FileCopyrightText: 2026 libpotassium team
# SPDX-License-Identifier: BSL-1.0

{
  description = "Development shell for libpotassium";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  # For CMake 4.5
  inputs.nixpkgs-staging = {
    url = "github:NixOS/nixpkgs/staging";
    flake = false;
  };

  outputs =
    { nixpkgs, nixpkgs-staging, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      pkgs-staging = import nixpkgs-staging { inherit system; };
      selectedStdenv = pkgs.gcc16Stdenv;

      cmake45 = pkgs.callPackage "${nixpkgs-staging}/pkgs/by-name/cm/cmake/package.nix" { };

      mkDevShell = pkgs.mkShell.override {
        stdenv = selectedStdenv;
      };

      baseShell = mkDevShell {
        packages = [
          cmake45
          pkgs.ninja
        ];

        buildInputs = [ pkgs.libsodium ];

        # Select nixpkgs' wrapped compilers.
        CC = "${selectedStdenv.cc}/bin/gcc";
        CXX = "${selectedStdenv.cc}/bin/g++";
      };

      fullShell = mkDevShell {
        inputsFrom = [ baseShell ];

        packages = [
          pkgs.doxygen
        ];

        buildInputs = [
          pkgs.catch2_3
        ];
      };
    in
    {
      devShells.${system} = {
        default = baseShell;
        full = fullShell;
      };
    };
}
