{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      nixpkgs,
      crane,
      rust-overlay,
      ...
    }:
    let
      inherit (nixpkgs) lib;

      eachSystem = lib.genAttrs lib.systems.flakeExposed (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };

          toolchain = pkgs.rust-bin.selectLatestNightlyWith (
            tc:
            tc.default.override {
              extensions = [
                "rust-src"
                "rust-analyzer"
              ];
            }
          );

          craneLib = (crane.mkLib pkgs).overrideToolchain (_: toolchain);

          src = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter = path: type: craneLib.filterCargoSources path type;
          };

          nativeBuildInputs = with pkgs; [
            pkg-config
            mold
          ];

          buildInputs = with pkgs; [
            dbus
            libusb1
            udev
          ];

          fido-ssh-agent = craneLib.buildPackage {
            inherit
              src
              strictDeps
              nativeBuildInputs
              buildInputs
              ;
            doCheck = false;
          };

          strictDeps = true;
        in
        {
          packages.default = fido-ssh-agent;

          devShells.default = craneLib.devShell {
            inherit buildInputs nativeBuildInputs;
            RUST_BACKTRACE = 1;
            LD_LIBRARY_PATH = lib.makeLibraryPath buildInputs;
          };
        }
      );
    in
    {
      packages = lib.mapAttrs (_: v: v.packages) eachSystem;
      devShells = lib.mapAttrs (_: v: v.devShells) eachSystem;
    };
}
