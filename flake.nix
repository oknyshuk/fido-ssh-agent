{
  description = "Linux SSH agent for FIDO2 security keys";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      ...
    }:
    let
      inherit (nixpkgs) lib;

      eachSystem =
        lib.genAttrs
          [
            "x86_64-linux"
            "aarch64-linux"
          ]
          (
            system:
            let
              pkgs = nixpkgs.legacyPackages.${system};
              craneLib = crane.mkLib pkgs;

              commonArgs = {
                src = craneLib.cleanCargoSource ./.;
                strictDeps = true;
                nativeBuildInputs = [ pkgs.pkg-config ];
                buildInputs = with pkgs; [
                  libusb1
                  udev
                ];
              };

              cargoArtifacts = craneLib.buildDepsOnly commonArgs;

              fido-ssh-agent = craneLib.buildPackage (
                commonArgs
                // {
                  inherit cargoArtifacts;
                  doCheck = false;
                  postInstall = ''
                    install -Dm644 ${./systemd/fido-ssh-agent.service} \
                      $out/share/systemd/user/fido-ssh-agent.service
                    install -Dm644 ${./systemd/fido-ssh-agent.socket} \
                      $out/share/systemd/user/fido-ssh-agent.socket
                  '';
                  meta = {
                    description = "Linux SSH agent for FIDO2 security keys";
                    homepage = "https://github.com/oknyshuk/fido-ssh-agent";
                    license = lib.licenses.mit;
                    mainProgram = "fido-ssh-agent";
                    platforms = lib.platforms.linux;
                  };
                }
              );
            in
            {
              packages = {
                default = fido-ssh-agent;
                inherit fido-ssh-agent;
              };

              apps.default = {
                type = "app";
                program = lib.getExe fido-ssh-agent;
              };

              checks = {
                inherit fido-ssh-agent;
                clippy = craneLib.cargoClippy (
                  commonArgs
                  // {
                    inherit cargoArtifacts;
                    cargoClippyExtraArgs = "--all-targets -- --deny warnings";
                  }
                );
                fmt = craneLib.cargoFmt { inherit (commonArgs) src; };
              };

              devShells.default = pkgs.mkShell {
                packages = with pkgs; [
                  cargo
                  rustc
                  rustfmt
                  clippy
                  rust-analyzer
                  pkg-config
                  libusb1
                  udev
                ];
              };

              formatter = pkgs.nixfmt-rfc-style;
            }
          );
    in
    {
      packages = lib.mapAttrs (_: v: v.packages) eachSystem;
      apps = lib.mapAttrs (_: v: v.apps) eachSystem;
      checks = lib.mapAttrs (_: v: v.checks) eachSystem;
      devShells = lib.mapAttrs (_: v: v.devShells) eachSystem;
      formatter = lib.mapAttrs (_: v: v.formatter) eachSystem;
      overlays.default = final: _: {
        fido-ssh-agent = self.packages.${final.stdenv.hostPlatform.system}.default;
      };
    };
}
