{
  description = "TEE attestation server";

  inputs = {
    # nixpkgs-unstable at 2026-03-23T13:48:00Z
    nixpkgs.url = "github:NixOS/nixpkgs/fdc7b8f7b30fdbedec91b71ed82f36e1637483ed";
    # flake-utils main at 2024-11-13T21:27:16Z
    flake-utils.url = "github:numtide/flake-utils/11707dc2f618dd54ca8739b309ec4fc024de578b";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        src = pkgs.lib.sources.cleanSourceWith {
          src = ./.;
          filter = path: type:
            let baseName = baseNameOf path; in
            type == "directory"
            || baseName == "go.mod"
            || baseName == "go.sum"
            || pkgs.lib.hasSuffix ".go" baseName;
        };
      in
      {
        packages = rec {
          attestation-server = pkgs.buildGoModule {
            pname = "attestation-server";
            version = self.shortRev or self.dirtyShortRev or "dev";

            inherit src;
            vendorHash = "sha256-sTgIRlivo+8b549oc2ysmOPk1c88Sy2sRbT65pWSzPQ=";

            subPackages = [ "." ];

            env.CGO_ENABLED = 0;
            ldflags = [ "-s" "-w" ];

            # Tests require TEE hardware devices and network access
            doCheck = false;
          };
          default = attestation-server;
        };
      }
    );
}
