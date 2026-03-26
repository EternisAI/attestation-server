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
            || pkgs.lib.hasSuffix ".go" baseName
            || pkgs.lib.hasSuffix ".json" baseName;
        };
      in
      {
        packages = rec {
          attestation-server = pkgs.buildGoModule {
            pname = "attestation-server";
            version = self.shortRev or self.dirtyShortRev or "dev";

            inherit src;
            vendorHash = "sha256-1BXfSgutuFxtBAByq+PO5K0gKpVNy4etCmcxe7t5Goo=";

            subPackages = [ "." ];

            env.CGO_ENABLED = 0;
            ldflags = [ "-s" "-w" ];

            # Live DNSSEC tests are gated behind DNSSEC_LIVE_TEST env var
            # and skip themselves in the sandbox; all other tests use fixtures
            doCheck = true;
          };
          default = attestation-server;

          docker-image = pkgs.dockerTools.streamLayeredImage {
            name = "ghcr.io/eternisai/attestation-server";
            tag = "latest";
            contents = [
              attestation-server
              (pkgs.runCommand "attestation-server-link" {} ''
                mkdir -p $out/usr/local/bin
                ln -s ${attestation-server}/bin/attestation-server $out/usr/local/bin/attestation-server
              '')
            ];
            config = {
              Entrypoint = [ "${attestation-server}/bin/attestation-server" ];
            };
          };
        };
      }
    );
}
