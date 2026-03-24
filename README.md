# attestation-server

A Go HTTP server that produces cryptographically verifiable TEE (Trusted Execution Environment) attestation reports. It is designed to run inside immutable, hermetic TEE images alongside a co-located Envoy proxy, enabling remote parties to verify the identity, code integrity, and end-to-end encryption of the workload in a single round-trip.

## Design philosophy

The server is built for security-sensitive workloads deployed as immutable TEE images. Each image is assembled by a CI/CD pipeline that:

1. Builds the workload binary and the attestation server
2. Records build provenance metadata (source repo, commit, builder identity) in a `build-info.json` file using [Fulcio OID](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md) field definitions
3. Computes golden measurements from the final image (PCR values, launch measurements)
4. Packages these measurements into an endorsement document, signs it with [cosign](https://github.com/sigstore/cosign) using Sigstore's public-good infrastructure and OIDC-based keyless signing, and uploads the document and its signature bundle to one or more public object storage buckets
5. Bakes the build-info file, the endorsement URL list, the attestation server binary, and a configured Envoy proxy into the immutable image

At runtime, the attestation server reads the baked-in build info and endorsement URLs, fetches the endorsement documents from the public URLs, validates that the TEE evidence matches the golden measurements, verifies the cosign signature chain back to the CI/CD pipeline, and serves the combined proof to callers. Using multiple storage buckets at different infrastructure providers mitigates credential exposure or malicious activity at any single provider — the server requires byte-for-byte identity across all configured URLs.

## Operational modes

The server supports two deployment modes, often used together in a layered topology:

### Edge mode (public-facing)

Serves attestation reports to external consumers at the boundary of the trusted computing infrastructure. The co-located Envoy proxy terminates TLS using a public certificate. No client certificate is required from callers. The attestation response includes the public certificate fingerprint, allowing verifiers to confirm that the TLS channel they observed matches the one bound into the hardware-signed evidence.

Edge instances typically configure `dependencies.endpoints` pointing to internal services, producing a full transitive attestation tree in their response.

### Internal mode (service-to-service)

Serves attestation reports within the trusted computing infrastructure. All services use private TLS certificates issued by the same CA, providing a service-mesh-like communication model with mutual TLS verification between TEEs. The co-located Envoy proxy terminates inbound mTLS and populates the XFCC header with the client certificate fingerprint. For outbound connections to dependencies, Envoy provides TLS origination — the attestation server connects to Envoy over plaintext HTTP, and Envoy wraps the connection in mTLS toward the upstream TEE.

The private key material never leaves the TEE. The certificate fingerprints are bound into the attestation evidence, so a verifier can confirm end-to-end encryption between specific TEE instances.

### SPIFFE readiness

The current design ingests private TLS certificates as opaque files and does not prescribe how they are issued. However, it is designed to support a complete SPIFFE-based implementation where SVIDs are issued based on TEE attestation documents and endorsed golden measurements — following the same attestation verification pattern implemented in this server. The instance identity computation already includes certificate SANs (where SPIFFE SVIDs carry their identity as URI SANs) to support this path.

## Features

- **Multi-platform TEE support** — AWS Nitro (NSM and NitroTPM), AMD SEV-SNP, and Intel TDX, with chained evidence (e.g. NitroTPM + SEV-SNP on the same request)
- **Nonce binding** — caller-supplied nonce is bound into a SHA-512 digest of all report data, then fed to the TEE attestation mechanism, preventing replay
- **Transitive dependency attestation** — fetches and cryptographically verifies attestation reports from downstream services in parallel, embedding them in the response to prove the entire service graph
- **Endorsement validation** — fetches golden measurement documents from public HTTPS URLs, verifies byte-for-byte identity across redundant storage providers, and validates all TEE evidence against expected values
- **Cosign signature verification** — verifies Sigstore cosign signatures on endorsement documents using Fulcio + Rekor with OIDC-based keyless signing, with per-OID validation against build provenance
- **DNSSEC chain-of-trust** — cryptographic DNSSEC validation for endorsement URL hosts as defense-in-depth against DNS spoofing at compromised infrastructure providers, verified locally against embedded IANA root KSK trust anchors
- **End-to-end encryption proof** — every response includes TLS certificate fingerprints proving the attestation is bound to an encrypted channel where key material is confined to the TEE
- **Certificate hot-reload** — TLS certificates are monitored via fsnotify and reloaded without restart
- **Startup self-attestation** — TEE devices are attested at startup to catch environment issues early and prime caches

## Architecture

The server runs as a plaintext HTTP service behind a co-located [Envoy](https://www.envoyproxy.io/) proxy that is part of the trusted computing base (baked into the same immutable TEE image):

```
                    ┌──────────────────────────────────────────────────┐
                    │                   TEE Instance                   │
                    │                                                  │
                    │   ┌────────────────────────────────────────┐     │
  Internet ────────►│   │ Envoy (public TLS  / private mTLS)     │     │
                    │   │  • terminates inbound TLS              │     │
                    │   │  • populates XFCC header (mTLS)        │     │
                    │   │  • originates outbound mTLS to deps    │     │
                    │   └──────────────┬───────────────────┬─────┘     │
                    │                  │ HTTP              │ mTLS      │
                    │                  ▼                   ▼           │
                    │   ┌──────────────────────┐  ┌──────────────┐     │
                    │   │  attestation-server  │  │  Upstream    │     │
                    │   │  :8187               │  │  TEE deps    │     │
                    │   └──────────┬───────────┘  └──────────────┘     │
                    │              │                                   │
                    │   ┌──────────▼───────────┐                       │
                    │   │  TEE Hardware        │                       │
                    │   │  /dev/nsm, /dev/tpm0 │                       │
                    │   │  /dev/sev-guest      │                       │
                    │   │  configfs (TDX)      │                       │
                    │   └──────────────────────┘                       │
                    └──────────────────────────────────────────────────┘
```

For the full deployment model, TLS design, dependency chain architecture, and endorsement lifecycle, see [docs/architecture.md](docs/architecture.md).

## API

### `GET /api/v1/attestation`

Returns an attestation report with hardware-signed evidence and server metadata.

**Parameters:**

| Parameter | Location | Description |
|-----------|----------|-------------|
| `nonce` | Query param or `x-attestation-nonce` header | Hex-encoded caller nonce (up to 64 bytes / 128 hex chars). Bound into evidence via SHA-512 digest. |

**Response:**

```jsonc
{
  "evidence": [
    {
      "kind": "sevsnp",           // TEE type: nitronsm, nitrotpm, sevsnp, tdx
      "blob": "<base64>",         // raw hardware-signed attestation document
      "data": { ... }             // parsed fields from verified evidence
    }
  ],
  "data": {
    "request_id": "...",
    "nonce": "<hex>",             // echoed caller nonce
    "build_info": { ... },        // SLSA provenance (Fulcio OID fields)
    "tls": {
      "client": { "certificate": "<sha256-hex>" },   // from XFCC (mTLS mode)
      "public": { "certificate": "<sha256-hex>", "public_key": "<sha256-hex>" },
      "private": { "certificate": "<sha256-hex>", "public_key": "<sha256-hex>" }
    },
    "endorsements": [ "https://..." ],   // public URLs of golden measurements
    "secure_boot": true,
    "tpm": { "digest": "SHA384", "pcrs": { "0": "<hex>", ... } },
    "user_data": { "env": { "VAR": "value" } }
  },
  "dependencies": [ { /* nested attestation reports */ } ]
}
```

The `data` field is the exact JSON that was SHA-512-hashed into the attestation nonce. A verifier recomputes `SHA-512(data)` and checks it against the nonce inside the evidence blob.

For a step-by-step client verification guide, see [docs/verification.md](docs/verification.md).

## Configuration

Configuration is loaded from a TOML file, environment variables, and CLI flags. Priority: CLI flags > env vars > config file > defaults.

The config file is resolved as: `--config-file` flag > `ATTESTATION_SERVER_CONFIG_FILE` env > `./config/config.toml` > `./config.toml`.

See [config/config.toml](config/config.toml) for the full annotated configuration with defaults, and [CLAUDE.md](CLAUDE.md) for the complete environment variable reference.

### Key settings

```toml
[report.evidence]
nitronsm = false    # AWS Nitro NSM (exclusive)
nitrotpm = false    # AWS NitroTPM (combinable with sevsnp)
sevsnp   = false    # AMD SEV-SNP (combinable with nitrotpm)
tdx      = false    # Intel TDX (exclusive)

[tls.private]
cert_path = ""      # required — private mTLS certificate (ECDSA)
key_path  = ""      # required — private key
ca_path   = ""      # required — CA bundle for the dependency chain

[dependencies]
endpoints = []      # URLs of downstream attestation servers

[endorsements.cosign]
verify = true       # verify Sigstore cosign signatures on endorsements
```

At least one evidence type must be enabled. NitroNSM and TDX are exclusive (cannot combine with others). NitroTPM and SEV-SNP can be combined for chained evidence.

## Security model

The server's security design is built around four principles:

1. **Immutable trusted computing base** — the server binary, Envoy proxy, configuration, build provenance, and endorsement URLs are all baked into an immutable TEE image; there is no runtime configuration surface for these security-critical components

2. **Hardware-rooted identity** — every response contains a hardware-signed attestation blob that a verifier can check against the TEE vendor's root of trust (AWS Nitro Root CA, AMD root certificates, or Intel SGX Root CA)

3. **Nonce-bound metadata** — all server metadata (build info, TLS fingerprints, endorsement URLs) is hashed into the attestation nonce, making it impossible to mix metadata from one request with evidence from another

4. **End-to-end encryption proof** — every response must include either a client certificate fingerprint (service-to-service mTLS via XFCC) or a public certificate fingerprint (Internet ingress), binding the attestation to a specific TLS channel whose key material is confined to the TEE

For the full security design including trust model, endorsement lifecycle, multi-provider redundancy, and cosign verification, see [docs/security.md](docs/security.md).

## Nix build

The project provides a Nix flake for reproducible, hermetic builds with pinned inputs. It is intended to be referenced as a flake input from downstream TEE image repositories:

```nix
inputs.attestation-server.url = "github:eternisai/attestation-server";
# Binary at: attestation-server.packages.x86_64-linux.default -> $out/bin/attestation-server
```

## Development

```sh
go build ./...          # build
go test ./...           # run tests
go fmt ./...            # format
go run .                # run locally (uses config/config.toml)
```

### Running fuzz tests

```sh
go test ./internal/ -fuzz=FuzzExtractXFCCHash -fuzztime=30s
go test ./pkg/hexbytes/ -fuzz=FuzzBytes_UnmarshalJSON -fuzztime=30s
```

### Running live DNSSEC tests

```sh
DNSSEC_LIVE_TEST=1 go test ./pkg/dnssec/ -run TestLive -v
```

## Public packages

The `pkg/` directory contains packages that can be imported independently for TEE attestation verification:

| Package | Description |
|---------|-------------|
| [`pkg/nitro`](pkg/nitro/) | AWS Nitro NSM and NitroTPM attestation — COSE_Sign1 verification against the AWS Nitro root CA |
| [`pkg/sevsnp`](pkg/sevsnp/) | AMD SEV-SNP attestation — signature verification against embedded AMD root certificates |
| [`pkg/tdx`](pkg/tdx/) | Intel TDX attestation — quote verification against the Intel SGX Root CA |
| [`pkg/dnssec`](pkg/dnssec/) | DNSSEC chain-of-trust validation with embedded IANA root KSK trust anchors |
| [`pkg/hexbytes`](pkg/hexbytes/) | `[]byte` type that JSON-serializes as hex strings |
| [`pkg/tpm`](pkg/tpm/) | Generic TPM PCR reading via `/dev/tpmrm0` |

## License

See [LICENSE](LICENSE) for details.
