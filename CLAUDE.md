# attestation-server

A Go HTTP server for serving TEE (Trusted Execution Environment) attestation documents. Runs behind an Envoy reverse proxy that terminates TLS — Envoy uses the private certificate for mTLS (XFCC header) and optionally the public certificate for Internet-facing ingress. The private certificate is only required when dependency endpoints are configured or when no public certificate is set.

## Tech stack

- **CLI/config**: [spf13/cobra](https://github.com/spf13/cobra) for CLI, [spf13/viper](https://github.com/spf13/viper) for configuration
- **HTTP**: [go-fiber v2](https://github.com/gofiber/fiber) with `requestid` middleware
- **Logging**: standard `log/slog`, JSON format on stdout

## Project structure

```
main.go                    # entry point
cmd/root.go                # cobra root command; initializes config, logger, starts server
internal/attestation.go    # GET /api/v1/attestation handler and helpers (package app)
internal/config.go         # Config struct and LoadConfig() (package app)
internal/dependencies.go   # Transitive dependency attestation (package app)
internal/cosign.go         # Cosign signature verification (package app)
internal/endorsements.go   # Endorsement fetching, validation, cosign integration (package app)
internal/fetch.go          # HTTP fetch with retry, cache (ristretto), TTL parsing (package app)
internal/health.go         # /healthz/live and /healthz/ready handlers (package app)
internal/logging.go        # NewLogger() (package app)
internal/server.go         # Server, NewServer(), Run() (package app)
internal/tls.go            # TLS cert/CA loading, verification, hot-reload (package app)
internal/types.go          # BuildInfo, AttestationReport, shared structs (package app)
pkg/dnssec/dnssec.go       # DNSSEC chain-of-trust validation (package dnssec)
pkg/hexbytes/hexbytes.go   # HexBytes type: []byte with hex JSON serialization (package hexbytes)
pkg/nitro/nitro.go         # Nitro COSE_Sign1 verification, cert chain validation (package nitro)
pkg/nitro/nsm.go           # NSM device access via /dev/nsm (package nitro)
pkg/nitro/tpm.go           # NitroTPM via raw TPM2 protocol over /dev/tpm0 (package nitro)
pkg/sevsnp/sevsnp.go       # SEV-SNP attestation via go-sev-guest (package sevsnp)
pkg/tdx/tdx.go             # Intel TDX attestation via go-tdx-guest (package tdx)
pkg/tpm/tpm.go             # Generic TPM PCR reading via /dev/tpmrm0 (package tpm)
config/config.toml         # default configuration file
flake.nix                  # Nix flake: hermetic build of binary and Docker image
flake.lock                 # pinned Nix input revisions
.github/workflows/ci.yml          # CI: fmt, test, vet, build on non-main branches
.github/workflows/nix-build.yml   # Nix build on PRs to main (flake/dep changes only)
.github/workflows/release.yml     # Release: Nix build -> Release Please -> GHCR + cosign
release-please-config.json        # Release Please configuration
.release-please-manifest.json     # Release Please version manifest
```

## Configuration

Loaded via TOML config file, environment variables, and CLI flags. Priority: CLI flags > env vars > config file > defaults. `LoadConfig` validates at startup: duration fields reject negative values (`parseDuration`), timeout/interval fields additionally reject zero, byte-size fields use `dustin/go-humanize` with int64 overflow protection.

### Config file

Resolved in order:
1. `--config-file` / `-c` flag
2. `ATTESTATION_SERVER_CONFIG_FILE` env var
3. `./config/config.toml` (fallback)
4. `./config.toml` (fallback)

See `config/config.toml` for the full structure and defaults.

### CLI flags

Only logging and config file have CLI flag equivalents: `--config-file`/`-c`, `--log-format` (`json`/`text`), `--log-level` (`debug`/`info`/`warn`/`error`).

### Environment variables

All TOML settings map to env vars prefixed with `ATTESTATION_SERVER_`, with `.` replaced by `_` and uppercased (e.g., `tls.private.ca_path` -> `ATTESTATION_SERVER_TLS_PRIVATE_CA_PATH`).

List-typed variables (`REPORT_USER_DATA_ENV`, `DEPENDENCIES_ENDPOINTS`, `ENDORSEMENTS_ALLOWED_DOMAINS`) support comma-separated values with trimmed spaces: `VAR=a,b,c`.

## Logging conventions

- Use `log/slog` throughout; never `fmt.Print*` or `log.*`.
- Messages: short single sentences, **no initial capital, no trailing punctuation**.
- Structured details (IDs, values, errors) go in slog fields, not in the message.
- Access logs: `method`, `path`, `status`, `duration_ms`, `request_id`. INFO for 2xx/3xx, WARN for 4xx, ERROR for 5xx.
- Error field key: `"error"`.

## Code style

- All Go code must be `go fmt`-conformant. Run `go fmt ./...` before committing.
- Use `github.com/goccy/go-json` everywhere instead of `encoding/json`. The attestation handler uses `json.MarshalWithOption(..., json.DisableHTMLEscape())` for the nonce digest, then embeds via `json.RawMessage` for byte-for-byte consistency.
- **Fiber `UnsafeString` hazard**: `c.Get()`, `c.Query()`, `c.IP()`, etc. return strings backed by fasthttp's reusable buffer. Use `strings.Clone()` before storing beyond handler lifetime. JSON marshaling and string concatenation are safe without cloning.
- **Fiber `c.UserContext()` hazard**: Returns `context.Background()` — never cancelled on shutdown. Use `s.shutdownCtx()` instead for blocking operations (HTTP fetches, rate limiter waits, etc.).

## TEE package public API

Each TEE package (`pkg/nitro`, `pkg/sevsnp`, `pkg/tdx`) exposes: `GetEvidence`, `VerifyEvidence`, `Attest` (combined get+verify). The `sevsnp` package additionally exports `SplitEvidence`, `ReportSize`, and `RevocationChecker`. Both `sevsnp.VerifyEvidence` and `tdx.VerifyEvidence` accept optional variadic parameters for revocation checking.

## SEV-SNP workarounds (pkg/sevsnp)

`VerifyEvidence` implements its own verification instead of `verify.SnpAttestation` from go-sev-guest to work around library issues on AWS Nitro:

- **Do not replace with `verify.SnpAttestation`** — fails on AWS due to unknown policy bits, malformed ASK/ARK certs, and proto round-trip breaking signatures.
- **Do not remove `reportToProto`** — sanitises policy bits for parsing while preserving original values.
- **Do not remove `trustedRoots`** — pre-parsed AMD root certs bypass malformed certificate table entries.
- Revisit when go-sev-guest ships [PR #181](https://github.com/google/go-sev-guest/pull/181).

`GetEvidence` caches the certificate table size after the first call to eliminate a ~2s throttle delay on subsequent calls. The startup self-attestation primes this cache.

## Critical design constraints

### Error information leakage

Handler error messages must be opaque (`"attestation failed"`, `"dependency attestation failed"`). Never include device errors, file paths, or firmware codes. Real errors are logged at ERROR level with `request_id`. Unhandled errors (not wrapped in `fiber.NewError`) fall back to `"internal error"`.

### XFCC header

Reject requests with multiple comma-separated XFCC entries (400). Single entry enforces direct e2e encryption without proxy intermediaries.

### End-to-end encryption proof

Every attestation response must have `data.tls.client` (mTLS) or `data.tls.public` (public ingress). Missing both -> 400.

### Dependency verification

After cryptographic verification of a dependency's attestation:
1. **Client cert check**: dependency's `data.tls.client` must match our private cert fingerprint
2. **Server cert check** (HTTPS only): observed server cert fingerprint must match dependency's `data.tls.private`

Raw dependency bytes are stored as `json.RawMessage` (not re-marshaled) to avoid `goccy/go-json` zero-copy string issues.

### Cycle detection

`X-Attestation-Path` header carries visited service identities. Identity = `SHA-256(json(build_info) || cert_subject || cert_SANs)` using private cert (public cert fallback). SANs included because SPIFFE SVIDs may have empty subjects.

### Rate limiting

Only applies to requests without XFCC header (edge traffic), scoped to `/api/v1/attestation`. Stalls over-limit requests up to `stall_timeout` before 429. IP extraction: `X-Envoy-Original-IP` > first `X-Forwarded-For` > connection IP (validated as IP to prevent unbounded map entries).

### Endorsement domain allowlist

Exact hostname match (case-insensitive), no subdomain matching. Applies to own and dependency endorsement URLs. Empty allowlist logs a startup warning.

### Cosign verification

Only Cosign v3 protobuf bundles supported. Fulcio OID fields validated against BuildInfo:
- `build_signer.uri` takes precedence over `uri_regex` (warning logged if both set)
- `BuildSignerDigest` skipped when any `build_signer` config is set (digest changes per-commit)
- `SourceRepositoryVisibilityAtSigning` maps to `SourceRepositoryVisibility`
- `DeploymentEnvironment` not checked (no standard Fulcio OID)

When cosign is enabled, endorsement URLs are required (own and dependencies).

### TLS

- Dependency mTLS client: TLS 1.3 minimum. Endorsement/cosign client: TLS 1.2 minimum.
- Certificate hot-reload via fsnotify; private cert, CA bundle, and fingerprints swapped atomically under `tlsCertificates.mu`.
- CA bundle loader (`loadCABundle`) verifies self-signed certs via `x509.CheckSignatureFrom`; SHA-1 CAs hard-rejected.

### Certificate revocation

- **SEV-SNP**: Background CRL fetch from AMD KDS (fail-open if no data yet). Initialized when local SEV-SNP evidence or dependency endpoints are configured.
- **TDX**: Delegated to go-tdx-guest with `cachedHTTPSGetter` backed by shared ristretto cache.
- **Nitro**: No CRL mechanism (ephemeral cert chains; AWS handles revocation).

### Health checks

`/healthz/live` returns 200 once the HTTP listener is up. `/healthz/ready` returns 200 after `NewServer` (self-attestation, endorsement validation) and the initial CRL fetch (if configured) complete; 503 before that. Readiness is a one-way transition — no runtime condition (cert reload failure, CRL refresh failure) flips it back because all background processes use fail-safe/fail-open semantics. Health routes are not rate-limited.

### Startup self-attestation

`NewServer` calls `Attest` with random nonce on each TEE device. Parsed results captured in `parsedSelfAttestation` for endorsement validation. Exits on failure.

### Endorsement document format

JSON with evidence-type keys (`nitronsm`, `nitrotpm`, `sevsnp`, `tdx`, `tpm`):
- **NitroNSM/NitroTPM/TPM**: `{"PCR0": "hex", ...}` or `{"0": "hex", ...}` — PCR indices to hex values. `PCRGoldenValues` is `map[int]hexbytes.Bytes`.
- **SEV-SNP**: single hex string (96 chars = 384-bit launch measurement)
- **TDX**: `{"MRTD": "hex", "RTMR0": "hex", "RTMR1": "hex", "RTMR2": "hex"}` (all optional)

## Testing

Standard `testing` package, table-driven subtests with `t.Run`, no testify, no hardware mocking.

### Fuzz tests

Security-sensitive parsers have `Fuzz*` tests (Go native fuzzing). Run seed corpus with `go test ./...`; run fuzzing with e.g. `go test ./internal/ -fuzz=FuzzExtractXFCCHash -fuzztime=30s`.

### Live DNSSEC tests

```sh
DNSSEC_LIVE_TEST=1 go test ./pkg/dnssec/ -run TestLive -v
```

### Attestation fixtures

TEE packages have `testdata/` directories with JSON fixtures from real hardware. Clock from `data.timestamp` (RFC 3339, truncated to seconds), nonce from `SHA-512(compact(data))`. Tests cross-check `NewAttestationData` output. Chained fixtures (NitroTPM+SEV-SNP) bind via `SHA-512(nitroTPMBlob)`. Dependency fixture tests a diamond graph with cross-service evidence.

## Nix build

Hermetic build via Nix flake (`CGO_ENABLED=0`, stripped). Tests run during build. Source filter: `*.go`, `*.json`, `go.mod`, `go.sum`. Two targets: `default` (static binary), `docker-image` (minimal OCI with compiled-in TLS roots via `x509roots/fallback`).

When `go.mod`/`go.sum` change, update `vendorHash` in `flake.nix`: set to `lib.fakeHash`, build, use hash from error.

Referenced as a GitHub source input from downstream TEE image repos:

```nix
inputs.attestation-server.url = "github:eternisai/attestation-server";
```

## CI/CD

- **CI** (`ci.yml`) — non-main pushes: `go fmt`, `go test` (with `DNSSEC_LIVE_TEST=1`), `go vet`, `go build`. Skips doc-only changes.
- **Nix Build** (`nix-build.yml`) — PRs to main, only on flake/dep changes. Catches recipe breakage and `vendorHash` mismatches.
- **Release** (`release.yml`) — push to main: Nix build -> Release Please -> Docker push to `ghcr.io/eternisai/attestation-server:<tag>` + keyless cosign.
- Branch protection: require both `Test` and `Build` checks; mark as "skippable" for GitHub rulesets so PRs without Nix changes aren't blocked.

Release Please configured via `release-please-config.json` and `.release-please-manifest.json`.

## Development

```sh
go build ./...              # build
go run .                    # run locally (config/config.toml)
go test ./...               # run tests
go fmt ./...                # format
```

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `chore:`, `refactor:`, `docs:`, `test:`, etc.
