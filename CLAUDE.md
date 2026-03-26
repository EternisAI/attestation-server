# attestation-server

A Go HTTP server for serving TEE (Trusted Execution Environment) attestation documents. The server runs behind an Envoy reverse proxy that terminates TLS — Envoy uses the private certificate for service-to-service mTLS (setting the XFCC header with the client cert hash) and optionally the public certificate for Internet-facing ingress without client certificates.

## Tech stack

- **CLI/config**: [spf13/cobra](https://github.com/spf13/cobra) for CLI, [spf13/viper](https://github.com/spf13/viper) for configuration
- **HTTP**: [go-fiber v2](https://github.com/gofiber/fiber) with `requestid` middleware
- **Logging**: standard `log/slog`, JSON format on stdout

## Project structure

```
main.go                    # entry point
cmd/root.go                # cobra root command; initializes config, logger, and starts server
internal/attestation.go    # GET /api/v1/attestation handler and helpers (package app)
internal/config.go         # Config struct and LoadConfig() (package app)
internal/dependencies.go   # Transitive dependency attestation: parallel fetch, verify, cycle detection (package app)
internal/cosign.go         # Cosign signature verification: bundle fetch, Sigstore/Rekor verification, Fulcio OID extraction + validation (package app)
internal/endorsements.go   # Endorsement document fetching, DNSSEC, measurement validation, cosign integration (package app)
internal/fetch.go          # Generic HTTP fetch with retry, per-attempt WARN logging, cache (ristretto), TTL parsing, cachedHTTPSGetter for TDX collateral — shared by endorsements, cosign, and TDX (package app)
internal/logging.go        # NewLogger() (package app)
internal/server.go         # Server, NewServer(), Run() (package app)
internal/tls.go            # TLS certificate/CA loading, verification, and hot-reload (package app)
internal/types.go          # BuildInfo, AttestationReport, AttestationReportData, and other shared structs (package app)
pkg/dnssec/dnssec.go       # DNSSEC chain-of-trust validation: walks delegation chain from zone to root, verifies RRSIG signatures, embedded IANA root KSK trust anchors (package dnssec)
pkg/hexbytes/hexbytes.go   # Shared HexBytes type: []byte that JSON-serializes as hex string (package hexbytes)
pkg/nitro/nitro.go         # Shared Nitro attestation: COSE_Sign1 verification, cert chain validation, embedded AWS Nitro root CA (package nitro)
pkg/nitro/nsm.go           # NSM device access and attestation via /dev/nsm (package nitro)
pkg/nitro/tpm.go           # NitroTPM device access and attestation via raw TPM2 protocol over /dev/tpm0 (package nitro)
pkg/sevsnp/sevsnp.go       # SEV-SNP device access, attestation via go-sev-guest, signature verification, report parsing (package sevsnp)
pkg/tdx/tdx.go             # Intel TDX device access, attestation via go-tdx-guest, quote verification, report parsing (package tdx)
pkg/tpm/tpm.go             # Generic TPM PCR reading via google/go-tpm over /dev/tpmrm0 (package tpm)
config/config.toml         # default configuration file
flake.nix                  # Nix flake: reproducible hermetic build of the server binary and Docker image
flake.lock                 # pinned Nix input revisions (nixpkgs, flake-utils)
.github/workflows/ci.yml  # CI: go fmt, go test (with DNSSEC live tests), go vet, go build on pushes to non-main branches
.github/workflows/nix-build.yml # Nix build: nix build .#docker-image (with offline tests) on PRs to main
.github/workflows/release.yml # Release: Nix build → Release Please → Docker push to GHCR + cosign
release-please-config.json # Release Please configuration (changelog sections, versioning)
.release-please-manifest.json # Release Please version manifest
```

## Configuration

Configuration is loaded via a TOML config file, environment variables, and CLI flags. Priority (highest to lowest): CLI flags > env vars > config file > defaults. `LoadConfig` validates all values at startup: duration fields reject negative values (`parseDuration`), timeout and interval fields (`endorsements.client.timeout`, `revocation.refresh_interval`, `ratelimit.stall_timeout`) additionally reject zero, byte-size fields use `dustin/go-humanize` for parsing with int64 overflow protection, and invalid durations or byte sizes fail the startup.

### Config file

The config file is resolved in order:
1. `--config-file` / `-c` flag
2. `ATTESTATION_SERVER_CONFIG_FILE` env var
3. `./config/config.toml` (fallback)
4. `./config.toml` (fallback)

See `config/config.toml` for the full structure:

```toml
[log]
format = "json"
level  = "info"

[server]
host = "127.0.0.1"
port = 8187

[paths]
build_info   = "/etc/build-info.json"
endorsements = "/etc/endorsements.json"

[report.evidence]
nitronsm    = false
nitrotpm    = false
sevsnp      = false
sevsnp_vmpl = 0
tdx         = false

[tpm]
enabled   = false
algorithm = "sha384"

[report.user_data]
env = []

[ratelimit]
enabled             = false
requests_per_second = 1
burst               = 1
stall_timeout       = "10s"

[revocation]
enabled          = true
refresh_interval = "12h"

[secure_boot]
enforce = false

[endorsements]
dnssec          = false
allowed_domains = []

[endorsements.client]
timeout = "10s"

[endorsements.cosign]
verify         = true
url_suffix     = ".sig"
tuf_cache_path = ""

[endorsements.cosign.build_signer]
uri       = ""
uri_regex = ""

[http]
allow_proxy = false

[http.cache]
size        = "100MiB"
default_ttl = "1h"

[dependencies]
endpoints = []

[tls.public]
cert_path   = ""
key_path    = ""
skip_verify = false

[tls.private]
cert_path = ""
key_path  = ""
ca_path   = ""  # required
```

### CLI flags

Only logging and config file settings have CLI flag equivalents:

| Flag | Default | Description |
|------|---------|-------------|
| `--config-file`, `-c` | _(see fallback above)_ | Path to TOML config file |
| `--log-format` | `json` | Log format: `json`/`text` |
| `--log-level` | `info` | Log level: `debug`/`info`/`warn`/`error` |

### Environment variables

All settings can be configured via environment variables prefixed with `ATTESTATION_SERVER_`:

| Env var | TOML key | Default | Description |
|---------|----------|---------|-------------|
| `ATTESTATION_SERVER_CONFIG_FILE` | — | — | Path to TOML config file |
| `ATTESTATION_SERVER_LOG_FORMAT` | `log.format` | `json` | Log format: `json`/`text` |
| `ATTESTATION_SERVER_LOG_LEVEL` | `log.level` | `info` | Log level: `debug`/`info`/`warn`/`error` |
| `ATTESTATION_SERVER_SERVER_HOST` | `server.host` | `127.0.0.1` | HTTP bind host |
| `ATTESTATION_SERVER_SERVER_PORT` | `server.port` | `8187` | HTTP bind port |
| `ATTESTATION_SERVER_PATHS_BUILD_INFO` | `paths.build_info` | `/etc/build-info.json` | Path to build information file |
| `ATTESTATION_SERVER_PATHS_ENDORSEMENTS` | `paths.endorsements` | `/etc/endorsements.json` | Path to endorsements URL list file |
| `ATTESTATION_SERVER_TLS_PUBLIC_CERT_PATH` | `tls.public.cert_path` | — | Path to public TLS certificate (PEM) |
| `ATTESTATION_SERVER_TLS_PUBLIC_KEY_PATH` | `tls.public.key_path` | — | Path to public TLS private key (PEM) |
| `ATTESTATION_SERVER_TLS_PUBLIC_SKIP_VERIFY` | `tls.public.skip_verify` | `false` | Skip system/Mozilla root CA chain verification for the public certificate |
| `ATTESTATION_SERVER_TLS_PRIVATE_CERT_PATH` | `tls.private.cert_path` | — | **Required.** Path to private TLS certificate (PEM) |
| `ATTESTATION_SERVER_TLS_PRIVATE_KEY_PATH` | `tls.private.key_path` | — | **Required.** Path to private TLS private key (PEM) |
| `ATTESTATION_SERVER_TLS_PRIVATE_CA_PATH` | `tls.private.ca_path` | — | **Required.** PEM CA bundle — all private certs in the dependency chain must be issued by this CA |
| `ATTESTATION_SERVER_REPORT_EVIDENCE_NITRONSM` | `report.evidence.nitronsm` | `false` | Enable Nitro NSM evidence (exclusive: cannot combine with others) |
| `ATTESTATION_SERVER_REPORT_EVIDENCE_NITROTPM` | `report.evidence.nitrotpm` | `false` | Enable Nitro TPM evidence |
| `ATTESTATION_SERVER_REPORT_EVIDENCE_SEVSNP` | `report.evidence.sevsnp` | `false` | Enable SEV-SNP evidence |
| `ATTESTATION_SERVER_REPORT_EVIDENCE_SEVSNP_VMPL` | `report.evidence.sevsnp_vmpl` | `0` | VMPL level for SEV-SNP attestation (0–3) |
| `ATTESTATION_SERVER_REPORT_EVIDENCE_TDX` | `report.evidence.tdx` | `false` | Enable Intel TDX evidence (exclusive: cannot combine with others) |
| `ATTESTATION_SERVER_TPM_ENABLED` | `tpm.enabled` | `false` | Enable generic TPM PCR reading via /dev/tpmrm0; auto-disabled if NitroNSM or NitroTPM evidence is enabled. **Note:** generic TPM PCR values are unattested (`TPM2_PCR_Read`) — they lack a hardware-signed quote. Integrity relies on the TEE's memory encryption protecting the OS. NitroNSM and NitroTPM PCRs are hardware-attested (embedded in the signed attestation document). A future revision may use `TPM2_Quote` for hardware-attested PCR values |
| `ATTESTATION_SERVER_TPM_ALGORITHM` | `tpm.algorithm` | `sha384` | Hash algorithm for TPM PCR values: `sha1`/`sha256`/`sha384`/`sha512` (case-insensitive) |
| `ATTESTATION_SERVER_REVOCATION_ENABLED` | `revocation.enabled` | `true` | Check TEE endorsement key CRLs. SEV-SNP CRLs are fetched from AMD KDS in the background when local SEV-SNP evidence is enabled or dependencies are configured; TDX uses go-tdx-guest's built-in Intel PCS collateral fetching |
| `ATTESTATION_SERVER_REVOCATION_REFRESH_INTERVAL` | `revocation.refresh_interval` | `12h` | How often to re-fetch CRLs in the background (SEV-SNP only; TDX checks are per-request via the library) |
| `ATTESTATION_SERVER_RATELIMIT_ENABLED` | `ratelimit.enabled` | `false` | Rate-limit edge requests (those without client certificate / XFCC header) |
| `ATTESTATION_SERVER_RATELIMIT_REQUESTS_PER_SECOND` | `ratelimit.requests_per_second` | `1` | Per-IP request rate for edge traffic |
| `ATTESTATION_SERVER_RATELIMIT_BURST` | `ratelimit.burst` | `1` | Burst allowance per IP |
| `ATTESTATION_SERVER_RATELIMIT_STALL_TIMEOUT` | `ratelimit.stall_timeout` | `10s` | Max time an over-limit request is stalled before receiving 429; IP extracted from `X-Envoy-Original-IP` > `X-Forwarded-For` > connection IP |
| `ATTESTATION_SERVER_SECURE_BOOT_ENFORCE` | `secure_boot.enforce` | `false` | Enforce UEFI Secure Boot; exit on startup if not enabled. UEFI secure boot detection is skipped when NitroNSM evidence is enabled (enclaves have no EFI firmware; boot integrity is proven by NSM PCR measurements) |
| `ATTESTATION_SERVER_REPORT_USER_DATA_ENV` | `report.user_data.env` | `[]` | Comma-separated environment variable names to include in report (unique) |
| `ATTESTATION_SERVER_DEPENDENCIES_ENDPOINTS` | `dependencies.endpoints` | `[]` | Comma-separated URLs of dependency attestation servers. HTTPS endpoints are verified against the private CA bundle (mTLS); HTTP endpoints are a design decision for transparent proxy configurations where Envoy diverts traffic through mTLS on non-loopback interfaces — the e2e encryption proof (XFCC fingerprint check) ensures the connection was mTLS-protected regardless of the URL scheme |
| `ATTESTATION_SERVER_ENDORSEMENTS_DNSSEC` | `endorsements.dnssec` | `false` | Require strict DNSSEC validation for endorsement URL hosts |
| `ATTESTATION_SERVER_ENDORSEMENTS_ALLOWED_DOMAINS` | `endorsements.allowed_domains` | `[]` | Comma-separated list of allowed endorsement hostnames (exact match). Empty = unrestricted. Applies to both own and dependency endorsement URLs |
| `ATTESTATION_SERVER_ENDORSEMENTS_CLIENT_TIMEOUT` | `endorsements.client.timeout` | `10s` | Overall timeout for fetching endorsement documents and cosign signatures (with retries) |
| `ATTESTATION_SERVER_ENDORSEMENTS_COSIGN_VERIFY` | `endorsements.cosign.verify` | `true` | Verify cosign signatures on endorsement documents using Sigstore public-good infrastructure |
| `ATTESTATION_SERVER_ENDORSEMENTS_COSIGN_URL_SUFFIX` | `endorsements.cosign.url_suffix` | `.sig` | Suffix appended to endorsement URL to fetch the cosign signature bundle |
| `ATTESTATION_SERVER_ENDORSEMENTS_COSIGN_TUF_CACHE_PATH` | `endorsements.cosign.tuf_cache_path` | — | Writable directory for Sigstore TUF metadata cache. Empty = in-memory only (no disk writes; background refresh every 24h). Set a path for disk-cached TUF root that survives restarts |
| `ATTESTATION_SERVER_ENDORSEMENTS_COSIGN_BUILD_SIGNER_URI` | `endorsements.cosign.build_signer.uri` | — | Exact match override for BuildSignerURI Fulcio OID (takes precedence over `uri_regex`) |
| `ATTESTATION_SERVER_ENDORSEMENTS_COSIGN_BUILD_SIGNER_URI_REGEX` | `endorsements.cosign.build_signer.uri_regex` | — | Regex match override for BuildSignerURI Fulcio OID (ignored if `uri` is set) |
| `ATTESTATION_SERVER_HTTP_ALLOW_PROXY` | `http.allow_proxy` | `false` | Honour `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` env vars for the server's outbound HTTP clients (endorsement/cosign fetches, SEV-SNP CRL fetches, dependency requests). Off by default; required in environments like AWS Nitro Enclaves where a vsock-proxy is the only egress path. TDX collateral fetching (go-tdx-guest) always honours proxy env vars via `http.DefaultTransport` regardless of this setting |
| `ATTESTATION_SERVER_HTTP_CACHE_SIZE` | `http.cache.size` | `100MiB` | Maximum memory for the shared HTTP fetch cache (endorsements + cosign signatures, ristretto) |
| `ATTESTATION_SERVER_HTTP_CACHE_DEFAULT_TTL` | `http.cache.default_ttl` | `1h` | Default cache TTL when response has no Cache-Control header (capped at 24h) |

List-typed environment variables (`ATTESTATION_SERVER_REPORT_USER_DATA_ENV`, `ATTESTATION_SERVER_DEPENDENCIES_ENDPOINTS`) support comma-separated values: `VAR=a,b,c`. Spaces around commas are trimmed.

## Logging conventions

- Use `log/slog` throughout; never use `fmt.Print*` or `log.*` for application logs.
- Log messages are short single sentences, **no initial capital, no trailing punctuation**.
- All structured details (IDs, values, errors) go in slog fields, not in the message string.
- Access logs (via the fiber middleware in `server.go`) include: `method`, `path`, `status`, `duration_ms`, `request_id`. Log level is INFO for 2xx/3xx, WARN for 4xx, ERROR for 5xx.
- Errors in log fields use key `"error"`.

## Code style

- All Go code must be `go fmt`-conformant. Always run `go fmt ./...` before committing.
- Use `github.com/goccy/go-json` everywhere instead of `encoding/json`. The attestation handler marshals report data with `json.MarshalWithOption(..., json.DisableHTMLEscape())` for the nonce digest, then embeds those exact bytes (via `json.RawMessage`) in the response to guarantee byte-for-byte consistency.
- **Fiber `UnsafeString` hazard**: Fiber's `c.Get()`, `c.Query()`, `c.IP()`, `c.Method()`, `c.Path()`, and similar methods return strings backed by fasthttp's reusable `RequestCtx` buffer (`UnsafeString`). These strings are only valid within the handler. If stored in a long-lived data structure (map key, struct field on the server, channel, etc.), the backing bytes are silently corrupted when fasthttp recycles the `RequestCtx` via `sync.Pool`. Use `strings.Clone()` before storing any Fiber context string beyond the handler lifetime. Operations that implicitly copy (JSON marshaling, string concatenation, `net/http.Header.Set`) are safe without cloning.
- **Fiber `c.UserContext()` hazard**: Fiber's `c.UserContext()` returns `context.Background()` — it is never cancelled on graceful shutdown. Do not pass it to functions that perform blocking operations (HTTP fetches with retry, rate limiter waits, etc.) because those operations will not be interrupted when the server shuts down. Use `s.shutdownCtx()` instead, which returns the server's lifecycle context (set in `Run()`), falling back to `context.Background()` for pre-`Run` callers and unit tests.

## TEE package public API

Each TEE package (`pkg/nitro`, `pkg/sevsnp`, `pkg/tdx`) exposes a consistent set of public functions:

| Function | Purpose |
|----------|---------|
| `GetEvidence` | Retrieve raw evidence from the device without verification |
| `VerifyEvidence` | Verify a raw evidence blob (standalone, no device needed) |
| `Attest` | Combined retrieval + verification (calls `GetEvidence` then `VerifyEvidence`) |

The `sevsnp` package additionally exports `SplitEvidence` (split a blob into raw report + certificate table), `ReportSize` (the raw report size constant), and the `RevocationChecker` function type.

Both `sevsnp.VerifyEvidence` and `tdx.VerifyEvidence` accept optional variadic parameters for revocation checking. These are omitted by standalone callers (backward-compatible) and provided by the attestation server when revocation is enabled:

- `sevsnp.VerifyEvidence(blob, reportData, now, checkers ...RevocationChecker)` — optional callback checking the endorsement key (VCEK/VLEK) certificate against a CRL
- `tdx.VerifyEvidence(rawQuote, reportData, now, opts ...VerifyOpt)` — `VerifyOpt` contains `CheckRevocations bool` (enables go-tdx-guest Intel PCS collateral fetching and CRL checking) and `Getter trust.HTTPSGetter` (overrides the HTTP client used for collateral fetching; the server provides a caching getter backed by the shared ristretto cache to avoid per-request Intel PCS round-trips)

## SEV-SNP workarounds (pkg/sevsnp)

`VerifyEvidence` implements its own verification flow instead of using `verify.SnpAttestation` from go-sev-guest (v0.14.1) to work around three library issues affecting cloud platforms like AWS Nitro. The workarounds are documented in the function's doc comment. Key constraints:

- **Do not replace with `verify.SnpAttestation`** — it will fail on AWS due to unknown policy bits, malformed ASK/ARK certs in the certificate table, and proto round-trip breaking the signature.
- **Do not remove `reportToProto`** — it sanitises policy bits for parsing while preserving the original value for the API response.
- **Do not remove `trustedRoots`** — these pre-parsed AMD root certs bypass the malformed certificate table entries.
- These workarounds can be revisited when go-sev-guest ships a release including [PR #181](https://github.com/google/go-sev-guest/pull/181) and fixes certificate table handling.

### SEV-SNP performance: certificate buffer caching

`GetEvidence` (and by extension `Attest`) caches the certificate table size after the first call. The go-sev-guest library's `GetRawExtendedReportAtVmpl` performs two ioctls per call (probe for cert buffer size + actual attestation), and the library's self-throttle inserts a ~2 s sleep between ioctls. By caching the cert size, subsequent calls use a single ioctl via `getExtendedReportDirect`, eliminating one PSP firmware round-trip and one throttle delay. The startup self-attestation `Attest` call primes this cache.

## Attestation handler

The handler calls `Attest` on each configured TEE device. Each `Attest` method retrieves evidence and verifies it internally using the same `VerifyEvidence` function that external verifiers would use, catching corrupted device output or driver bugs before they reach callers. The handler receives the verified parsed result alongside the raw blob and does not perform any additional verification.

The `request_id` (a `crypto/rand`-backed UUID) is included in the nonce-bound `AttestationReportData` for audit trail purposes. Since it is cryptographically random, an attacker cannot predict it to pre-compute attestation reports. Verifiers recompute the nonce from the response data (which includes the request_id), not from a pre-shared value.

### Startup self-attestation

During server initialization (`NewServer`), each opened TEE device is self-attested by calling `Attest` with random nonce/report data. The parsed results are captured in `parsedSelfAttestation` for endorsement validation. This catches environment issues early (tampered firmware, broken devices), primes the SEV-SNP certificate buffer cache, and provides the baseline measurements for endorsement checks. The server exits on any self-attestation failure.

## Transitive dependency attestation

When `dependencies.endpoints` is configured, the attestation handler fetches and verifies attestation reports from all dependency endpoints in parallel before collecting its own evidence. Each dependency receives the same nonce (`x-attestation-nonce` header) derived from the local `AttestationReportData` digest, and the same `X-Request-Id` for traceability.

### Verification flow

Each dependency response is parsed as an `AttestationReport`, verified (nonce binding + cryptographic evidence verification for all known TEE types including NitroTPM→SEV-SNP chaining), and embedded as `json.RawMessage` in the `dependencies` field. Raw bytes are stored instead of re-marshaled structs to avoid `goccy/go-json` zero-copy string issues.

After cryptographic verification, the client certificate fingerprint check enforces end-to-end encryption: the dependency's `data.tls.client` must be present and match the SHA-256 fingerprint of our private certificate (which is used as the client cert for outgoing mTLS connections). If missing or mismatched, a descriptive error is logged and an opaque error is returned to the caller.

The dependency HTTP client verifies server certificates against the private CA bundle (`tls.private.ca_path`) and presents the private certificate as the TLS client cert. All private certificates in the dependency chain must be issued by the same CA — Envoy only populates the XFCC header (which provides the client cert fingerprint) when the client cert passes CA verification.

### End-to-end encryption proof

Every attestation response must prove end-to-end encryption via at least one of:
- `data.tls.client` — XFCC-forwarded client cert fingerprint (service-to-service mTLS within the dependency chain)
- `data.tls.public` — public certificate fingerprint (external Internet clients at the first ingress hop, without client certificates)

If neither is present, the handler returns 400. This ensures the attestation evidence is always bound to a TLS channel that the verifier can reason about.

### Cycle detection

Dependency cycles are detected via the `X-Attestation-Path` header, which carries a comma-separated list of service identities visited along the dependency chain. Each server appends its own identity before forwarding to dependencies. If a server finds its identity already in the path, it returns 409 Conflict, which propagates up the chain.

The service identity is deterministic: `SHA-256(json(build_info) || cert_subject || cert_SANs)`, using the private cert (or public cert as fallback). This ensures replicas of the same service share the same identity (cycles are between services, not processes), while different services produce distinct identities. SANs are included because SPIFFE SVIDs may have empty subjects.

### HTTP client hardening

The dependency HTTP client is hardened against slowloris-like attacks with per-phase timeouts (dial: 5s, TLS handshake: 10s, response headers: 15s, overall: 30s), a 4 MiB response body limit, and disabled keep-alives.

### Certificate hot-reload

Certificate files (public cert/key, private cert/key, and private CA bundle) are hot-reloaded via fsnotify directory watchers. Since `validateTLSConfig` requires the CA bundle to be in the same directory as the private cert/key, a single watcher covers all three files. On reload, the private cert, CA bundle, and computed fingerprints are swapped atomically under the same `sync.RWMutex` (`tlsCertificates.mu`) that protects concurrent reads from request handlers and the dependency HTTP client.

The CA bundle loader (`loadCABundle`) cryptographically verifies self-signed certificates using `x509.CheckSignatureFrom`, rejecting certificates whose issuer matches subject but whose signature is invalid. SHA-1 CAs are hard-rejected (Go 1.18+ enforces this).

### TLS version requirements

The dependency mTLS HTTP client enforces TLS 1.3 minimum. The endorsement/cosign fetch client uses TLS 1.2 minimum since public CDNs may not yet support TLS 1.3.

## Rate limiting

When `ratelimit.enabled` is true, a per-IP rate limiting handler is chained on the attestation endpoint (`/api/v1/attestation`) to protect the server from resource exhaustion by edge clients. It is scoped to this endpoint because attestation involves blocking TEE hardware operations; future lightweight endpoints should not inherit this restriction. The handler only applies to requests **without** an `x-forwarded-client-cert` (XFCC) header — service-to-service mTLS traffic is never rate-limited.

Client IP is extracted with priority: `X-Envoy-Original-IP` header > first entry in `X-Forwarded-For` > connection IP. Extracted values are validated as IP addresses to prevent header injection from creating unbounded map entries.

Over-limit requests are **stalled** (blocked in a FIFO queue) up to `ratelimit.stall_timeout` before receiving HTTP 429. This avoids immediately rejecting burst traffic while still bounding resource consumption. Per-IP rate limiter entries are cleaned up in a background goroutine when idle for 2× the stall timeout.

## Certificate revocation checking

When `revocation.enabled` is true (the default), the server checks TEE endorsement key certificates against Certificate Revocation Lists. CRL fetching is conditional on configuration:

- **SEV-SNP**: A background goroutine fetches AMD KDS CRLs for all supported product lines (Milan, Genoa, Turin) at `revocation.refresh_interval` (default 12h). Both VCEK and VLEK CRLs are fetched. CRLs are initialized when local SEV-SNP evidence is enabled **or** when dependency endpoints are configured (dependencies may include SEV-SNP evidence requiring revocation checks). The `crlCache` stores parsed `x509.RevocationList` entries and checks endorsement key serial numbers during verification. Design is **fail-open**: if no CRL data is available yet (first fetch still pending or failed), certificates are accepted. CRL fetches use the server's `fetchHTTPClient()` and honour `http.allow_proxy`.
- **TDX**: Revocation checking is delegated to go-tdx-guest's built-in Intel PCS collateral fetching (`CheckRevocations: true, GetCollateral: true`). The server provides a `cachedHTTPSGetter` (via `VerifyOpt.Getter`) that caches Intel PCS responses (TCB info, QE identity, PCK CRL, Root CA CRL) in the shared ristretto cache. On cache hit, no network calls are made. TTL is derived from response `Cache-Control` headers; Intel PCS currently returns no cache headers, so `http.cache.default_ttl` applies. The go-tdx-guest library still validates `NextUpdate` expiry on all collateral, so stale cached data is rejected. The cached getter uses the server's `fetchHTTPClient()` and honours `http.allow_proxy`.
- **Nitro**: No CRL mechanism exists (ephemeral certificate chains per attestation; revocation is handled by AWS at the hypervisor level).

When disabled, a startup warning is logged: "certificate revocation checking is disabled, revoked TEE endorsement keys will be accepted".

## Error information leakage

The server returns opaque `"internal error"` messages for all 5xx responses to prevent leaking device errors, file paths, and firmware codes to external callers. The real error is logged at ERROR level with `request_id` for debugging. 4xx error messages are preserved since they describe client-fixable problems (bad nonce, missing cert, etc.).

## XFCC header validation

The server rejects requests with multiple comma-separated XFCC entries (HTTP 400). The design assumes a single forwarded client certificate entry per request, enforcing direct end-to-end encryption without proxy intermediaries that might strip or replace the client cert.

## Endorsement domain allowlist

When `endorsements.allowed_domains` is configured (non-empty), endorsement document URLs are checked against the allowlist before fetching. Matching is **exact hostname** (case-insensitive) — subdomain matching is not supported, each host must be listed explicitly. The check applies to both own endorsement URLs and dependency endorsement URLs. An empty allowlist logs a startup warning since dependency reports can contain attacker-controlled URLs.

## Endorsement validation

When `paths.endorsements` is configured with endorsement URLs, the server fetches and validates endorsement documents containing golden measurement values for each configured evidence type.

### Endorsement document format

A JSON object with evidence-type keys (`nitronsm`, `nitrotpm`, `sevsnp`, `tdx`, `tpm`):
- **NitroNSM/NitroTPM/TPM**: `{"PCR0": "hex", ...}` or `{"0": "hex", ...}` — a flat map of PCR register indices to hex-encoded measurement values. Keys use either `"PCRN"` or `"N"` format (where N is 0–24). Values must be non-empty valid hex strings. These constraints are enforced at JSON parse time (`PCRGoldenValues.UnmarshalJSON`) so that downstream comparison functions (`comparePCRs`, `validateTPMMeasurements`) can trust the values are well-formed. `PCRGoldenValues` is `map[int]hexbytes.Bytes`, matching the type used for TPM PCR values throughout the codebase.
- **SEV-SNP**: a single hex string (96 chars = 384-bit launch measurement)
- **TDX**: `{"MRTD": "hex", "RTMR0": "hex", "RTMR1": "hex", "RTMR2": "hex"}` (all optional)

### Startup validation

During `NewServer()`, after self-attestation (which now captures parsed results instead of discarding them), the server:
1. Fetches endorsement documents from all configured URLs in parallel with retry
2. Verifies all documents are byte-for-byte identical
3. Validates each configured evidence type against the golden measurements
4. Exits on any failure (missing measurements, mismatches, fetch errors)

### Per-request revalidation

Before collecting own evidence in `handleAttestation`, the handler calls `validateOwnEndorsements`. On cache hit this is fast (pointer lookup + comparison). On cache miss (TTL expired) it re-fetches and revalidates. If revalidation fails, the handler returns 500 but the server stays up and self-heals when endorsements become available.

### Dependency endorsement validation

After cryptographically verifying a dependency's attestation report, the server also validates the dependency's endorsement URLs (from `reportData.Endorsements`) against the evidence in the dependency report. The shared ristretto cache is used across own and dependency endorsements.

### Endorsement HTTP client

Uses system/Mozilla root CAs (via `golang.org/x/crypto/x509roots/fallback` blank import). Hardened with per-phase timeouts (dial 3s, TLS 5s, headers 5s), 1 MiB body limit, disabled keep-alives. When `endorsements.dnssec` is enabled, the `pkg/dnssec` resolver performs cryptographic DNSSEC chain-of-trust validation for endorsement URL hosts before fetching. The resolver reads upstream nameservers from `/etc/resolv.conf` (falling back to `127.0.0.53:53` then `127.0.0.1:53`), sets the CD bit to get raw RRSIG records from any resolver, and validates the full delegation chain from zone to root against embedded IANA root KSK trust anchors (KSK-2017 tag 20326, KSK-2024 tag 38696). It does not rely on the upstream resolver's AD flag.

### Endorsement cache

Uses `dgraph-io/ristretto/v2` with URL-string keys in a shared `fetcherCache` (stores both `*EndorsementDocument` and `*cosignResult` values — endorsement URLs and signature URLs don't collide). When multiple URLs resolve to the same document (verified byte-for-byte), the same pointer is stored under all URL keys (cost charged once). TTL is derived from Cache-Control `max-age` (capped at 24h, default `http.cache.default_ttl`).

Endorsement URLs are tied to CI commit hashes with immutable content. Extended caching (up to 24h) is by design — measurement changes require new commits and new URLs. The TTL cap and per-request revalidation on cache miss provide eventual consistency.

### Cosign endorsement verification

When `endorsements.cosign.verify` is enabled (default: `true`), the server verifies cosign signatures on endorsement documents using the Sigstore public-good infrastructure (Fulcio + Rekor). Only Cosign v3 protobuf bundles (from `cosign sign-blob --bundle`) are supported.

#### Verification flow

After fetching an endorsement document, a corresponding signature bundle is fetched from the same URL with the configured suffix appended (default `.sig`). The single `endorsements.client.timeout` covers both fetches (not extended for the signature). Signature bundles undergo the same multi-URL byte-for-byte identity check as endorsement documents.

Verification performs a full online Rekor inclusion proof check using an auto-updating Sigstore TUF client (`root.NewLiveTrustedRoot`) that refreshes roots in the background. Upon successful verification, Fulcio OID extensions are extracted from the signing certificate and validated against the server's `BuildInfo`:

- **All OID fields** except BuildSignerURI and BuildSignerDigest: exact match against corresponding BuildInfo field
- **BuildSignerURI**: matched against `endorsements.cosign.build_signer.uri` (exact) or `.uri_regex` (regex) if configured; `.uri` takes precedence if both set (warning logged). When neither is configured, exact match against `BuildInfo.BuildSignerURI`
- **BuildSignerDigest**: exact match against `BuildInfo.BuildSignerDigest` when no `build_signer` config is set; **skipped** when any `build_signer` config is set (digest changes per-commit)
- **DeploymentEnvironment**: not checked (no standard Fulcio OID)
- Fulcio's `SourceRepositoryVisibilityAtSigning` maps to BuildInfo's `SourceRepositoryVisibility`

When cosign verification is enabled, the server requires endorsement URLs to be configured (non-empty `paths.endorsements`); startup fails otherwise. Dependency attestation reports are also required to include non-empty endorsement URL lists — a dependency with no endorsement URLs is rejected.

Cosign verification is applied to both own endorsements and dependency endorsements. For dependencies, OIDs are validated against the dependency's `BuildInfo` from its attestation report.

Verified cosign results are cached alongside endorsement documents in the shared `fetcherCache`. On cache hit for both, zero network calls happen. On cache miss for either, both are re-fetched together.

## Testing

Tests use the standard `testing` package (no testify), table-driven subtests with `t.Run`, and no mocking of hardware interfaces.

### Fuzz tests

Security-sensitive parsers have `Fuzz*` tests (Go native fuzzing) that verify no panics on arbitrary input. Run seed corpus with `go test ./...`; run actual fuzzing with e.g. `go test ./internal/ -fuzz=FuzzExtractXFCCHash -fuzztime=30s`. Current fuzz targets:

- `FuzzExtractXFCCHash`, `FuzzIsValidHexFingerprint` — untrusted XFCC header parsing (`internal/attestation_test.go`)
- `FuzzParseCacheTTL`, `FuzzParseByteSize`, `FuzzPCRGoldenValues_UnmarshalJSON` — untrusted HTTP headers, config input, endorsement JSON (`internal/endorsements_test.go`)
- `FuzzBytes_UnmarshalJSON`, `FuzzBytes_RoundTrip` — hex JSON deserialization and marshal↔unmarshal consistency (`pkg/hexbytes/hexbytes_test.go`)

### Live DNSSEC tests

`pkg/dnssec/dnssec_test.go` includes live tests that perform real DNSSEC chain-of-trust validation against public domains (ietf.org, internetsociety.org). Gated behind an environment variable:

```sh
DNSSEC_LIVE_TEST=1 go test ./pkg/dnssec/ -run TestLive -v
```

### Attestation verification fixtures

Each TEE package has a `testdata/` directory with JSON fixtures captured from real hardware. All fixtures are the raw `AttestationReport` JSON as returned by the attestation handler (pretty-printed):

```json
{
  "evidence": [{"kind": "...", "blob": "base64...", "data": {...}}],
  "data": { ... AttestationReportData ... }
}
```

The clock value for certificate validation is extracted from `data.timestamp` (RFC 3339, truncated to seconds). The nonce/report_data is derived as `SHA-512(compact(data))`. Each verification test also cross-checks that `NewAttestationData` produces JSON matching the fixture's `evidence[0].data`.

Chained (composite) attestation fixtures contain multiple evidence entries. For NitroTPM+SEV-SNP, the SEV-SNP report_data is `SHA-512(nitroTPMBlob)` instead of the raw digest, binding both proofs to the same request. The chained test in `internal/attestation_test.go` verifies both links and confirms the chain breaks if the unchained digest is used.

Fixture files:
- `pkg/nitro/testdata/nitronsm_attestation.json`
- `pkg/nitro/testdata/nitrotpm_attestation.json`
- `pkg/sevsnp/testdata/sevsnp_attestation_aws.json`
- `pkg/sevsnp/testdata/sevsnp_attestation_gcp.json`
- `pkg/tdx/testdata/tdx_attestation.json`
- `internal/testdata/nitrotpm_sevsnp_attestation.json` (chained NitroTPM → SEV-SNP)
- `internal/testdata/dependencies_attestation.json` (diamond dependency graph: A → {B, C}, B → C with NitroTPM+SEV-SNP, TDX, and SEV-SNP evidence across services; each dependency has client cert matching caller's private cert)

## Nix build

The project provides a Nix flake for reproducible, hermetic builds. Inputs are pinned to exact commit hashes in `flake.nix` and locked in `flake.lock`. The flake builds a statically linked binary (`CGO_ENABLED=0`, stripped with `-s -w`). Tests run during the build (live DNSSEC tests skip themselves in the sandbox since `DNSSEC_LIVE_TEST` is unset; all other tests use fixtures). The source filter includes `*.go`, `*.json` (test fixtures), `go.mod`, and `go.sum` — changes to docs or config do not trigger a rebuild. Runtime closure references to nixpkgs-patched `mailcap`, `iana-etc`, and `tzdata` store paths are stripped via `removeReferencesTo` (the server does not use `mime.TypeByExtension`, `net.LookupPort`, or `time.LoadLocation`), keeping the Docker image minimal.

The flake exposes two package targets:
- `default` / `attestation-server` — the statically linked binary
- `docker-image` — a minimal OCI image (`streamLayeredImage`) containing the binary (TLS root CAs are compiled in via `x509roots/fallback`) and a `/usr/local/bin/attestation-server` symlink for use in multi-stage Docker builds, used by the release workflow and downstream Nitro TEE EIF builds

The flake is designed to be referenced as a GitHub source input from downstream TEE image repositories:

```nix
# In the downstream flake:
inputs.attestation-server.url = "github:eternisai/attestation-server";
# Binary: attestation-server.packages.x86_64-linux.default -> $out/bin/attestation-server
```

When `go.mod` or `go.sum` change, the `vendorHash` in `flake.nix` must be updated. Set it to `lib.fakeHash`, build, and use the hash from the error message.

## CI/CD

- **CI** (`.github/workflows/ci.yml`) — runs on pushes to non-main branches: `go fmt` check, `go test` with `DNSSEC_LIVE_TEST=1`, `go vet`, `go build`.
- **Nix Build** (`.github/workflows/nix-build.yml`) — runs on PRs targeting main: `nix build .#docker-image` (runs offline test suite via `doCheck`). Catches flake breakage before merge.
- Branch protection on main should require both `Test` and `Build` status checks to pass.
- **Release** (`.github/workflows/release.yml`) — runs on push to main, three sequential jobs:
  1. **Build** — `nix build .#docker-image` (runs tests via `doCheck`), uploads image tarball as artifact
  2. **Release** — Release Please creates/updates a release PR; on merge, creates a GitHub Release + tag
  3. **Docker** — loads the pre-built image, pushes to `ghcr.io/eternisai/attestation-server:<tag>`, cosigns with keyless Sigstore (Fulcio + Rekor via GitHub OIDC)

Release Please is configured via `release-please-config.json` and `.release-please-manifest.json`. It parses Conventional Commit messages to determine version bumps and generate changelogs.

## Development

```sh
# build
go build ./...

# run locally (uses config/config.toml by default)
go run .

# run locally (with env vars)
ATTESTATION_SERVER_SERVER_PORT=8187 go run .

# run tests
go test ./...

# format
go fmt ./...
```

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages:
`feat:`, `fix:`, `chore:`, `refactor:`, `docs:`, `test:`, etc.
