# attestation-server

A Go HTTP server for serving TEE (Trusted Execution Environment) attestation documents.

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
internal/logging.go        # NewLogger() (package app)
internal/server.go         # Server, NewServer(), Run() (package app)
internal/tls.go            # TLS certificate loading and hot-reload (package app)
internal/types.go          # BuildInfo, AttestationReport, AttestationReportData, and other shared structs (package app)
pkg/nitro/nitro.go         # Shared Nitro attestation: COSE_Sign1 verification, cert chain validation, embedded AWS Nitro root CA (package nitro)
pkg/nitro/nsm.go           # NSM device access and attestation via /dev/nsm (package nitro)
pkg/nitro/tpm.go           # NitroTPM device access and attestation via raw TPM2 protocol over /dev/tpm0 (package nitro)
pkg/sevsnp/sevsnp.go       # SEV-SNP device access, attestation via go-sev-guest, signature verification, report parsing (package sevsnp)
pkg/tdx/tdx.go             # Intel TDX device access, attestation via go-tdx-guest, quote verification, report parsing (package tdx)
pkg/tpm/tpm.go             # Generic TPM PCR reading via google/go-tpm over /dev/tpmrm0 (package tpm)
config/config.toml         # default configuration file
```

## Configuration

Configuration is loaded via a TOML config file, environment variables, and CLI flags. Priority (highest to lowest): CLI flags > env vars > config file > defaults.

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
host = "0.0.0.0"
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

[secure_boot]
enforce = false

[tls.public]
cert_path = ""
key_path  = ""

[tls.private]
cert_path = ""
key_path  = ""
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
| `ATTESTATION_SERVER_SERVER_HOST` | `server.host` | `0.0.0.0` | HTTP bind host |
| `ATTESTATION_SERVER_SERVER_PORT` | `server.port` | `8187` | HTTP bind port |
| `ATTESTATION_SERVER_PATHS_BUILD_INFO` | `paths.build_info` | `/etc/build-info.json` | Path to build information file |
| `ATTESTATION_SERVER_PATHS_ENDORSEMENTS` | `paths.endorsements` | `/etc/endorsements.json` | Path to endorsements URL list file |
| `ATTESTATION_SERVER_TLS_PUBLIC_CERT_PATH` | `tls.public.cert_path` | — | Path to public TLS certificate (PEM) |
| `ATTESTATION_SERVER_TLS_PUBLIC_KEY_PATH` | `tls.public.key_path` | — | Path to public TLS private key (PEM) |
| `ATTESTATION_SERVER_TLS_PRIVATE_CERT_PATH` | `tls.private.cert_path` | — | Path to private TLS certificate (PEM) |
| `ATTESTATION_SERVER_TLS_PRIVATE_KEY_PATH` | `tls.private.key_path` | — | Path to private TLS private key (PEM) |
| `ATTESTATION_SERVER_REPORT_EVIDENCE_NITRONSM` | `report.evidence.nitronsm` | `false` | Enable Nitro NSM evidence (exclusive: cannot combine with others) |
| `ATTESTATION_SERVER_REPORT_EVIDENCE_NITROTPM` | `report.evidence.nitrotpm` | `false` | Enable Nitro TPM evidence |
| `ATTESTATION_SERVER_REPORT_EVIDENCE_SEVSNP` | `report.evidence.sevsnp` | `false` | Enable SEV-SNP evidence |
| `ATTESTATION_SERVER_REPORT_EVIDENCE_SEVSNP_VMPL` | `report.evidence.sevsnp_vmpl` | `0` | VMPL level for SEV-SNP attestation (0–3) |
| `ATTESTATION_SERVER_REPORT_EVIDENCE_TDX` | `report.evidence.tdx` | `false` | Enable Intel TDX evidence (exclusive: cannot combine with others) |
| `ATTESTATION_SERVER_TPM_ENABLED` | `tpm.enabled` | `false` | Enable generic TPM PCR reading via /dev/tpmrm0; auto-disabled if NitroNSM or NitroTPM evidence is enabled |
| `ATTESTATION_SERVER_TPM_ALGORITHM` | `tpm.algorithm` | `sha384` | Hash algorithm for TPM PCR values: `sha1`/`sha256`/`sha384`/`sha512` (case-insensitive) |
| `ATTESTATION_SERVER_SECURE_BOOT_ENFORCE` | `secure_boot.enforce` | `false` | Enforce UEFI Secure Boot; exit on startup if not enabled. UEFI secure boot detection is skipped when NitroNSM evidence is enabled (enclaves have no EFI firmware; boot integrity is proven by NSM PCR measurements) |
| `ATTESTATION_SERVER_REPORT_USER_DATA_ENV` | `report.user_data.env` | `[]` | Environment variable names to include in report (unique) |

## Logging conventions

- Use `log/slog` throughout; never use `fmt.Print*` or `log.*` for application logs.
- Log messages are short single sentences, **no initial capital, no trailing punctuation**.
- All structured details (IDs, values, errors) go in slog fields, not in the message string.
- Access logs (via the fiber middleware in `server.go`) include: `method`, `path`, `status`, `duration_ms`, `request_id`. Log level is INFO for 2xx/3xx, WARN for 4xx, ERROR for 5xx.
- Errors in log fields use key `"error"`.

## Code style

- All Go code must be `go fmt`-conformant. Always run `go fmt ./...` before committing.
- Use `github.com/goccy/go-json` everywhere instead of `encoding/json`. The attestation handler marshals report data with `json.MarshalWithOption(..., json.DisableHTMLEscape())` for the nonce digest, then embeds those exact bytes (via `json.RawMessage`) in the response to guarantee byte-for-byte consistency.

## SEV-SNP workarounds (pkg/sevsnp)

`VerifyAttestation` implements its own verification flow instead of using `verify.SnpAttestation` from go-sev-guest (v0.14.1) to work around three library issues affecting cloud platforms like AWS Nitro. The workarounds are documented in the function's doc comment. Key constraints:

- **Do not replace with `verify.SnpAttestation`** — it will fail on AWS due to unknown policy bits, malformed ASK/ARK certs in the certificate table, and proto round-trip breaking the signature.
- **Do not remove `reportToProto`** — it sanitises policy bits for parsing while preserving the original value for the API response.
- **Do not remove `trustedRoots`** — these pre-parsed AMD root certs bypass the malformed certificate table entries.
- These workarounds can be revisited when go-sev-guest ships a release including [PR #181](https://github.com/google/go-sev-guest/pull/181) and fixes certificate table handling.

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
