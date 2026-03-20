# attestation-server

A Go HTTP server for serving TEE (Trusted Execution Environment) attestation documents.

## Tech stack

- **CLI/config**: [spf13/cobra](https://github.com/spf13/cobra) for CLI, [spf13/viper](https://github.com/spf13/viper) for configuration
- **HTTP**: [go-fiber v2](https://github.com/gofiber/fiber) with `requestid` middleware
- **Logging**: standard `log/slog`, JSON format on stdout

## Project structure

```
main.go              # entry point
cmd/root.go          # cobra root command; initializes config, logger, and starts server
internal/config.go   # Config struct and LoadConfig() (package app)
internal/logging.go  # NewLogger() (package app)
internal/server.go   # Server, NewServer(), Run() (package app)
internal/types.go    # BuildInfo struct (package app)
```

## Configuration

All configuration is via environment variables. Some options also have CLI flag equivalents (flags take precedence over env vars when explicitly set).

| Env var      | Flag     | Default     | Description              |
|--------------|----------|-------------|--------------------------|
| `BIND_HOST`  | `--host`         | `0.0.0.0`   | HTTP bind host           |
| `BIND_PORT`  | `--port`         | `8187`      | HTTP bind port           |
| `LOG_FORMAT` | `--log-format`   | `json`      | Log format: `json`/`text`|
| `LOG_LEVEL`  | `--log-level`    | `info`      | Log level: `debug`/`info`/`warn`/`error` |
| `BUILD_INFO_PATH` | `--build-info-path` | `/etc/build-info.json` | Path to build information file |
| `ENDORSEMENTS_PATH` | `--endorsements-path` | `/etc/endorsements.json` | Path to endorsements URL list file |

## Logging conventions

- Use `log/slog` throughout; never use `fmt.Print*` or `log.*` for application logs.
- Log messages are short single sentences, **no initial capital, no trailing punctuation**.
- All structured details (IDs, values, errors) go in slog fields, not in the message string.
- Access logs (via the fiber middleware in `server.go`) include: `method`, `path`, `status`, `duration_ms`, `request_id`. Log level is INFO for 2xx/3xx, WARN for 4xx, ERROR for 5xx.
- Errors in log fields use key `"error"`.

## Development

```sh
# build
go build ./...

# run locally
go run . --port 8187

# run tests
go test ./...
```

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages:
`feat:`, `fix:`, `chore:`, `refactor:`, `docs:`, `test:`, etc.
