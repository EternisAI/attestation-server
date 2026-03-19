package app

import (
	"log/slog"
	"os"
)

// NewLogger creates a slog.Logger based on the supplied configuration.
// Format defaults to JSON; pass LOG_FORMAT=text for human-readable output.
func NewLogger(cfg *Config) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}

	var handler slog.Handler
	if cfg.LogFormat == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}
