package app

import (
	"log/slog"
	"strings"

	"github.com/spf13/viper"
)

// Config holds the resolved server configuration.
type Config struct {
	BindHost  string
	BindPort  int
	LogFormat string
	LogLevel  slog.Level
}

// LoadConfig reads configuration from viper (env vars / pflags / defaults).
func LoadConfig() *Config {
	return &Config{
		BindHost:  viper.GetString("bind_host"),
		BindPort:  viper.GetInt("bind_port"),
		LogFormat: viper.GetString("log_format"),
		LogLevel:  parseLogLevel(viper.GetString("log_level")),
	}
}

func parseLogLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
