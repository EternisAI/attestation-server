package app

import (
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// Config holds the resolved server configuration.
type Config struct {
	BindHost           string
	BindPort           int
	LogFormat          string
	LogLevel           slog.Level
	BuildInfoPath      string
	EndorsementsPath   string
	PublicTLSCertPath  string
	PublicTLSKeyPath   string
	PrivateTLSCertPath string
	PrivateTLSKeyPath  string
}

// LoadConfig reads configuration from viper (env vars / pflags / defaults).
func LoadConfig() *Config {
	return &Config{
		BindHost:           viper.GetString("bind_host"),
		BindPort:           viper.GetInt("bind_port"),
		LogFormat:          viper.GetString("log_format"),
		LogLevel:           parseLogLevel(viper.GetString("log_level")),
		BuildInfoPath:      viper.GetString("build_info_path"),
		EndorsementsPath:   viper.GetString("endorsements_path"),
		PublicTLSCertPath:  absPath(viper.GetString("public_tls_cert_path")),
		PublicTLSKeyPath:   absPath(viper.GetString("public_tls_key_path")),
		PrivateTLSCertPath: absPath(viper.GetString("private_tls_cert_path")),
		PrivateTLSKeyPath:  absPath(viper.GetString("private_tls_key_path")),
	}
}

func absPath(p string) string {
	if p == "" {
		return ""
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
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
