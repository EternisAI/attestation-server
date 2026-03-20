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

// LoadConfig reads configuration from viper (config file / env vars / pflags / defaults).
func LoadConfig() *Config {
	return &Config{
		BindHost:           viper.GetString("server.host"),
		BindPort:           viper.GetInt("server.port"),
		LogFormat:          viper.GetString("log.format"),
		LogLevel:           parseLogLevel(viper.GetString("log.level")),
		BuildInfoPath:      viper.GetString("paths.build_info"),
		EndorsementsPath:   viper.GetString("paths.endorsements"),
		PublicTLSCertPath:  absPath(viper.GetString("tls.public.cert_path")),
		PublicTLSKeyPath:   absPath(viper.GetString("tls.public.key_path")),
		PrivateTLSCertPath: absPath(viper.GetString("tls.private.cert_path")),
		PrivateTLSKeyPath:  absPath(viper.GetString("tls.private.key_path")),
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
