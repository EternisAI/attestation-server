package app

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"regexp"
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
	ReportEvidence     EvidenceConfig
	ReportEnvVars      []string
}

// EvidenceConfig holds the evidence type flags.
type EvidenceConfig struct {
	NitroNSM   bool
	NitroTPM   bool
	SEVSNP     bool
	SEVSNPVMPL int
}

// LoadConfig reads configuration from viper (config file / env vars / pflags / defaults).
func LoadConfig() (*Config, error) {
	evidence := EvidenceConfig{
		NitroNSM:   viper.GetBool("report.evidence.nitronsm"),
		NitroTPM:   viper.GetBool("report.evidence.nitrotpm"),
		SEVSNP:     viper.GetBool("report.evidence.sevsnp"),
		SEVSNPVMPL: viper.GetInt("report.evidence.sevsnp_vmpl"),
	}
	if err := validateEvidence(evidence); err != nil {
		return nil, err
	}
	envVars := viper.GetStringSlice("report.user_data.env")
	if err := validateEnvNames(envVars); err != nil {
		return nil, err
	}

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
		ReportEvidence:     evidence,
		ReportEnvVars:      envVars,
	}, nil
}

func validateEvidence(e EvidenceConfig) error {
	if !e.NitroNSM && !e.NitroTPM && !e.SEVSNP {
		return fmt.Errorf("report.evidence: at least one evidence type must be enabled")
	}
	if e.NitroNSM && (e.NitroTPM || e.SEVSNP) {
		return fmt.Errorf("report.evidence: nitronsm cannot be combined with other evidence types")
	}
	return nil
}

var envNameRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func validateEnvNames(names []string) error {
	if dup := findDuplicate(names); dup != "" {
		return fmt.Errorf("report.user_data.env contains duplicate value %q", dup)
	}
	for _, n := range names {
		if !envNameRe.MatchString(n) {
			return fmt.Errorf("report.user_data.env contains invalid environment variable name %q", n)
		}
	}
	return nil
}

func findDuplicate(vals []string) string {
	seen := make(map[string]bool, len(vals))
	for _, v := range vals {
		if seen[v] {
			return v
		}
		seen[v] = true
	}
	return ""
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
