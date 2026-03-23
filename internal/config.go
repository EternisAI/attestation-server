package app

import (
	"fmt"
	"log/slog"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/spf13/viper"
)

// Config holds the resolved server configuration.
type Config struct {
	BindHost                 string
	BindPort                 int
	LogFormat                string
	LogLevel                 slog.Level
	BuildInfoPath            string
	EndorsementsPath         string
	PublicTLSCertPath        string
	PublicTLSKeyPath         string
	PrivateTLSCertPath       string
	PrivateTLSKeyPath        string
	PrivateTLSCAPath         string
	ReportEvidence           EvidenceConfig
	ReportEnvVars            []string
	SecureBootEnforce        bool
	TPM                      TPMConfig
	DependencyEndpoints      []*url.URL
	EndorsementDNSSEC        bool
	EndorsementClientTimeout time.Duration
	EndorsementCacheSize     int64
}

// TPMConfig holds the configuration for generic TPM PCR reading.
type TPMConfig struct {
	Enabled       bool
	Algorithm     tpm2.TPMAlgID
	AlgorithmName string
}

// EvidenceConfig holds the evidence type flags.
type EvidenceConfig struct {
	NitroNSM   bool
	NitroTPM   bool
	SEVSNP     bool
	SEVSNPVMPL int
	TDX        bool
}

// LoadConfig reads configuration from viper (config file / env vars / pflags / defaults).
func LoadConfig() (*Config, error) {
	evidence := EvidenceConfig{
		NitroNSM:   viper.GetBool("report.evidence.nitronsm"),
		NitroTPM:   viper.GetBool("report.evidence.nitrotpm"),
		SEVSNP:     viper.GetBool("report.evidence.sevsnp"),
		SEVSNPVMPL: viper.GetInt("report.evidence.sevsnp_vmpl"),
		TDX:        viper.GetBool("report.evidence.tdx"),
	}
	if err := validateEvidence(evidence); err != nil {
		return nil, err
	}
	tpmAlg, err := parseTPMAlgorithm(viper.GetString("tpm.algorithm"))
	if err != nil {
		return nil, err
	}
	tpmAlgName := strings.ToUpper(viper.GetString("tpm.algorithm"))
	tpmCfg := TPMConfig{
		Enabled:       viper.GetBool("tpm.enabled"),
		Algorithm:     tpmAlg,
		AlgorithmName: tpmAlgName,
	}

	envVars := splitCommaValues(viper.GetStringSlice("report.user_data.env"))
	if err := validateEnvNames(envVars); err != nil {
		return nil, err
	}

	depEndpoints, err := parseDependencyEndpoints(splitCommaValues(viper.GetStringSlice("dependencies.endpoints")))
	if err != nil {
		return nil, err
	}

	endorsementTimeout, err := time.ParseDuration(viper.GetString("endorsements.client.timeout"))
	if err != nil {
		endorsementTimeout = 10 * time.Second
	}
	endorsementCacheSize, err := parseByteSize(viper.GetString("endorsements.cache.size"))
	if err != nil {
		endorsementCacheSize = 100 << 20
	}

	return &Config{
		BindHost:                 viper.GetString("server.host"),
		BindPort:                 viper.GetInt("server.port"),
		LogFormat:                viper.GetString("log.format"),
		LogLevel:                 parseLogLevel(viper.GetString("log.level")),
		BuildInfoPath:            viper.GetString("paths.build_info"),
		EndorsementsPath:         viper.GetString("paths.endorsements"),
		PublicTLSCertPath:        absPath(viper.GetString("tls.public.cert_path")),
		PublicTLSKeyPath:         absPath(viper.GetString("tls.public.key_path")),
		PrivateTLSCertPath:       absPath(viper.GetString("tls.private.cert_path")),
		PrivateTLSKeyPath:        absPath(viper.GetString("tls.private.key_path")),
		PrivateTLSCAPath:         absPath(viper.GetString("tls.private.ca_path")),
		ReportEvidence:           evidence,
		ReportEnvVars:            envVars,
		SecureBootEnforce:        viper.GetBool("secure_boot.enforce"),
		TPM:                      tpmCfg,
		DependencyEndpoints:      depEndpoints,
		EndorsementDNSSEC:        viper.GetBool("endorsements.dnssec"),
		EndorsementClientTimeout: endorsementTimeout,
		EndorsementCacheSize:     endorsementCacheSize,
	}, nil
}

// validateEvidence checks that at least one evidence type is enabled and that
// exclusive types (NitroNSM, TDX) are not combined with others.
func validateEvidence(e EvidenceConfig) error {
	if !e.NitroNSM && !e.NitroTPM && !e.SEVSNP && !e.TDX {
		return fmt.Errorf("report.evidence: at least one evidence type must be enabled")
	}
	if e.NitroNSM && (e.NitroTPM || e.SEVSNP || e.TDX) {
		return fmt.Errorf("report.evidence: nitronsm cannot be combined with other evidence types")
	}
	if e.TDX && (e.NitroNSM || e.NitroTPM || e.SEVSNP) {
		return fmt.Errorf("report.evidence: tdx cannot be combined with other evidence types")
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

// splitCommaValues expands a string slice so that comma-separated values
// within a single element are split into separate entries. This allows
// env vars (which viper delivers as a single string) to specify multiple
// values: VAR=a,b,c. TOML arrays already produce individual elements so
// the split is a no-op there.
func splitCommaValues(raw []string) []string {
	var out []string
	for _, s := range raw {
		for _, part := range strings.Split(s, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
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

func parseDependencyEndpoints(raw []string) ([]*url.URL, error) {
	seen := make(map[string]bool, len(raw))
	urls := make([]*url.URL, 0, len(raw))
	for i, s := range raw {
		if s == "" {
			continue
		}
		u, err := url.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("dependencies.endpoints[%d]: invalid URL %q: %w", i, s, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("dependencies.endpoints[%d]: scheme must be http or https, got %q", i, u.Scheme)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("dependencies.endpoints[%d]: missing host in %q", i, s)
		}
		if seen[s] {
			return nil, fmt.Errorf("dependencies.endpoints contains duplicate value %q", s)
		}
		seen[s] = true
		urls = append(urls, u)
	}
	return urls, nil
}

func parseTPMAlgorithm(s string) (tpm2.TPMAlgID, error) {
	switch strings.ToLower(s) {
	case "sha1":
		return tpm2.TPMAlgSHA1, nil
	case "sha256":
		return tpm2.TPMAlgSHA256, nil
	case "sha384":
		return tpm2.TPMAlgSHA384, nil
	case "sha512":
		return tpm2.TPMAlgSHA512, nil
	default:
		return 0, fmt.Errorf("tpm.algorithm: unsupported algorithm %q (valid: sha1, sha256, sha384, sha512)", s)
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

// parseByteSize parses a human-readable byte size string like "100MiB" or
// "1GiB" into a byte count. Supported suffixes: B, KiB, MiB, GiB, TiB
// (case-insensitive). A bare number without suffix is treated as bytes.
func parseByteSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty byte size")
	}

	suffixes := []struct {
		suffix     string
		multiplier int64
	}{
		{"TiB", 1 << 40},
		{"GiB", 1 << 30},
		{"MiB", 1 << 20},
		{"KiB", 1 << 10},
		{"B", 1},
	}

	lower := strings.ToLower(s)
	for _, sf := range suffixes {
		if strings.HasSuffix(lower, strings.ToLower(sf.suffix)) {
			numStr := strings.TrimSpace(s[:len(s)-len(sf.suffix)])
			n, err := strconv.ParseInt(numStr, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid byte size %q: %w", s, err)
			}
			if n < 0 {
				return 0, fmt.Errorf("negative byte size %q", s)
			}
			return n * sf.multiplier, nil
		}
	}

	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid byte size %q: %w", s, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("negative byte size %q", s)
	}
	return n, nil
}
