package app

import (
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestValidateEvidence(t *testing.T) {
	tests := []struct {
		name    string
		cfg     EvidenceConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "none enabled",
			cfg:     EvidenceConfig{},
			wantErr: true,
			errMsg:  "at least one evidence type must be enabled",
		},
		{
			name:    "nitronsm only",
			cfg:     EvidenceConfig{NitroNSM: true},
			wantErr: false,
		},
		{
			name:    "nitrotpm only",
			cfg:     EvidenceConfig{NitroTPM: true},
			wantErr: false,
		},
		{
			name:    "sevsnp only",
			cfg:     EvidenceConfig{SEVSNP: true},
			wantErr: false,
		},
		{
			name:    "tdx only",
			cfg:     EvidenceConfig{TDX: true},
			wantErr: false,
		},
		{
			name:    "nitrotpm and sevsnp",
			cfg:     EvidenceConfig{NitroTPM: true, SEVSNP: true},
			wantErr: false,
		},
		{
			name:    "nitronsm and nitrotpm",
			cfg:     EvidenceConfig{NitroNSM: true, NitroTPM: true},
			wantErr: true,
			errMsg:  "nitronsm cannot be combined",
		},
		{
			name:    "nitronsm and sevsnp",
			cfg:     EvidenceConfig{NitroNSM: true, SEVSNP: true},
			wantErr: true,
			errMsg:  "nitronsm cannot be combined",
		},
		{
			name:    "nitronsm and tdx",
			cfg:     EvidenceConfig{NitroNSM: true, TDX: true},
			wantErr: true,
			errMsg:  "nitronsm cannot be combined",
		},
		{
			name:    "nitronsm with all others",
			cfg:     EvidenceConfig{NitroNSM: true, NitroTPM: true, SEVSNP: true, TDX: true},
			wantErr: true,
			errMsg:  "nitronsm cannot be combined",
		},
		{
			name:    "tdx and nitrotpm",
			cfg:     EvidenceConfig{TDX: true, NitroTPM: true},
			wantErr: true,
			errMsg:  "tdx cannot be combined",
		},
		{
			name:    "tdx and sevsnp",
			cfg:     EvidenceConfig{TDX: true, SEVSNP: true},
			wantErr: true,
			errMsg:  "tdx cannot be combined",
		},
		{
			name:    "tdx and nitronsm",
			cfg:     EvidenceConfig{TDX: true, NitroNSM: true},
			wantErr: true,
			// NitroNSM check fires first in the code
			errMsg: "nitronsm cannot be combined",
		},
		{
			name:    "sevsnp with vmpl set",
			cfg:     EvidenceConfig{SEVSNP: true, SEVSNPVMPL: 2},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEvidence(tt.cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateEnvNames(t *testing.T) {
	tests := []struct {
		name    string
		names   []string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty slice",
			names:   []string{},
			wantErr: false,
		},
		{
			name:    "nil slice",
			names:   nil,
			wantErr: false,
		},
		{
			name:    "single valid name",
			names:   []string{"HOME"},
			wantErr: false,
		},
		{
			name:    "multiple valid names",
			names:   []string{"HOME", "PATH", "MY_VAR_123"},
			wantErr: false,
		},
		{
			name:    "underscore prefix",
			names:   []string{"_PRIVATE"},
			wantErr: false,
		},
		{
			name:    "single underscore",
			names:   []string{"_"},
			wantErr: false,
		},
		{
			name:    "lowercase",
			names:   []string{"my_var"},
			wantErr: false,
		},
		{
			name:    "mixed case",
			names:   []string{"My_Var_1"},
			wantErr: false,
		},
		{
			name:    "starts with digit",
			names:   []string{"1BAD"},
			wantErr: true,
			errMsg:  "invalid environment variable name",
		},
		{
			name:    "contains dash",
			names:   []string{"BAD-NAME"},
			wantErr: true,
			errMsg:  "invalid environment variable name",
		},
		{
			name:    "contains dot",
			names:   []string{"BAD.NAME"},
			wantErr: true,
			errMsg:  "invalid environment variable name",
		},
		{
			name:    "contains space",
			names:   []string{"BAD NAME"},
			wantErr: true,
			errMsg:  "invalid environment variable name",
		},
		{
			name:    "empty string element",
			names:   []string{""},
			wantErr: true,
			errMsg:  "invalid environment variable name",
		},
		{
			name:    "duplicate names",
			names:   []string{"HOME", "PATH", "HOME"},
			wantErr: true,
			errMsg:  "duplicate",
		},
		{
			name:    "invalid after valid",
			names:   []string{"GOOD", "2BAD"},
			wantErr: true,
			errMsg:  "invalid environment variable name",
		},
		{
			name:    "duplicate checked before validity",
			names:   []string{"A", "A"},
			wantErr: true,
			errMsg:  "duplicate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEnvNames(tt.names)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestFindDuplicate(t *testing.T) {
	tests := []struct {
		name string
		vals []string
		want string
	}{
		{
			name: "empty slice",
			vals: []string{},
			want: "",
		},
		{
			name: "nil slice",
			vals: nil,
			want: "",
		},
		{
			name: "no duplicates",
			vals: []string{"a", "b", "c"},
			want: "",
		},
		{
			name: "single element",
			vals: []string{"a"},
			want: "",
		},
		{
			name: "duplicate at end",
			vals: []string{"a", "b", "a"},
			want: "a",
		},
		{
			name: "duplicate adjacent",
			vals: []string{"x", "x"},
			want: "x",
		},
		{
			name: "first duplicate returned",
			vals: []string{"a", "b", "c", "b", "a"},
			want: "b",
		},
		{
			name: "all same",
			vals: []string{"z", "z", "z"},
			want: "z",
		},
		{
			name: "empty string duplicate",
			vals: []string{"", ""},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findDuplicate(tt.vals)
			if got != tt.want {
				t.Fatalf("findDuplicate(%v) = %q, want %q", tt.vals, got, tt.want)
			}
		})
	}
}

func TestParseTPMAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    tpm2.TPMAlgID
		wantErr bool
		errMsg  string
	}{
		{
			name:  "sha1 lowercase",
			input: "sha1",
			want:  tpm2.TPMAlgSHA1,
		},
		{
			name:  "sha1 uppercase",
			input: "SHA1",
			want:  tpm2.TPMAlgSHA1,
		},
		{
			name:  "sha1 mixed case",
			input: "Sha1",
			want:  tpm2.TPMAlgSHA1,
		},
		{
			name:  "sha256 lowercase",
			input: "sha256",
			want:  tpm2.TPMAlgSHA256,
		},
		{
			name:  "sha256 uppercase",
			input: "SHA256",
			want:  tpm2.TPMAlgSHA256,
		},
		{
			name:  "sha384 lowercase",
			input: "sha384",
			want:  tpm2.TPMAlgSHA384,
		},
		{
			name:  "sha384 uppercase",
			input: "SHA384",
			want:  tpm2.TPMAlgSHA384,
		},
		{
			name:  "sha512 lowercase",
			input: "sha512",
			want:  tpm2.TPMAlgSHA512,
		},
		{
			name:  "sha512 uppercase",
			input: "SHA512",
			want:  tpm2.TPMAlgSHA512,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
			errMsg:  "unsupported algorithm",
		},
		{
			name:    "unknown algorithm",
			input:   "md5",
			wantErr: true,
			errMsg:  "unsupported algorithm",
		},
		{
			name:    "sha3-256 unsupported",
			input:   "sha3-256",
			wantErr: true,
			errMsg:  "unsupported algorithm",
		},
		{
			name:    "numeric string",
			input:   "256",
			wantErr: true,
			errMsg:  "unsupported algorithm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTPMAlgorithm(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tt.want {
					t.Fatalf("parseTPMAlgorithm(%q) = %v, want %v", tt.input, got, tt.want)
				}
			}
		})
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  slog.Level
	}{
		{name: "debug lowercase", input: "debug", want: slog.LevelDebug},
		{name: "debug uppercase", input: "DEBUG", want: slog.LevelDebug},
		{name: "debug mixed case", input: "Debug", want: slog.LevelDebug},
		{name: "info lowercase", input: "info", want: slog.LevelInfo},
		{name: "info uppercase", input: "INFO", want: slog.LevelInfo},
		{name: "warn lowercase", input: "warn", want: slog.LevelWarn},
		{name: "warn uppercase", input: "WARN", want: slog.LevelWarn},
		{name: "warning lowercase", input: "warning", want: slog.LevelWarn},
		{name: "warning uppercase", input: "WARNING", want: slog.LevelWarn},
		{name: "error lowercase", input: "error", want: slog.LevelError},
		{name: "error uppercase", input: "ERROR", want: slog.LevelError},
		{name: "unknown defaults to info", input: "trace", want: slog.LevelInfo},
		{name: "empty defaults to info", input: "", want: slog.LevelInfo},
		{name: "gibberish defaults to info", input: "xyzzy", want: slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLogLevel(tt.input)
			if got != tt.want {
				t.Fatalf("parseLogLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestAbsPath(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(t *testing.T, result string)
	}{
		{
			name:  "empty returns empty",
			input: "",
			check: func(t *testing.T, result string) {
				if result != "" {
					t.Fatalf("absPath(%q) = %q, want %q", "", result, "")
				}
			},
		},
		{
			name:  "absolute path unchanged",
			input: "/abs/path/to/file",
			check: func(t *testing.T, result string) {
				if result != "/abs/path/to/file" {
					t.Fatalf("absPath(%q) = %q, want %q", "/abs/path/to/file", result, "/abs/path/to/file")
				}
			},
		},
		{
			name:  "relative path becomes absolute",
			input: "relative/path",
			check: func(t *testing.T, result string) {
				if !filepath.IsAbs(result) {
					t.Fatalf("absPath(%q) = %q, expected absolute path", "relative/path", result)
				}
				// The result should end with the relative path components
				if !contains(result, "relative/path") {
					t.Fatalf("absPath(%q) = %q, expected to contain %q", "relative/path", result, "relative/path")
				}
			},
		},
		{
			name:  "dot path becomes absolute",
			input: ".",
			check: func(t *testing.T, result string) {
				if !filepath.IsAbs(result) {
					t.Fatalf("absPath(%q) = %q, expected absolute path", ".", result)
				}
			},
		},
		{
			name:  "filename only becomes absolute",
			input: "file.pem",
			check: func(t *testing.T, result string) {
				if !filepath.IsAbs(result) {
					t.Fatalf("absPath(%q) = %q, expected absolute path", "file.pem", result)
				}
				if !contains(result, "file.pem") {
					t.Fatalf("absPath(%q) = %q, expected to contain %q", "file.pem", result, "file.pem")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := absPath(tt.input)
			tt.check(t, result)
		})
	}
}

func TestParseDependencyEndpoints(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantLen int
		wantErr string
	}{
		{
			name:    "empty list",
			input:   []string{},
			wantLen: 0,
		},
		{
			name:    "nil list",
			input:   nil,
			wantLen: 0,
		},
		{
			name:    "single http endpoint",
			input:   []string{"http://host1:8187/api/v1/attestation"},
			wantLen: 1,
		},
		{
			name:    "single https endpoint",
			input:   []string{"https://host1:8187/api/v1/attestation"},
			wantLen: 1,
		},
		{
			name:    "multiple valid endpoints",
			input:   []string{"http://host1:8187/attest", "https://host2:8187/attest"},
			wantLen: 2,
		},
		{
			name:    "empty strings are skipped",
			input:   []string{"", "http://host1:8187/attest", ""},
			wantLen: 1,
		},
		{
			name:    "host without port",
			input:   []string{"http://myhost/api/v1/attestation"},
			wantLen: 1,
		},
		{
			name:    "host without path",
			input:   []string{"http://myhost"},
			wantLen: 1,
		},
		{
			name:    "invalid scheme ftp",
			input:   []string{"ftp://host1:8187/attest"},
			wantErr: "scheme must be http or https",
		},
		{
			name:    "no scheme",
			input:   []string{"host1:8187/attest"},
			wantErr: "scheme must be http or https",
		},
		{
			name:    "missing host",
			input:   []string{"http:///path"},
			wantErr: "missing host",
		},
		{
			name:    "duplicate endpoints",
			input:   []string{"http://host1:8187/attest", "http://host1:8187/attest"},
			wantErr: "duplicate value",
		},
		{
			name:    "error on first invalid stops parsing",
			input:   []string{"http://valid:8187", "ftp://invalid:8187"},
			wantErr: "scheme must be http or https",
		},
		{
			name:    "comma-separated single string from env var",
			input:   []string{"http://host1:8187/attest", "http://host2:8187/attest"},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDependencyEndpoints(tt.input)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tt.wantLen {
				t.Errorf("got %d URLs, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestSplitCommaValues(t *testing.T) {
	tests := []struct {
		name string
		raw  []string
		want []string
	}{
		{
			name: "nil input",
			raw:  nil,
			want: nil,
		},
		{
			name: "empty input",
			raw:  []string{},
			want: nil,
		},
		{
			name: "single value no comma",
			raw:  []string{"abc"},
			want: []string{"abc"},
		},
		{
			name: "comma-separated in one element",
			raw:  []string{"a,b,c"},
			want: []string{"a", "b", "c"},
		},
		{
			name: "comma-separated with spaces",
			raw:  []string{"a , b , c"},
			want: []string{"a", "b", "c"},
		},
		{
			name: "trailing comma",
			raw:  []string{"a,b,"},
			want: []string{"a", "b"},
		},
		{
			name: "leading comma",
			raw:  []string{",a,b"},
			want: []string{"a", "b"},
		},
		{
			name: "multiple elements already split",
			raw:  []string{"a", "b", "c"},
			want: []string{"a", "b", "c"},
		},
		{
			name: "mixed single and comma-separated",
			raw:  []string{"a", "b,c", "d"},
			want: []string{"a", "b", "c", "d"},
		},
		{
			name: "empty strings filtered",
			raw:  []string{"", "a", ""},
			want: []string{"a"},
		},
		{
			name: "only commas",
			raw:  []string{",,,"},
			want: nil,
		},
		{
			name: "urls comma-separated",
			raw:  []string{"http://host1:8187/attest,http://host2:8187/attest"},
			want: []string{"http://host1:8187/attest", "http://host2:8187/attest"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitCommaValues(tt.raw)
			if len(got) != len(tt.want) {
				t.Fatalf("splitCommaValues(%v) = %v (len %d), want %v (len %d)", tt.raw, got, len(got), tt.want, len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitCommaValues(%v)[%d] = %q, want %q", tt.raw, i, got[i], tt.want[i])
				}
			}
		})
	}
}

// contains reports whether s contains substr. Avoids importing strings just
// for tests.
func contains(s, substr string) bool {
	return len(substr) == 0 || len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
