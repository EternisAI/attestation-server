package app

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goccy/go-json"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	pb "github.com/google/go-tdx-guest/proto/tdx"

	"github.com/eternisai/attestation-server/pkg/hexbytes"
	"github.com/eternisai/attestation-server/pkg/nitro"
)

// --- PCRGoldenValues UnmarshalJSON ---

func TestPCRGoldenValues_UnmarshalJSON(t *testing.T) {
	sha384Hex := strings.Repeat("aa", 48)
	sha384Hex2 := strings.Repeat("bb", 48)
	sha384Hex3 := strings.Repeat("cc", 48)
	sha256Hex := strings.Repeat("dd", 32)

	tests := []struct {
		name      string
		input     string
		wantPCRs  map[int][]byte
		wantError bool
	}{
		{
			name:     "PCRN keys",
			input:    `{"PCR0":"` + sha384Hex + `","PCR1":"` + sha384Hex2 + `","PCR2":"` + sha384Hex3 + `"}`,
			wantPCRs: map[int][]byte{0: bytes.Repeat([]byte{0xaa}, 48), 1: bytes.Repeat([]byte{0xbb}, 48), 2: bytes.Repeat([]byte{0xcc}, 48)},
		},
		{
			name:     "numeric keys",
			input:    `{"4":"` + sha384Hex + `","7":"` + sha384Hex2 + `","12":"` + sha384Hex3 + `"}`,
			wantPCRs: map[int][]byte{4: bytes.Repeat([]byte{0xaa}, 48), 7: bytes.Repeat([]byte{0xbb}, 48), 12: bytes.Repeat([]byte{0xcc}, 48)},
		},
		{
			name:     "mixed PCRN and numeric keys",
			input:    `{"PCR0":"` + sha384Hex + `","1":"` + sha256Hex + `"}`,
			wantPCRs: map[int][]byte{0: bytes.Repeat([]byte{0xaa}, 48), 1: bytes.Repeat([]byte{0xdd}, 32)},
		},
		{
			name:      "empty PCR value rejected",
			input:     `{"PCR0":"` + sha256Hex + `","PCR1":""}`,
			wantError: true,
		},
		{
			name:     "no PCRs",
			input:    `{}`,
			wantPCRs: map[int][]byte{},
		},
		{
			name:      "empty PCR value",
			input:     `{"PCR0":""}`,
			wantError: true,
		},
		{
			name:      "invalid PCR hex",
			input:     `{"PCR0":"not-valid-hex"}`,
			wantError: true,
		},
		{
			name:     "short hex is valid",
			input:    `{"PCR0":"aabb"}`,
			wantPCRs: map[int][]byte{0: {0xaa, 0xbb}},
		},
		{
			name:      "invalid PCR index",
			input:     `{"PCRnotanumber":"` + sha384Hex + `"}`,
			wantError: true,
		},
		{
			name:      "non-numeric non-PCR key",
			input:     `{"foo":"` + sha384Hex + `"}`,
			wantError: true,
		},
		{
			name:      "PCR index out of range",
			input:     `{"PCR25":"` + sha384Hex + `"}`,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v PCRGoldenValues
			err := json.Unmarshal([]byte(tt.input), &v)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(v) != len(tt.wantPCRs) {
				t.Fatalf("PCRs length = %d, want %d", len(v), len(tt.wantPCRs))
			}
			for idx, want := range tt.wantPCRs {
				if !bytes.Equal(v[idx], want) {
					t.Errorf("PCR%d = %x, want %x", idx, v[idx], want)
				}
			}
		})
	}
}

// --- EndorsementDocument parsing ---

func TestParseEndorsementDocument(t *testing.T) {
	pcr384a := strings.Repeat("aa", 48)
	pcr384b := strings.Repeat("bb", 48)
	pcr384c := strings.Repeat("cc", 48)
	pcr384d := strings.Repeat("dd", 48)
	pcr384e := strings.Repeat("ee", 48)
	pcr256 := strings.Repeat("ff", 32)

	doc := `{
		"nitronsm": {"PCR0": "` + pcr384a + `", "PCR1": "` + pcr384b + `", "PCR2": "` + pcr384c + `"},
		"nitrotpm": {"PCR4": "` + pcr384d + `", "PCR7": "` + pcr384e + `"},
		"sevsnp": "aabbccddee00112233445566778899aabbccddee00112233445566778899aabbccddee001122334455667788aabbccdd",
		"tdx": {"MRTD": "1122", "RTMR0": "3344"},
		"tpm": {"PCR0": "` + pcr256 + `"}
	}`

	var ed EndorsementDocument
	if err := json.Unmarshal([]byte(doc), &ed); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if ed.NitroNSM == nil {
		t.Fatal("NitroNSM is nil")
	}
	if got := (*ed.NitroNSM)[0]; !bytes.Equal(got, bytes.Repeat([]byte{0xaa}, 48)) {
		t.Errorf("NitroNSM PCR0 = %x, want %s", got, pcr384a)
	}

	if ed.NitroTPM == nil {
		t.Fatal("NitroTPM is nil")
	}
	if got := (*ed.NitroTPM)[4]; !bytes.Equal(got, bytes.Repeat([]byte{0xdd}, 48)) {
		t.Errorf("NitroTPM PCR4 = %x, want %s", got, pcr384d)
	}

	if ed.SEVSNP == nil {
		t.Fatal("SEVSNP is nil")
	}
	if len(*ed.SEVSNP) != 96 {
		t.Errorf("SEVSNP length = %d, want 96", len(*ed.SEVSNP))
	}

	if ed.TDX == nil {
		t.Fatal("TDX is nil")
	}
	if ed.TDX.MRTD != "1122" {
		t.Errorf("TDX MRTD = %q, want %q", ed.TDX.MRTD, "1122")
	}
	if ed.TDX.RTMR0 != "3344" {
		t.Errorf("TDX RTMR0 = %q, want %q", ed.TDX.RTMR0, "3344")
	}
	if ed.TDX.RTMR1 != "" {
		t.Errorf("TDX RTMR1 = %q, want empty", ed.TDX.RTMR1)
	}

	if ed.TPM == nil {
		t.Fatal("TPM is nil")
	}
	if got := (*ed.TPM)[0]; !bytes.Equal(got, bytes.Repeat([]byte{0xff}, 32)) {
		t.Errorf("TPM PCR0 = %x, want %s", got, pcr256)
	}
}

// --- Measurement comparison ---

func TestValidateNitroNSMMeasurements(t *testing.T) {
	pcr0 := bytes.Repeat([]byte{0xaa}, 48)
	pcr1 := bytes.Repeat([]byte{0xcc}, 48)
	pcr2 := bytes.Repeat([]byte{0xee}, 48)
	doc := &nitro.AttestationDocument{
		PCRs: map[int][]byte{0: pcr0, 1: pcr1, 2: pcr2},
	}

	t.Run("match", func(t *testing.T) {
		endorsement := PCRGoldenValues{0: bytes.Repeat([]byte{0xaa}, 48), 1: bytes.Repeat([]byte{0xcc}, 48), 2: bytes.Repeat([]byte{0xee}, 48)}
		if err := validateNitroNSMMeasurements(doc, endorsement); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		endorsement := PCRGoldenValues{0: bytes.Repeat([]byte{0xaa}, 48), 1: bytes.Repeat([]byte{0x00}, 48)}
		err := validateNitroNSMMeasurements(doc, endorsement)
		if err == nil {
			t.Fatal("expected error for mismatch")
		}
		if !contains(err.Error(), "PCR1 mismatch") {
			t.Errorf("error %q does not mention PCR1 mismatch", err)
		}
	})

	t.Run("missing PCR in evidence", func(t *testing.T) {
		endorsement := PCRGoldenValues{8: bytes.Repeat([]byte{0xaa}, 48)}
		err := validateNitroNSMMeasurements(doc, endorsement)
		if err == nil {
			t.Fatal("expected error for missing PCR")
		}
		if !contains(err.Error(), "missing from evidence") {
			t.Errorf("error %q does not mention missing from evidence", err)
		}
	})
}

func TestValidateNitroTPMMeasurements(t *testing.T) {
	doc := &nitro.AttestationDocument{
		NitroTPMPCRs: map[int][]byte{
			4:  bytes.Repeat([]byte{0x11}, 48),
			7:  bytes.Repeat([]byte{0x33}, 48),
			12: bytes.Repeat([]byte{0x55}, 48),
		},
	}

	t.Run("match", func(t *testing.T) {
		endorsement := PCRGoldenValues{4: bytes.Repeat([]byte{0x11}, 48), 7: bytes.Repeat([]byte{0x33}, 48), 12: bytes.Repeat([]byte{0x55}, 48)}
		if err := validateNitroTPMMeasurements(doc, endorsement); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		endorsement := PCRGoldenValues{4: bytes.Repeat([]byte{0xff}, 48)}
		err := validateNitroTPMMeasurements(doc, endorsement)
		if err == nil {
			t.Fatal("expected error for mismatch")
		}
		if !contains(err.Error(), "PCR4 mismatch") {
			t.Errorf("error %q does not mention PCR4 mismatch", err)
		}
	})
}

func TestValidateSEVSNPMeasurement(t *testing.T) {
	measurement := bytes.Repeat([]byte{0xdd}, 48)
	report := &spb.Report{Measurement: measurement}

	t.Run("match", func(t *testing.T) {
		hexStr := strings.Repeat("dd", 48) // 96 hex chars = 48 bytes of 0xdd
		if err := validateSEVSNPMeasurement(report, hexStr); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		hexStr := strings.Repeat("aa", 48)
		err := validateSEVSNPMeasurement(report, hexStr)
		if err == nil {
			t.Fatal("expected error for mismatch")
		}
		if !contains(err.Error(), "measurement mismatch") {
			t.Errorf("error %q does not mention measurement mismatch", err)
		}
	})

	t.Run("invalid hex", func(t *testing.T) {
		err := validateSEVSNPMeasurement(report, "not-hex")
		if err == nil {
			t.Fatal("expected error for invalid hex")
		}
		if !contains(err.Error(), "invalid hex") {
			t.Errorf("error %q does not mention invalid hex", err)
		}
	})
}

func TestValidateTDXMeasurements(t *testing.T) {
	quote := &pb.QuoteV4{
		TdQuoteBody: &pb.TDQuoteBody{
			MrTd:  bytes.Repeat([]byte{0x11}, 48),
			Rtmrs: [][]byte{bytes.Repeat([]byte{0x22}, 48), bytes.Repeat([]byte{0x33}, 48), bytes.Repeat([]byte{0x44}, 48)},
		},
	}

	t.Run("match all", func(t *testing.T) {
		endorsement := &TDXEndorsement{
			MRTD:  strings.Repeat("11", 48),
			RTMR0: strings.Repeat("22", 48),
		}
		if err := validateTDXMeasurements(quote, endorsement); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("partial fields", func(t *testing.T) {
		endorsement := &TDXEndorsement{RTMR2: strings.Repeat("44", 48)}
		if err := validateTDXMeasurements(quote, endorsement); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		endorsement := &TDXEndorsement{MRTD: strings.Repeat("00", 48)}
		err := validateTDXMeasurements(quote, endorsement)
		if err == nil {
			t.Fatal("expected error for mismatch")
		}
		if !contains(err.Error(), "MRTD mismatch") {
			t.Errorf("error %q does not mention MRTD mismatch", err)
		}
	})
}

func TestValidateTPMMeasurements(t *testing.T) {
	pcrs := map[int]hexbytes.Bytes{
		0: bytes.Repeat([]byte{0xaa}, 48),
		1: bytes.Repeat([]byte{0xcc}, 48),
	}

	t.Run("match", func(t *testing.T) {
		endorsement := PCRGoldenValues{0: bytes.Repeat([]byte{0xaa}, 48), 1: bytes.Repeat([]byte{0xcc}, 48)}
		if err := validateTPMMeasurements(pcrs, endorsement); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("subset match", func(t *testing.T) {
		endorsement := PCRGoldenValues{0: bytes.Repeat([]byte{0xaa}, 48)}
		if err := validateTPMMeasurements(pcrs, endorsement); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		endorsement := PCRGoldenValues{1: bytes.Repeat([]byte{0xff}, 48)}
		err := validateTPMMeasurements(pcrs, endorsement)
		if err == nil {
			t.Fatal("expected error for mismatch")
		}
		if !contains(err.Error(), "PCR1 mismatch") {
			t.Errorf("error %q does not mention PCR1 mismatch", err)
		}
	})
}

// --- parseCacheTTL ---

func TestParseCacheTTL(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    time.Duration
	}{
		{
			name:    "max-age",
			headers: map[string]string{"Cache-Control": "max-age=3600"},
			want:    time.Hour,
		},
		{
			name:    "max-age capped at 24h",
			headers: map[string]string{"Cache-Control": "max-age=999999"},
			want:    24 * time.Hour,
		},
		{
			name:    "no-cache returns 0",
			headers: map[string]string{"Cache-Control": "no-cache"},
			want:    0,
		},
		{
			name:    "no-store returns 0",
			headers: map[string]string{"Cache-Control": "no-store"},
			want:    0,
		},
		{
			name:    "no headers returns default 30m",
			headers: map[string]string{},
			want:    30 * time.Minute,
		},
		{
			name:    "max-age with other directives",
			headers: map[string]string{"Cache-Control": "public, max-age=1800"},
			want:    30 * time.Minute,
		},
		{
			name: "expires header fallback",
			headers: map[string]string{
				"Date":    time.Now().UTC().Format(http.TimeFormat),
				"Expires": time.Now().Add(2 * time.Hour).UTC().Format(http.TimeFormat),
			},
			want: 2 * time.Hour,
		},
		{
			name: "expires in the past returns 0",
			headers: map[string]string{
				"Date":    time.Now().UTC().Format(http.TimeFormat),
				"Expires": time.Now().Add(-1 * time.Hour).UTC().Format(http.TimeFormat),
			},
			want: 0,
		},
		{
			name: "expires capped at 24h",
			headers: map[string]string{
				"Date":    time.Now().UTC().Format(http.TimeFormat),
				"Expires": time.Now().Add(48 * time.Hour).UTC().Format(http.TimeFormat),
			},
			want: 24 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			for k, v := range tt.headers {
				h.Set(k, v)
			}
			got := parseCacheTTL(h)
			// Allow 2s tolerance for time-based tests
			diff := got - tt.want
			if diff < 0 {
				diff = -diff
			}
			if diff > 2*time.Second {
				t.Errorf("parseCacheTTL() = %v, want %v (diff %v)", got, tt.want, diff)
			}
		})
	}
}

// --- parseByteSize ---

func TestParseByteSize(t *testing.T) {
	tests := []struct {
		input     string
		want      int64
		wantError bool
	}{
		// IEC (binary) suffixes
		{"100MiB", 100 << 20, false},
		{"1GiB", 1 << 30, false},
		{"512KiB", 512 << 10, false},
		{"1024B", 1024, false},
		{"2TiB", 2 << 40, false},
		// SI (decimal) suffixes
		{"100MB", 100_000_000, false},
		{"1GB", 1_000_000_000, false},
		{"512KB", 512_000, false},
		{"2TB", 2_000_000_000_000, false},
		// Bare number (bytes)
		{"42", 42, false},
		{"0", 0, false},
		// Whitespace
		{" 10 MiB ", 10 << 20, false},
		// Case insensitive
		{"100mib", 100 << 20, false},
		{"1gib", 1 << 30, false},
		// Errors
		{"", 0, true},
		{"abc", 0, true},
		{"-1MiB", 0, true},
		{"-5", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseByteSize(tt.input)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("parseByteSize(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// --- Fetch endorsement documents ---

func TestFetchEndorsementDocuments_Identical(t *testing.T) {
	docJSON := `{"sevsnp":"aabbccdd"}`

	srv1 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=600")
		w.Write([]byte(docJSON))
	}))
	defer srv1.Close()

	srv2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=1200")
		w.Write([]byte(docJSON))
	}))
	defer srv2.Close()

	s := &Server{
		cfg: &Config{EndorsementClientTimeout: 5 * time.Second},
	}

	u1, _ := url.Parse(srv1.URL + "/endorsement.json")
	u2, _ := url.Parse(srv2.URL + "/endorsement.json")

	// Use the test servers' TLS clients
	origClient := s.fetchHTTPClient()
	_ = origClient // we need to use TLS test servers' transport

	// Create a client that trusts the test servers
	doc, _, _, ttl, err := s.fetchEndorsementDocumentsWithClient(context.Background(), []*url.URL{u1, u2}, srv1.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc.SEVSNP == nil || *doc.SEVSNP != "aabbccdd" {
		t.Errorf("SEVSNP = %v, want aabbccdd", doc.SEVSNP)
	}
	// Should use most conservative TTL (600s = 10m)
	if ttl != 10*time.Minute {
		t.Errorf("TTL = %v, want %v", ttl, 10*time.Minute)
	}
}

func TestFetchEndorsementDocuments_Mismatch(t *testing.T) {
	srv1 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"sevsnp":"aabb"}`))
	}))
	defer srv1.Close()

	srv2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"sevsnp":"ccdd"}`))
	}))
	defer srv2.Close()

	s := &Server{
		cfg: &Config{EndorsementClientTimeout: 5 * time.Second},
	}

	u1, _ := url.Parse(srv1.URL + "/endorsement.json")
	u2, _ := url.Parse(srv2.URL + "/endorsement.json")

	_, _, _, _, err := s.fetchEndorsementDocumentsWithClient(context.Background(), []*url.URL{u1, u2}, srv1.Client())
	if err == nil {
		t.Fatal("expected error for mismatched documents")
	}
	if !contains(err.Error(), "mismatch") {
		t.Errorf("error %q does not mention mismatch", err)
	}
}

// --- Endorsement cache ---

func TestEndorsementCache_SetGroupAndGet(t *testing.T) {
	cache, err := newFetcherCache(100 << 20)
	if err != nil {
		t.Fatal(err)
	}

	doc := &EndorsementDocument{SEVSNP: strPtr("aabbccdd")}
	cache.setGroup([]string{"https://a.com/e.json", "https://b.com/e.json"}, doc, 100, time.Minute)

	got1, ok1 := cache.get("https://a.com/e.json")
	got2, ok2 := cache.get("https://b.com/e.json")

	if !ok1 || !ok2 {
		t.Fatal("cache miss for stored URLs")
	}

	// Both should point to the same object (dedup)
	if got1 != got2 {
		t.Error("expected same pointer for deduplicated entries")
	}
	if got1 != doc {
		t.Error("expected same pointer as original document")
	}
}

func TestEndorsementCache_Miss(t *testing.T) {
	cache, err := newFetcherCache(100 << 20)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := cache.get("https://missing.com/e.json")
	if ok {
		t.Error("expected cache miss for unknown URL")
	}
}

// --- validateEndorsementsAgainstEvidence ---

func TestValidateEndorsementsAgainstEvidence(t *testing.T) {
	// Shared self-attestation results with known measurements.
	sa := &parsedSelfAttestation{
		nitroNSMDoc: &nitro.AttestationDocument{
			PCRs: map[int][]byte{
				0: bytes.Repeat([]byte{0xaa}, 48),
				1: bytes.Repeat([]byte{0xbb}, 48),
				2: bytes.Repeat([]byte{0xcc}, 48),
			},
		},
		sevSNPReport: &spb.Report{
			Measurement: bytes.Repeat([]byte{0xdd}, 48),
		},
		tpmPCRs: map[int]hexbytes.Bytes{
			0: bytes.Repeat([]byte{0x11}, 48),
		},
	}

	t.Run("nitronsm match", func(t *testing.T) {
		doc := EndorsementDocument{
			NitroNSM: &PCRGoldenValues{0: bytes.Repeat([]byte{0xaa}, 48), 1: bytes.Repeat([]byte{0xbb}, 48), 2: bytes.Repeat([]byte{0xcc}, 48)},
		}
		cfg := &Config{ReportEvidence: EvidenceConfig{NitroNSM: true}}
		if err := validateEndorsementsAgainstEvidence(doc, cfg, sa); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("nitronsm configured but missing in endorsement", func(t *testing.T) {
		doc := EndorsementDocument{}
		cfg := &Config{ReportEvidence: EvidenceConfig{NitroNSM: true}}
		err := validateEndorsementsAgainstEvidence(doc, cfg, sa)
		if err == nil {
			t.Fatal("expected error")
		}
		if !contains(err.Error(), "nitronsm") || !contains(err.Error(), "no endorsement measurements") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("sevsnp match", func(t *testing.T) {
		hex := strings.Repeat("dd", 48)
		doc := EndorsementDocument{SEVSNP: &hex}
		cfg := &Config{ReportEvidence: EvidenceConfig{SEVSNP: true}}
		if err := validateEndorsementsAgainstEvidence(doc, cfg, sa); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("sevsnp configured but missing in endorsement", func(t *testing.T) {
		doc := EndorsementDocument{}
		cfg := &Config{ReportEvidence: EvidenceConfig{SEVSNP: true}}
		err := validateEndorsementsAgainstEvidence(doc, cfg, sa)
		if err == nil {
			t.Fatal("expected error")
		}
		if !contains(err.Error(), "sevsnp") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("sevsnp mismatch", func(t *testing.T) {
		hex := strings.Repeat("00", 48)
		doc := EndorsementDocument{SEVSNP: &hex}
		cfg := &Config{ReportEvidence: EvidenceConfig{SEVSNP: true}}
		err := validateEndorsementsAgainstEvidence(doc, cfg, sa)
		if err == nil {
			t.Fatal("expected error")
		}
		if !contains(err.Error(), "sevsnp") || !contains(err.Error(), "mismatch") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("tpm configured but missing in endorsement", func(t *testing.T) {
		doc := EndorsementDocument{}
		cfg := &Config{TPM: TPMConfig{Enabled: true}}
		err := validateEndorsementsAgainstEvidence(doc, cfg, sa)
		if err == nil {
			t.Fatal("expected error")
		}
		if !contains(err.Error(), "tpm") || !contains(err.Error(), "no endorsement measurements") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("tpm match", func(t *testing.T) {
		doc := EndorsementDocument{
			TPM: &PCRGoldenValues{0: bytes.Repeat([]byte{0x11}, 48)},
		}
		cfg := &Config{TPM: TPMConfig{Enabled: true}}
		if err := validateEndorsementsAgainstEvidence(doc, cfg, sa); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("tdx configured but missing in endorsement", func(t *testing.T) {
		doc := EndorsementDocument{}
		cfg := &Config{ReportEvidence: EvidenceConfig{TDX: true}}
		sa := &parsedSelfAttestation{
			tdxQuote: &pb.QuoteV4{TdQuoteBody: &pb.TDQuoteBody{
				MrTd: bytes.Repeat([]byte{0x11}, 48),
			}},
		}
		err := validateEndorsementsAgainstEvidence(doc, cfg, sa)
		if err == nil {
			t.Fatal("expected error")
		}
		if !contains(err.Error(), "tdx") || !contains(err.Error(), "no endorsement measurements") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("nitrotpm configured but missing in endorsement", func(t *testing.T) {
		doc := EndorsementDocument{}
		cfg := &Config{ReportEvidence: EvidenceConfig{NitroTPM: true}}
		sa := &parsedSelfAttestation{
			nitroTPMDoc: &nitro.AttestationDocument{
				NitroTPMPCRs: map[int][]byte{4: {0x11}},
			},
		}
		err := validateEndorsementsAgainstEvidence(doc, cfg, sa)
		if err == nil {
			t.Fatal("expected error")
		}
		if !contains(err.Error(), "nitrotpm") || !contains(err.Error(), "no endorsement measurements") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("no evidence configured passes", func(t *testing.T) {
		doc := EndorsementDocument{}
		cfg := &Config{}
		if err := validateEndorsementsAgainstEvidence(doc, cfg, sa); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// --- validateOwnEndorsements ---

func TestValidateOwnEndorsements_NoURLs(t *testing.T) {
	s := &Server{cfg: &Config{}}
	if err := s.validateOwnEndorsements(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateOwnEndorsements_CacheHit(t *testing.T) {
	cache, err := newFetcherCache(100 << 20)
	if err != nil {
		t.Fatal(err)
	}

	hex := strings.Repeat("dd", 48)
	doc := &EndorsementDocument{SEVSNP: &hex}
	cache.setGroup([]string{"https://example.com/e.json"}, doc, 100, time.Minute)

	u, _ := url.Parse("https://example.com/e.json")
	s := &Server{
		cfg: &Config{
			ReportEvidence:           EvidenceConfig{SEVSNP: true},
			EndorsementClientTimeout: 5 * time.Second,
		},
		endorsements: []*url.URL{u},
		httpCache:    cache,
		selfAttestation: &parsedSelfAttestation{
			sevSNPReport: &spb.Report{Measurement: bytes.Repeat([]byte{0xdd}, 48)},
		},
	}

	if err := s.validateOwnEndorsements(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateOwnEndorsements_CacheHitMismatch(t *testing.T) {
	cache, err := newFetcherCache(100 << 20)
	if err != nil {
		t.Fatal(err)
	}

	hex := strings.Repeat("00", 48) // wrong measurement
	doc := &EndorsementDocument{SEVSNP: &hex}
	cache.setGroup([]string{"https://example.com/e.json"}, doc, 100, time.Minute)

	u, _ := url.Parse("https://example.com/e.json")
	s := &Server{
		cfg: &Config{
			ReportEvidence:           EvidenceConfig{SEVSNP: true},
			EndorsementClientTimeout: 5 * time.Second,
		},
		endorsements: []*url.URL{u},
		httpCache:    cache,
		selfAttestation: &parsedSelfAttestation{
			sevSNPReport: &spb.Report{Measurement: bytes.Repeat([]byte{0xdd}, 48)},
		},
	}

	err = s.validateOwnEndorsements(context.Background())
	if err == nil {
		t.Fatal("expected error for measurement mismatch")
	}
	if !contains(err.Error(), "sevsnp") || !contains(err.Error(), "mismatch") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- resolveEndorsements ---

func TestResolveEndorsements_CacheHit(t *testing.T) {
	cache, err := newFetcherCache(100 << 20)
	if err != nil {
		t.Fatal(err)
	}

	doc := &EndorsementDocument{SEVSNP: strPtr("aabb")}
	cache.setGroup([]string{"https://example.com/e.json"}, doc, 50, time.Minute)

	s := &Server{
		cfg:       &Config{EndorsementClientTimeout: 5 * time.Second},
		httpCache: cache,
	}

	u, _ := url.Parse("https://example.com/e.json")
	got, _, err := s.resolveEndorsements(context.Background(), []*url.URL{u})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != doc {
		t.Error("expected same pointer from cache")
	}
}

func TestResolveEndorsements_CacheMissFetches(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"sevsnp":"aabb"}`))
	}))
	defer srv.Close()

	cache, err := newFetcherCache(100 << 20)
	if err != nil {
		t.Fatal(err)
	}

	s := &Server{
		cfg:       &Config{EndorsementClientTimeout: 5 * time.Second},
		httpCache: cache,
	}

	u, _ := url.Parse(srv.URL + "/e.json")

	// First call should fetch
	doc, _, err := s.resolveEndorsementsWithClient(context.Background(), []*url.URL{u}, srv.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc.SEVSNP == nil || *doc.SEVSNP != "aabb" {
		t.Errorf("SEVSNP = %v, want aabb", doc.SEVSNP)
	}

	// Second call should hit cache (same pointer)
	doc2, _, err := s.resolveEndorsements(context.Background(), []*url.URL{u})
	if err != nil {
		t.Fatalf("unexpected error on cached call: %v", err)
	}
	if doc2 != doc {
		t.Error("expected same pointer from cache on second call")
	}
}

// --- fetchWithRetry ---

func TestFetchWithRetry_RetriesOnError(t *testing.T) {
	var attempts int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte(`ok`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	u, _ := url.Parse(srv.URL + "/e.json")
	body, _, err := fetchWithRetry(ctx, srv.Client(), u, slog.Default())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(body) != "ok" {
		t.Errorf("body = %q, want %q", string(body), "ok")
	}
	if atomic.LoadInt32(&attempts) < 3 {
		t.Errorf("expected at least 3 attempts, got %d", atomic.LoadInt32(&attempts))
	}
}

func TestFetchWithRetry_ContextCancelled(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	u, _ := url.Parse(srv.URL + "/e.json")
	_, _, err := fetchWithRetry(ctx, srv.Client(), u, slog.Default())
	if err == nil {
		t.Fatal("expected error when context expires")
	}
}

// --- cachedHTTPSGetter ---

func TestCachedHTTPSGetter_CachesResponse(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("X-Test", "value")
		w.Write([]byte(`response`))
	}))
	defer srv.Close()

	cache, err := newFetcherCache(100 << 20)
	if err != nil {
		t.Fatal(err)
	}

	getter := &cachedHTTPSGetter{
		inner:  &simpleHTTPSGetter{client: srv.Client()},
		cache:  cache,
		logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}

	// First call: cache miss → network fetch
	header, body, err := getter.Get(srv.URL + "/collateral")
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if string(body) != "response" {
		t.Errorf("body = %q, want %q", string(body), "response")
	}
	if http.Header(header).Get("X-Test") != "value" {
		t.Errorf("header X-Test = %q, want %q", http.Header(header).Get("X-Test"), "value")
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("expected 1 network call, got %d", atomic.LoadInt32(&calls))
	}

	// Second call: cache hit → no network
	header2, body2, err := getter.Get(srv.URL + "/collateral")
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if string(body2) != "response" {
		t.Errorf("cached body = %q, want %q", string(body2), "response")
	}
	if http.Header(header2).Get("X-Test") != "value" {
		t.Errorf("cached header X-Test = %q, want %q", http.Header(header2).Get("X-Test"), "value")
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("expected still 1 network call after cache hit, got %d", atomic.LoadInt32(&calls))
	}
}

func TestCachedHTTPSGetter_PropagatesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cache, err := newFetcherCache(100 << 20)
	if err != nil {
		t.Fatal(err)
	}

	getter := &cachedHTTPSGetter{
		inner: &simpleHTTPSGetter{client: srv.Client()},
		cache: cache,
	}

	_, _, err = getter.Get(srv.URL + "/fail")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}

	// Error should not be cached
	if _, ok := cache.get(srv.URL + "/fail"); ok {
		t.Fatal("error response should not be cached")
	}
}

// --- HTTPS scheme enforcement ---

func TestFetchEndorsementDocuments_RejectsHTTP(t *testing.T) {
	s := &Server{
		cfg: &Config{EndorsementClientTimeout: 5 * time.Second},
	}

	u, _ := url.Parse("http://example.com/e.json")
	_, _, _, _, err := s.fetchEndorsementDocumentsWithClient(context.Background(), []*url.URL{u}, nil)
	if err == nil {
		t.Fatal("expected error for http URL")
	}
	if !contains(err.Error(), "scheme must be https") {
		t.Errorf("error %q does not mention scheme", err)
	}
}

func TestFetchEndorsementDocuments_RejectsMixedSchemes(t *testing.T) {
	s := &Server{
		cfg: &Config{EndorsementClientTimeout: 5 * time.Second},
	}

	u1, _ := url.Parse("https://example.com/e.json")
	u2, _ := url.Parse("http://example.com/e.json")
	_, _, _, _, err := s.fetchEndorsementDocumentsWithClient(context.Background(), []*url.URL{u1, u2}, nil)
	if err == nil {
		t.Fatal("expected error for mixed schemes")
	}
	if !contains(err.Error(), "scheme must be https") {
		t.Errorf("error %q does not mention scheme", err)
	}
}

func TestFetchEndorsementDocuments_RejectsDisallowedDomain(t *testing.T) {
	s := &Server{
		cfg: &Config{
			EndorsementClientTimeout:  5 * time.Second,
			EndorsementAllowedDomains: []string{"trusted.example.com"},
		},
	}

	u, _ := url.Parse("https://evil.attacker.com/endorsement.json")
	_, _, _, _, err := s.fetchEndorsementDocumentsWithClient(context.Background(), []*url.URL{u}, nil)
	if err == nil {
		t.Fatal("expected error for disallowed domain")
	}
	if !contains(err.Error(), "not in allowed domains") {
		t.Errorf("error %q does not mention allowed domains", err)
	}
}

func TestFetchEndorsementDocuments_AllowsPermittedDomain(t *testing.T) {
	s := &Server{
		cfg: &Config{
			EndorsementClientTimeout:  1 * time.Second,
			EndorsementAllowedDomains: []string{"trusted.example.com"},
		},
	}

	// The domain is allowed, but the URL won't resolve — we just check it
	// passes the domain check and fails at the network level instead.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	u, _ := url.Parse("https://trusted.example.com/endorsement.json")
	_, _, _, _, err := s.fetchEndorsementDocumentsWithClient(ctx, []*url.URL{u}, nil)
	if err == nil {
		t.Fatal("expected error (network), but domain check should have passed")
	}
	if contains(err.Error(), "not in allowed domains") {
		t.Errorf("domain check should have passed for allowed domain, got: %v", err)
	}
}

// --- validateDependencyEndorsements ---

func TestValidateDependencyEndorsements_NoEndorsementURLs(t *testing.T) {
	reportData := &AttestationReportData{
		Endorsements: []string{},
	}
	dataJSON, _ := json.Marshal(reportData)
	report := &AttestationReport{
		Evidence: []*AttestationEvidence{{Kind: "sevsnp", Blob: []byte("fake")}},
		Data:     json.RawMessage(dataJSON),
	}

	s := &Server{cfg: &Config{EndorsementClientTimeout: 5 * time.Second}}
	parsed := &parsedDependencyEvidence{}
	if err := s.validateDependencyEndorsements(context.Background(), report, parsed); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateDependencyEndorsements_CacheHit(t *testing.T) {
	cache, err := newFetcherCache(100 << 20)
	if err != nil {
		t.Fatal(err)
	}

	hex := strings.Repeat("dd", 48)
	doc := &EndorsementDocument{SEVSNP: &hex}
	cache.setGroup([]string{"https://dep.example.com/e.json"}, doc, 100, time.Minute)

	reportData := &AttestationReportData{
		Endorsements: []string{"https://dep.example.com/e.json"},
	}
	dataJSON, _ := json.Marshal(reportData)
	report := &AttestationReport{
		Evidence: []*AttestationEvidence{{Kind: "sevsnp", Blob: []byte("fake")}},
		Data:     json.RawMessage(dataJSON),
	}

	s := &Server{
		cfg:       &Config{EndorsementClientTimeout: 5 * time.Second},
		httpCache: cache,
	}
	parsed := &parsedDependencyEvidence{
		sevSNPReport: &spb.Report{Measurement: bytes.Repeat([]byte{0xdd}, 48)},
	}

	if err := s.validateDependencyEndorsements(context.Background(), report, parsed); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateDependencyEndorsements_Mismatch(t *testing.T) {
	cache, err := newFetcherCache(100 << 20)
	if err != nil {
		t.Fatal(err)
	}

	hex := strings.Repeat("00", 48) // different from actual measurement
	doc := &EndorsementDocument{SEVSNP: &hex}
	cache.setGroup([]string{"https://dep.example.com/e.json"}, doc, 100, time.Minute)

	reportData := &AttestationReportData{
		Endorsements: []string{"https://dep.example.com/e.json"},
	}
	dataJSON, _ := json.Marshal(reportData)
	report := &AttestationReport{
		Evidence: []*AttestationEvidence{{Kind: "sevsnp", Blob: []byte("fake")}},
		Data:     json.RawMessage(dataJSON),
	}

	s := &Server{
		cfg:       &Config{EndorsementClientTimeout: 5 * time.Second},
		httpCache: cache,
	}
	parsed := &parsedDependencyEvidence{
		sevSNPReport: &spb.Report{Measurement: bytes.Repeat([]byte{0xdd}, 48)},
	}

	err = s.validateDependencyEndorsements(context.Background(), report, parsed)
	if err == nil {
		t.Fatal("expected error for mismatch")
	}
	if !contains(err.Error(), "sevsnp") || !contains(err.Error(), "mismatch") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateDependencyEndorsements_EvidenceButNoEndorsement(t *testing.T) {
	cache, err := newFetcherCache(100 << 20)
	if err != nil {
		t.Fatal(err)
	}

	// Endorsement document has no SEV-SNP field
	doc := &EndorsementDocument{}
	cache.setGroup([]string{"https://dep.example.com/e.json"}, doc, 100, time.Minute)

	reportData := &AttestationReportData{
		Endorsements: []string{"https://dep.example.com/e.json"},
	}
	dataJSON, _ := json.Marshal(reportData)
	report := &AttestationReport{
		Evidence: []*AttestationEvidence{{Kind: "sevsnp", Blob: []byte("fake")}},
		Data:     json.RawMessage(dataJSON),
	}

	s := &Server{
		cfg:       &Config{EndorsementClientTimeout: 5 * time.Second},
		httpCache: cache,
	}
	parsed := &parsedDependencyEvidence{
		sevSNPReport: &spb.Report{Measurement: bytes.Repeat([]byte{0xdd}, 48)},
	}

	err = s.validateDependencyEndorsements(context.Background(), report, parsed)
	if err == nil {
		t.Fatal("expected error when evidence has no endorsement measurements")
	}
	if !contains(err.Error(), "sevsnp") || !contains(err.Error(), "no measurements") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateDependencyEndorsements_SEVSNPNilParsedEvidence(t *testing.T) {
	cache, err := newFetcherCache(100 << 20)
	if err != nil {
		t.Fatal(err)
	}

	hex := strings.Repeat("dd", 48)
	doc := &EndorsementDocument{SEVSNP: &hex}
	cache.setGroup([]string{"https://dep.example.com/e.json"}, doc, 100, time.Minute)

	reportData := &AttestationReportData{
		Endorsements: []string{"https://dep.example.com/e.json"},
	}
	dataJSON, _ := json.Marshal(reportData)
	report := &AttestationReport{
		Evidence: []*AttestationEvidence{{Kind: "sevsnp", Blob: []byte("fake")}},
		Data:     json.RawMessage(dataJSON),
	}

	s := &Server{
		cfg:       &Config{EndorsementClientTimeout: 5 * time.Second},
		httpCache: cache,
	}
	parsed := &parsedDependencyEvidence{} // sevSNPReport is nil

	err = s.validateDependencyEndorsements(context.Background(), report, parsed)
	if err == nil {
		t.Fatal("expected error for nil parsed evidence")
	}
	if !contains(err.Error(), "sevsnp") || !contains(err.Error(), "no parsed evidence") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateDependencyEndorsements_TPMData(t *testing.T) {
	cache, err := newFetcherCache(100 << 20)
	if err != nil {
		t.Fatal(err)
	}

	doc := &EndorsementDocument{
		TPM: &PCRGoldenValues{0: bytes.Repeat([]byte{0xaa}, 48)},
	}
	cache.setGroup([]string{"https://dep.example.com/e.json"}, doc, 100, time.Minute)

	reportData := &AttestationReportData{
		Endorsements: []string{"https://dep.example.com/e.json"},
		TPMData: &TPMData{
			Digest: "SHA384",
			PCRs:   map[int]hexbytes.Bytes{0: bytes.Repeat([]byte{0xaa}, 48)},
		},
	}
	dataJSON, _ := json.Marshal(reportData)
	report := &AttestationReport{
		Evidence: []*AttestationEvidence{},
		Data:     json.RawMessage(dataJSON),
	}

	s := &Server{
		cfg:       &Config{EndorsementClientTimeout: 5 * time.Second},
		httpCache: cache,
	}
	parsed := &parsedDependencyEvidence{}

	if err := s.validateDependencyEndorsements(context.Background(), report, parsed); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- validateDependencyEndorsements: additional evidence paths ---

func TestValidateDependencyEndorsements_NitroNSM(t *testing.T) {
	cache, err := newFetcherCache(100 << 20)
	if err != nil {
		t.Fatal(err)
	}

	doc := &EndorsementDocument{
		NitroNSM: &PCRGoldenValues{0: bytes.Repeat([]byte{0xaa}, 48), 1: bytes.Repeat([]byte{0xcc}, 48)},
	}
	cache.setGroup([]string{"https://dep.example.com/e.json"}, doc, 100, time.Minute)

	reportData := &AttestationReportData{
		Endorsements: []string{"https://dep.example.com/e.json"},
	}
	dataJSON, _ := json.Marshal(reportData)

	t.Run("match", func(t *testing.T) {
		report := &AttestationReport{
			Evidence: []*AttestationEvidence{{Kind: "nitronsm", Blob: []byte("fake")}},
			Data:     json.RawMessage(dataJSON),
		}
		s := &Server{cfg: &Config{EndorsementClientTimeout: 5 * time.Second}, httpCache: cache}
		parsed := &parsedDependencyEvidence{
			nitroNSMDoc: &nitro.AttestationDocument{
				PCRs: map[int][]byte{0: bytes.Repeat([]byte{0xaa}, 48), 1: bytes.Repeat([]byte{0xcc}, 48)},
			},
		}
		if err := s.validateDependencyEndorsements(context.Background(), report, parsed); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		report := &AttestationReport{
			Evidence: []*AttestationEvidence{{Kind: "nitronsm", Blob: []byte("fake")}},
			Data:     json.RawMessage(dataJSON),
		}
		s := &Server{cfg: &Config{EndorsementClientTimeout: 5 * time.Second}, httpCache: cache}
		parsed := &parsedDependencyEvidence{
			nitroNSMDoc: &nitro.AttestationDocument{
				PCRs: map[int][]byte{0: bytes.Repeat([]byte{0xff}, 48), 1: bytes.Repeat([]byte{0xcc}, 48)},
			},
		}
		err := s.validateDependencyEndorsements(context.Background(), report, parsed)
		if err == nil {
			t.Fatal("expected error for mismatch")
		}
		if !contains(err.Error(), "nitronsm") {
			t.Errorf("error %q does not mention nitronsm", err)
		}
	})

	t.Run("nil parsed evidence", func(t *testing.T) {
		report := &AttestationReport{
			Evidence: []*AttestationEvidence{{Kind: "nitronsm", Blob: []byte("fake")}},
			Data:     json.RawMessage(dataJSON),
		}
		s := &Server{cfg: &Config{EndorsementClientTimeout: 5 * time.Second}, httpCache: cache}
		parsed := &parsedDependencyEvidence{}
		err := s.validateDependencyEndorsements(context.Background(), report, parsed)
		if err == nil {
			t.Fatal("expected error for nil parsed evidence")
		}
		if !contains(err.Error(), "no parsed evidence") {
			t.Errorf("error %q does not mention no parsed evidence", err)
		}
	})
}

func TestValidateDependencyEndorsements_NitroTPM(t *testing.T) {
	cache, err := newFetcherCache(100 << 20)
	if err != nil {
		t.Fatal(err)
	}

	doc := &EndorsementDocument{
		NitroTPM: &PCRGoldenValues{4: bytes.Repeat([]byte{0x11}, 48)},
	}
	cache.setGroup([]string{"https://dep.example.com/e.json"}, doc, 100, time.Minute)

	reportData := &AttestationReportData{
		Endorsements: []string{"https://dep.example.com/e.json"},
	}
	dataJSON, _ := json.Marshal(reportData)

	t.Run("match", func(t *testing.T) {
		report := &AttestationReport{
			Evidence: []*AttestationEvidence{{Kind: "nitrotpm", Blob: []byte("fake")}},
			Data:     json.RawMessage(dataJSON),
		}
		s := &Server{cfg: &Config{EndorsementClientTimeout: 5 * time.Second}, httpCache: cache}
		parsed := &parsedDependencyEvidence{
			nitroTPMDoc: &nitro.AttestationDocument{
				NitroTPMPCRs: map[int][]byte{4: bytes.Repeat([]byte{0x11}, 48)},
			},
		}
		if err := s.validateDependencyEndorsements(context.Background(), report, parsed); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("no endorsement measurements", func(t *testing.T) {
		emptyDoc := &EndorsementDocument{}
		emptyCache, _ := newFetcherCache(100 << 20)
		emptyCache.setGroup([]string{"https://dep.example.com/e.json"}, emptyDoc, 100, time.Minute)

		report := &AttestationReport{
			Evidence: []*AttestationEvidence{{Kind: "nitrotpm", Blob: []byte("fake")}},
			Data:     json.RawMessage(dataJSON),
		}
		s := &Server{cfg: &Config{EndorsementClientTimeout: 5 * time.Second}, httpCache: emptyCache}
		parsed := &parsedDependencyEvidence{
			nitroTPMDoc: &nitro.AttestationDocument{NitroTPMPCRs: map[int][]byte{4: {0x11}}},
		}
		err := s.validateDependencyEndorsements(context.Background(), report, parsed)
		if err == nil {
			t.Fatal("expected error when endorsement has no measurements")
		}
		if !contains(err.Error(), "nitrotpm") || !contains(err.Error(), "no measurements") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestValidateDependencyEndorsements_TDX(t *testing.T) {
	cache, err := newFetcherCache(100 << 20)
	if err != nil {
		t.Fatal(err)
	}

	mrtdHex := strings.Repeat("11", 48)
	doc := &EndorsementDocument{
		TDX: &TDXEndorsement{MRTD: mrtdHex},
	}
	cache.setGroup([]string{"https://dep.example.com/e.json"}, doc, 100, time.Minute)

	reportData := &AttestationReportData{
		Endorsements: []string{"https://dep.example.com/e.json"},
	}
	dataJSON, _ := json.Marshal(reportData)

	t.Run("match", func(t *testing.T) {
		report := &AttestationReport{
			Evidence: []*AttestationEvidence{{Kind: "tdx", Blob: []byte("fake")}},
			Data:     json.RawMessage(dataJSON),
		}
		s := &Server{cfg: &Config{EndorsementClientTimeout: 5 * time.Second}, httpCache: cache}
		parsed := &parsedDependencyEvidence{
			tdxQuote: &pb.QuoteV4{TdQuoteBody: &pb.TDQuoteBody{MrTd: bytes.Repeat([]byte{0x11}, 48)}},
		}
		if err := s.validateDependencyEndorsements(context.Background(), report, parsed); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		report := &AttestationReport{
			Evidence: []*AttestationEvidence{{Kind: "tdx", Blob: []byte("fake")}},
			Data:     json.RawMessage(dataJSON),
		}
		s := &Server{cfg: &Config{EndorsementClientTimeout: 5 * time.Second}, httpCache: cache}
		parsed := &parsedDependencyEvidence{
			tdxQuote: &pb.QuoteV4{TdQuoteBody: &pb.TDQuoteBody{MrTd: bytes.Repeat([]byte{0xff}, 48)}},
		}
		err := s.validateDependencyEndorsements(context.Background(), report, parsed)
		if err == nil {
			t.Fatal("expected error for mismatch")
		}
		if !contains(err.Error(), "tdx") {
			t.Errorf("error %q does not mention tdx", err)
		}
	})

	t.Run("nil parsed evidence", func(t *testing.T) {
		report := &AttestationReport{
			Evidence: []*AttestationEvidence{{Kind: "tdx", Blob: []byte("fake")}},
			Data:     json.RawMessage(dataJSON),
		}
		s := &Server{cfg: &Config{EndorsementClientTimeout: 5 * time.Second}, httpCache: cache}
		parsed := &parsedDependencyEvidence{}
		err := s.validateDependencyEndorsements(context.Background(), report, parsed)
		if err == nil {
			t.Fatal("expected error for nil parsed evidence")
		}
		if !contains(err.Error(), "no parsed evidence") {
			t.Errorf("error %q does not mention no parsed evidence", err)
		}
	})
}

func TestValidateDependencyEndorsements_TPMNoEndorsement(t *testing.T) {
	cache, err := newFetcherCache(100 << 20)
	if err != nil {
		t.Fatal(err)
	}

	doc := &EndorsementDocument{} // no TPM field
	cache.setGroup([]string{"https://dep.example.com/e.json"}, doc, 100, time.Minute)

	reportData := &AttestationReportData{
		Endorsements: []string{"https://dep.example.com/e.json"},
		TPMData: &TPMData{
			Digest: "SHA256",
			PCRs:   map[int]hexbytes.Bytes{0: {0xaa}},
		},
	}
	dataJSON, _ := json.Marshal(reportData)
	report := &AttestationReport{
		Evidence: []*AttestationEvidence{},
		Data:     json.RawMessage(dataJSON),
	}

	s := &Server{cfg: &Config{EndorsementClientTimeout: 5 * time.Second}, httpCache: cache}
	parsed := &parsedDependencyEvidence{}

	err = s.validateDependencyEndorsements(context.Background(), report, parsed)
	if err == nil {
		t.Fatal("expected error when TPM data has no endorsement")
	}
	if !contains(err.Error(), "tpm") || !contains(err.Error(), "no measurements") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- Edge case tests for measurement comparison ---

func TestValidateSEVSNPMeasurement_Empty(t *testing.T) {
	report := &spb.Report{Measurement: bytes.Repeat([]byte{0xdd}, 48)}
	err := validateSEVSNPMeasurement(report, "")
	if err == nil {
		t.Fatal("expected error for empty endorsement measurement")
	}
	if !contains(err.Error(), "empty measurement") {
		t.Errorf("error %q does not mention empty measurement", err)
	}
}

func TestValidateTPMMeasurements_MissingPCR(t *testing.T) {
	pcrs := map[int]hexbytes.Bytes{0: {0xaa}}
	endorsement := PCRGoldenValues{5: bytes.Repeat([]byte{0xaa}, 48)}
	err := validateTPMMeasurements(pcrs, endorsement)
	if err == nil {
		t.Fatal("expected error for missing PCR in evidence")
	}
	if !contains(err.Error(), "missing from evidence") {
		t.Errorf("error %q does not mention missing from evidence", err)
	}
}

func TestValidateTDXMeasurements_AllFieldsEmpty(t *testing.T) {
	quote := &pb.QuoteV4{
		TdQuoteBody: &pb.TDQuoteBody{
			MrTd:  bytes.Repeat([]byte{0x11}, 48),
			Rtmrs: [][]byte{bytes.Repeat([]byte{0x22}, 48)},
		},
	}
	endorsement := &TDXEndorsement{} // all fields empty
	err := validateTDXMeasurements(quote, endorsement)
	if err == nil {
		t.Fatal("expected error for endorsement with all empty fields")
	}
	if !contains(err.Error(), "no measurements") {
		t.Errorf("error %q does not mention no measurements", err)
	}
}

func TestValidateTDXMeasurements_InvalidHex(t *testing.T) {
	quote := &pb.QuoteV4{
		TdQuoteBody: &pb.TDQuoteBody{
			MrTd: bytes.Repeat([]byte{0x11}, 48),
		},
	}
	endorsement := &TDXEndorsement{MRTD: "not-valid-hex"}
	err := validateTDXMeasurements(quote, endorsement)
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
	if !contains(err.Error(), "invalid hex") {
		t.Errorf("error %q does not mention invalid hex", err)
	}
}

func TestGetRTMR_OutOfRange(t *testing.T) {
	body := &pb.TDQuoteBody{
		Rtmrs: [][]byte{{0x01}, {0x02}},
	}
	if got := getRTMR(body, 5); got != nil {
		t.Errorf("getRTMR(body, 5) = %v, want nil", got)
	}
	if got := getRTMR(body, 0); !bytes.Equal(got, []byte{0x01}) {
		t.Errorf("getRTMR(body, 0) = %v, want [0x01]", got)
	}
}

func TestPCRGoldenValues_UnmarshalJSON_NegativeIndex(t *testing.T) {
	input := `{"PCR-1":"` + strings.Repeat("aa", 48) + `"}`
	var v PCRGoldenValues
	err := json.Unmarshal([]byte(input), &v)
	if err == nil {
		t.Fatal("expected error for negative PCR index")
	}
}

func TestPCRGoldenValues_UnmarshalJSON_InvalidJSON(t *testing.T) {
	var v PCRGoldenValues
	err := json.Unmarshal([]byte(`not json`), &v)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// --- Fuzz tests ---

// FuzzParseCacheTTL ensures parseCacheTTL never panics on arbitrary
// HTTP headers. Cache-Control headers come from untrusted CDN/origin servers.
func FuzzParseCacheTTL(f *testing.F) {
	f.Add("max-age=600")
	f.Add("no-cache, no-store")
	f.Add("public, max-age=86400, s-maxage=3600")
	f.Add("")
	f.Add("max-age=abc")
	f.Add("max-age=-1")
	f.Add("max-age=99999999999999")
	f.Fuzz(func(t *testing.T, cc string) {
		h := http.Header{}
		h.Set("Cache-Control", cc)
		parseCacheTTL(h)
	})
}

// FuzzParseByteSize ensures parseByteSize never panics on arbitrary input.
func FuzzParseByteSize(f *testing.F) {
	f.Add("100MiB")
	f.Add("1GiB")
	f.Add("100MB")
	f.Add("1.5GiB")
	f.Add(" 10 MiB ")
	f.Add("")
	f.Add("0")
	f.Add("-1")
	f.Add("abc")
	f.Add("999999999999999999999TiB")
	f.Fuzz(func(t *testing.T, input string) {
		parseByteSize(input)
	})
}

// FuzzPCRGoldenValues_UnmarshalJSON ensures PCR golden value parsing
// never panics on arbitrary JSON. Endorsement documents come from
// external URLs.
func FuzzPCRGoldenValues_UnmarshalJSON(f *testing.F) {
	f.Add(`{"PCR0":"` + strings.Repeat("aa", 48) + `"}`)
	f.Add(`{}`)
	f.Add(`{"PCR99":"ff"}`)
	f.Add(`not json`)
	f.Add(`{"PCR-1":"aa","PCRabc":"bb"}`)
	f.Add(`{"0":"aabb"}`)
	f.Add(`{"foo":"aabb"}`)
	f.Fuzz(func(t *testing.T, input string) {
		var v PCRGoldenValues
		json.Unmarshal([]byte(input), &v)
	})
}

func strPtr(s string) *string { return &s }
