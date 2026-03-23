package app

import (
	"bytes"
	"context"
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
	tests := []struct {
		name      string
		input     string
		wantAlg   string
		wantPCRs  map[int]string
		wantError bool
	}{
		{
			name:     "nitro nsm style",
			input:    `{"HashAlgorithm":"Sha384 { ... }","PCR0":"aabb","PCR1":"ccdd","PCR2":"eeff"}`,
			wantAlg:  "Sha384 { ... }",
			wantPCRs: map[int]string{0: "aabb", 1: "ccdd", 2: "eeff"},
		},
		{
			name:     "nitro tpm style",
			input:    `{"HashAlgorithm":"SHA384 { ... }","PCR4":"1111","PCR7":"2222","PCR12":"3333"}`,
			wantAlg:  "SHA384 { ... }",
			wantPCRs: map[int]string{4: "1111", 7: "2222", 12: "3333"},
		},
		{
			name:     "empty PCR value skipped",
			input:    `{"HashAlgorithm":"SHA256","PCR0":"aabb","PCR1":""}`,
			wantAlg:  "SHA256",
			wantPCRs: map[int]string{0: "aabb"},
		},
		{
			name:     "no PCRs",
			input:    `{"HashAlgorithm":"SHA384"}`,
			wantAlg:  "SHA384",
			wantPCRs: map[int]string{},
		},
		{
			name:      "invalid PCR index",
			input:     `{"HashAlgorithm":"SHA384","PCRnotanumber":"aabb"}`,
			wantError: true,
		},
		{
			name:      "PCR index out of range",
			input:     `{"HashAlgorithm":"SHA384","PCR25":"aabb"}`,
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
			if v.HashAlgorithm != tt.wantAlg {
				t.Errorf("HashAlgorithm = %q, want %q", v.HashAlgorithm, tt.wantAlg)
			}
			if len(v.PCRs) != len(tt.wantPCRs) {
				t.Fatalf("PCRs length = %d, want %d", len(v.PCRs), len(tt.wantPCRs))
			}
			for idx, want := range tt.wantPCRs {
				if got := v.PCRs[idx]; got != want {
					t.Errorf("PCR%d = %q, want %q", idx, got, want)
				}
			}
		})
	}
}

// --- EndorsementDocument parsing ---

func TestParseEndorsementDocument(t *testing.T) {
	doc := `{
		"nitronsm": {"Measurements": {"HashAlgorithm": "Sha384 { ... }", "PCR0": "aa", "PCR1": "bb", "PCR2": "cc"}},
		"nitrotpm": {"Measurements": {"HashAlgorithm": "SHA384 { ... }", "PCR4": "dd", "PCR7": "ee"}},
		"sevsnp": "aabbccddee00112233445566778899aabbccddee00112233445566778899aabbccddee001122334455667788aabbccdd",
		"tdx": {"MRTD": "1122", "RTMR0": "3344"},
		"tpm": {"Measurements": {"HashAlgorithm": "SHA256", "PCR0": "ff00"}}
	}`

	var ed EndorsementDocument
	if err := json.Unmarshal([]byte(doc), &ed); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if ed.NitroNSM == nil {
		t.Fatal("NitroNSM is nil")
	}
	if got := ed.NitroNSM.Measurements.PCRs[0]; got != "aa" {
		t.Errorf("NitroNSM PCR0 = %q, want %q", got, "aa")
	}

	if ed.NitroTPM == nil {
		t.Fatal("NitroTPM is nil")
	}
	if got := ed.NitroTPM.Measurements.PCRs[4]; got != "dd" {
		t.Errorf("NitroTPM PCR4 = %q, want %q", got, "dd")
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
	if got := ed.TPM.Measurements.PCRs[0]; got != "ff00" {
		t.Errorf("TPM PCR0 = %q, want %q", got, "ff00")
	}
}

// --- Measurement comparison ---

func TestValidateNitroNSMMeasurements(t *testing.T) {
	doc := &nitro.AttestationDocument{
		PCRs: map[int][]byte{
			0: {0xaa, 0xbb},
			1: {0xcc, 0xdd},
			2: {0xee, 0xff},
		},
	}

	t.Run("match", func(t *testing.T) {
		endorsement := &PCREndorsement{Measurements: PCRGoldenValues{
			PCRs: map[int]string{0: "aabb", 1: "ccdd", 2: "eeff"},
		}}
		if err := validateNitroNSMMeasurements(doc, endorsement); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		endorsement := &PCREndorsement{Measurements: PCRGoldenValues{
			PCRs: map[int]string{0: "aabb", 1: "0000"},
		}}
		err := validateNitroNSMMeasurements(doc, endorsement)
		if err == nil {
			t.Fatal("expected error for mismatch")
		}
		if !contains(err.Error(), "PCR1 mismatch") {
			t.Errorf("error %q does not mention PCR1 mismatch", err)
		}
	})

	t.Run("missing PCR in evidence", func(t *testing.T) {
		endorsement := &PCREndorsement{Measurements: PCRGoldenValues{
			PCRs: map[int]string{8: "aabb"},
		}}
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
			4:  {0x11, 0x22},
			7:  {0x33, 0x44},
			12: {0x55, 0x66},
		},
	}

	t.Run("match", func(t *testing.T) {
		endorsement := &PCREndorsement{Measurements: PCRGoldenValues{
			PCRs: map[int]string{4: "1122", 7: "3344", 12: "5566"},
		}}
		if err := validateNitroTPMMeasurements(doc, endorsement); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		endorsement := &PCREndorsement{Measurements: PCRGoldenValues{
			PCRs: map[int]string{4: "ffff"},
		}}
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
		0: {0xaa, 0xbb},
		1: {0xcc, 0xdd},
	}

	t.Run("match", func(t *testing.T) {
		endorsement := &PCREndorsement{Measurements: PCRGoldenValues{
			PCRs: map[int]string{0: "aabb", 1: "ccdd"},
		}}
		if err := validateTPMMeasurements(pcrs, endorsement); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("subset match", func(t *testing.T) {
		endorsement := &PCREndorsement{Measurements: PCRGoldenValues{
			PCRs: map[int]string{0: "aabb"},
		}}
		if err := validateTPMMeasurements(pcrs, endorsement); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		endorsement := &PCREndorsement{Measurements: PCRGoldenValues{
			PCRs: map[int]string{1: "ffff"},
		}}
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
		{"100MiB", 100 << 20, false},
		{"1GiB", 1 << 30, false},
		{"512KiB", 512 << 10, false},
		{"1024B", 1024, false},
		{"2TiB", 2 << 40, false},
		{"42", 42, false},
		{"0", 0, false},
		{"", 0, true},
		{"abc", 0, true},
		{"-1MiB", 0, true},
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
	origClient := s.endorsementHTTPClient()
	_ = origClient // we need to use TLS test servers' transport

	// Create a client that trusts the test servers
	doc, _, ttl, err := s.fetchEndorsementDocumentsWithClient(context.Background(), []*url.URL{u1, u2}, srv1.Client())
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

	_, _, _, err := s.fetchEndorsementDocumentsWithClient(context.Background(), []*url.URL{u1, u2}, srv1.Client())
	if err == nil {
		t.Fatal("expected error for mismatched documents")
	}
	if !contains(err.Error(), "mismatch") {
		t.Errorf("error %q does not mention mismatch", err)
	}
}

// --- Endorsement cache ---

func TestEndorsementCache_SetGroupAndGet(t *testing.T) {
	cache, err := newEndorsementCache(100 << 20)
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
	cache, err := newEndorsementCache(100 << 20)
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
			PCRs: map[int][]byte{0: {0xaa}, 1: {0xbb}, 2: {0xcc}},
		},
		sevSNPReport: &spb.Report{
			Measurement: bytes.Repeat([]byte{0xdd}, 48),
		},
		tpmPCRs: map[int]hexbytes.Bytes{
			0: {0x11, 0x22},
		},
	}

	t.Run("nitronsm match", func(t *testing.T) {
		doc := &EndorsementDocument{
			NitroNSM: &PCREndorsement{Measurements: PCRGoldenValues{
				PCRs: map[int]string{0: "aa", 1: "bb", 2: "cc"},
			}},
		}
		cfg := &Config{ReportEvidence: EvidenceConfig{NitroNSM: true}}
		if err := validateEndorsementsAgainstEvidence(doc, cfg, sa); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("nitronsm configured but missing in endorsement", func(t *testing.T) {
		doc := &EndorsementDocument{}
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
		doc := &EndorsementDocument{SEVSNP: &hex}
		cfg := &Config{ReportEvidence: EvidenceConfig{SEVSNP: true}}
		if err := validateEndorsementsAgainstEvidence(doc, cfg, sa); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("sevsnp configured but missing in endorsement", func(t *testing.T) {
		doc := &EndorsementDocument{}
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
		doc := &EndorsementDocument{SEVSNP: &hex}
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
		doc := &EndorsementDocument{}
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
		doc := &EndorsementDocument{
			TPM: &PCREndorsement{Measurements: PCRGoldenValues{
				PCRs: map[int]string{0: "1122"},
			}},
		}
		cfg := &Config{TPM: TPMConfig{Enabled: true}}
		if err := validateEndorsementsAgainstEvidence(doc, cfg, sa); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("tdx configured but missing in endorsement", func(t *testing.T) {
		doc := &EndorsementDocument{}
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
		doc := &EndorsementDocument{}
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
		doc := &EndorsementDocument{}
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
	cache, err := newEndorsementCache(100 << 20)
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
		endCache:     cache,
		selfAttestation: &parsedSelfAttestation{
			sevSNPReport: &spb.Report{Measurement: bytes.Repeat([]byte{0xdd}, 48)},
		},
	}

	if err := s.validateOwnEndorsements(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateOwnEndorsements_CacheHitMismatch(t *testing.T) {
	cache, err := newEndorsementCache(100 << 20)
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
		endCache:     cache,
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
	cache, err := newEndorsementCache(100 << 20)
	if err != nil {
		t.Fatal(err)
	}

	doc := &EndorsementDocument{SEVSNP: strPtr("aabb")}
	cache.setGroup([]string{"https://example.com/e.json"}, doc, 50, time.Minute)

	s := &Server{
		cfg:      &Config{EndorsementClientTimeout: 5 * time.Second},
		endCache: cache,
	}

	u, _ := url.Parse("https://example.com/e.json")
	got, err := s.resolveEndorsements(context.Background(), []*url.URL{u})
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

	cache, err := newEndorsementCache(100 << 20)
	if err != nil {
		t.Fatal(err)
	}

	s := &Server{
		cfg:      &Config{EndorsementClientTimeout: 5 * time.Second},
		endCache: cache,
	}

	u, _ := url.Parse(srv.URL + "/e.json")

	// First call should fetch
	doc, err := s.resolveEndorsementsWithClient(context.Background(), []*url.URL{u}, srv.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc.SEVSNP == nil || *doc.SEVSNP != "aabb" {
		t.Errorf("SEVSNP = %v, want aabb", doc.SEVSNP)
	}

	// Second call should hit cache (same pointer)
	doc2, err := s.resolveEndorsements(context.Background(), []*url.URL{u})
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
	body, _, err := fetchWithRetry(ctx, srv.Client(), u)
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
	_, _, err := fetchWithRetry(ctx, srv.Client(), u)
	if err == nil {
		t.Fatal("expected error when context expires")
	}
}

// --- HTTPS scheme enforcement ---

func TestFetchEndorsementDocuments_RejectsHTTP(t *testing.T) {
	s := &Server{
		cfg: &Config{EndorsementClientTimeout: 5 * time.Second},
	}

	u, _ := url.Parse("http://example.com/e.json")
	_, _, _, err := s.fetchEndorsementDocumentsWithClient(context.Background(), []*url.URL{u}, nil)
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
	_, _, _, err := s.fetchEndorsementDocumentsWithClient(context.Background(), []*url.URL{u1, u2}, nil)
	if err == nil {
		t.Fatal("expected error for mixed schemes")
	}
	if !contains(err.Error(), "scheme must be https") {
		t.Errorf("error %q does not mention scheme", err)
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
	cache, err := newEndorsementCache(100 << 20)
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
		cfg:      &Config{EndorsementClientTimeout: 5 * time.Second},
		endCache: cache,
	}
	parsed := &parsedDependencyEvidence{
		sevSNPReport: &spb.Report{Measurement: bytes.Repeat([]byte{0xdd}, 48)},
	}

	if err := s.validateDependencyEndorsements(context.Background(), report, parsed); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateDependencyEndorsements_Mismatch(t *testing.T) {
	cache, err := newEndorsementCache(100 << 20)
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
		cfg:      &Config{EndorsementClientTimeout: 5 * time.Second},
		endCache: cache,
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
	cache, err := newEndorsementCache(100 << 20)
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
		cfg:      &Config{EndorsementClientTimeout: 5 * time.Second},
		endCache: cache,
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

func TestValidateDependencyEndorsements_TPMData(t *testing.T) {
	cache, err := newEndorsementCache(100 << 20)
	if err != nil {
		t.Fatal(err)
	}

	doc := &EndorsementDocument{
		TPM: &PCREndorsement{Measurements: PCRGoldenValues{
			PCRs: map[int]string{0: "aabb"},
		}},
	}
	cache.setGroup([]string{"https://dep.example.com/e.json"}, doc, 100, time.Minute)

	reportData := &AttestationReportData{
		Endorsements: []string{"https://dep.example.com/e.json"},
		TPMData: &TPMData{
			Digest: "SHA256",
			PCRs:   map[int]hexbytes.Bytes{0: {0xaa, 0xbb}},
		},
	}
	dataJSON, _ := json.Marshal(reportData)
	report := &AttestationReport{
		Evidence: []*AttestationEvidence{},
		Data:     json.RawMessage(dataJSON),
	}

	s := &Server{
		cfg:      &Config{EndorsementClientTimeout: 5 * time.Second},
		endCache: cache,
	}
	parsed := &parsedDependencyEvidence{}

	if err := s.validateDependencyEndorsements(context.Background(), report, parsed); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func strPtr(s string) *string { return &s }
