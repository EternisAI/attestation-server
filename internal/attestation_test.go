package app

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eternisai/attestation-server/pkg/nitro"
	"github.com/eternisai/attestation-server/pkg/sevsnp"
	"github.com/google/go-sev-guest/abi"
)

func TestExtractXFCCHash(t *testing.T) {
	tests := []struct {
		name string
		xfcc string
		want string
	}{
		{
			name: "empty string",
			xfcc: "",
			want: "",
		},
		{
			name: "single entry with Hash",
			xfcc: "Hash=abcd1234",
			want: "abcd1234",
		},
		{
			name: "multiple entries rightmost wins",
			xfcc: "Hash=aaaa1111,Hash=bbbb2222",
			want: "bbbb2222",
		},
		{
			name: "multiple entries rightmost has no Hash",
			xfcc: "Hash=aaaa1111,By=spiffe://example",
			want: "",
		},
		{
			name: "no Hash field",
			xfcc: "By=spiffe://cluster.local/ns/default;URI=spiffe://cluster.local/ns/default",
			want: "",
		},
		{
			name: "Hash with invalid hex odd length",
			xfcc: "Hash=abcde",
			want: "",
		},
		{
			name: "Hash with non-hex characters",
			xfcc: "Hash=zzzz1234",
			want: "",
		},
		{
			name: "standard Envoy format",
			xfcc: "By=spiffe://cluster.local/ns/default;Hash=abcd1234ef567890;URI=spiffe://cluster.local/sa/client",
			want: "abcd1234ef567890",
		},
		{
			name: "standard Envoy format multiple entries rightmost wins",
			xfcc: "By=spiffe://a;Hash=aaaa1111,By=spiffe://b;Hash=bbbb2222;URI=spiffe://b",
			want: "bbbb2222",
		},
		{
			name: "whitespace around fields",
			xfcc: " By=spiffe://example ; Hash=abcd1234 ; URI=spiffe://example ",
			want: "abcd1234",
		},
		{
			name: "whitespace around Hash in multiple entries",
			xfcc: "Hash=aaaa1111, Hash=bbbb2222 ",
			want: "bbbb2222",
		},
		{
			name: "Hash field with empty value",
			xfcc: "Hash=",
			want: "",
		},
		{
			name: "Hash field 64-char SHA-256 hex",
			xfcc: "Hash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			want: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name: "Hash field 128-char hex at max length",
			xfcc: "Hash=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			want: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		},
		{
			name: "Hash field exceeds 128 chars",
			xfcc: "Hash=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567890a",
			want: "",
		},
		{
			name: "multiple Hash fields in same entry uses first match",
			xfcc: "Hash=aabb1122;Hash=ccdd3344",
			want: "aabb1122",
		},
		{
			name: "Hash prefix as substring of another key",
			xfcc: "SomeHash=1234;Hash=aabb1122",
			want: "aabb1122",
		},
		{
			name: "only comma no Hash",
			xfcc: ",",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractXFCCHash(tt.xfcc)
			if got != tt.want {
				t.Errorf("extractXFCCHash(%q) = %q, want %q", tt.xfcc, got, tt.want)
			}
		})
	}
}

func TestIsValidHexFingerprint(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "empty string",
			input: "",
			want:  false,
		},
		{
			name:  "valid 64-char hex SHA-256",
			input: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			want:  true,
		},
		{
			name:  "valid 128-char hex at max length",
			input: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			want:  true,
		},
		{
			name:  "odd-length hex string",
			input: "abcde",
			want:  false,
		},
		{
			name:  "non-hex characters",
			input: "zzzzzzzz",
			want:  false,
		},
		{
			name:  "mixed valid and invalid hex chars",
			input: "abcd12gh",
			want:  false,
		},
		{
			name:  "exceeds 128 chars",
			input: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567890a",
			want:  false,
		},
		{
			name:  "short valid hex",
			input: "abcdef",
			want:  true,
		},
		{
			name:  "two char hex",
			input: "ff",
			want:  true,
		},
		{
			name:  "uppercase hex",
			input: "ABCDEF0123456789",
			want:  true,
		},
		{
			name:  "mixed case hex",
			input: "aAbBcCdDeEfF",
			want:  true,
		},
		{
			name:  "single char not valid hex decode",
			input: "a",
			want:  false,
		},
		{
			name:  "spaces in hex",
			input: "ab cd",
			want:  false,
		},
		{
			name:  "exactly 129 chars",
			input: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789a",
			want:  false,
		},
		{
			name:  "130 chars even length still too long",
			input: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567890a",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidHexFingerprint(tt.input)
			if got != tt.want {
				t.Errorf("isValidHexFingerprint(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// chainedFixture is the JSON format for chained attestation test fixtures.
type chainedFixture struct {
	Time   string `json:"time"`
	Report struct {
		Evidence []struct {
			Kind    string          `json:"kind"`
			Blob    string          `json:"blob"`
			RawData json.RawMessage `json:"data"`
		} `json:"evidence"`
		Data json.RawMessage `json:"data"`
	} `json:"report"`
}

// TestChainedAttestation_NitroTPM_SEVSNP verifies the chained attestation
// flow where the NitroTPM blob's SHA-512 digest is used as the SEV-SNP
// report_data, binding both evidence entries to the same request.
// This mirrors the logic in handleAttestation when both NitroTPM and
// SEV-SNP evidence types are enabled.
func TestChainedAttestation_NitroTPM_SEVSNP(t *testing.T) {
	path := filepath.Join("testdata", "nitrotpm_sevsnp_attestation.json")
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skip("fixture testdata/nitrotpm_sevsnp_attestation.json not found, skipping")
	}
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	var f chainedFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}

	if len(f.Report.Evidence) < 2 {
		t.Fatalf("fixture has %d evidence entries, want at least 2", len(f.Report.Evidence))
	}

	// Find NitroTPM and SEV-SNP evidence entries by kind.
	var nitroTPMEntry, sevsnpEntry *struct {
		Kind    string          `json:"kind"`
		Blob    string          `json:"blob"`
		RawData json.RawMessage `json:"data"`
	}
	for i := range f.Report.Evidence {
		switch f.Report.Evidence[i].Kind {
		case "nitrotpm":
			nitroTPMEntry = &f.Report.Evidence[i]
		case "sevsnp":
			sevsnpEntry = &f.Report.Evidence[i]
		}
	}
	if nitroTPMEntry == nil {
		t.Fatal("fixture missing nitrotpm evidence entry")
	}
	if sevsnpEntry == nil {
		t.Fatal("fixture missing sevsnp evidence entry")
	}

	now, err := time.Parse(time.RFC3339Nano, f.Time)
	if err != nil {
		t.Fatalf("parsing time: %v", err)
	}

	// Derive the nonce from report data, matching the handler's flow:
	// digest = SHA-512(compact(reportDataJSON))
	var buf bytes.Buffer
	if err := json.Compact(&buf, f.Report.Data); err != nil {
		t.Fatalf("compacting fixture data JSON: %v", err)
	}
	digest := sha512.Sum512(buf.Bytes())

	// Decode the NitroTPM blob.
	nitroTPMBlob, err := base64.StdEncoding.DecodeString(nitroTPMEntry.Blob)
	if err != nil {
		t.Fatalf("decoding nitrotpm blob: %v", err)
	}

	// Step 1: Verify NitroTPM attestation with digest as nonce.
	t.Run("nitrotpm verification", func(t *testing.T) {
		doc, err := nitro.VerifyAttestation(nitroTPMBlob, digest[:], now)
		if err != nil {
			t.Fatalf("nitro.VerifyAttestation() error: %v", err)
		}
		if !bytes.Equal(doc.Nonce, digest[:]) {
			t.Error("NitroTPM nonce does not match expected digest")
		}

		// Cross-check NewAttestationData JSON.
		got := nitro.NewAttestationData(doc)
		gotJSON, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("marshaling nitro.NewAttestationData: %v", err)
		}
		if len(nitroTPMEntry.RawData) > 0 {
			var fixtureCompact, gotCompact bytes.Buffer
			json.Compact(&fixtureCompact, nitroTPMEntry.RawData)
			json.Compact(&gotCompact, gotJSON)
			if fixtureCompact.String() != gotCompact.String() {
				t.Errorf("NitroTPM NewAttestationData JSON mismatch\ngot:     %s\nfixture: %s", gotCompact.String(), fixtureCompact.String())
			}
		}
	})

	// Step 2: Verify SEV-SNP attestation with SHA-512(nitroTPMBlob) as report_data.
	// This is the chaining: the SEV-SNP report_data is the hash of the NitroTPM blob,
	// not the original digest.
	t.Run("sevsnp verification with chained report_data", func(t *testing.T) {
		snpBlob, err := base64.StdEncoding.DecodeString(sevsnpEntry.Blob)
		if err != nil {
			t.Fatalf("decoding sevsnp blob: %v", err)
		}

		if len(snpBlob) < abi.ReportSize {
			t.Fatalf("sevsnp blob too short: %d < %d", len(snpBlob), abi.ReportSize)
		}
		rawReport := snpBlob[:abi.ReportSize]
		certTable := snpBlob[abi.ReportSize:]

		// The handler chains: snpReportData = SHA-512(nitroTPMBlob)
		snpReportData := sha512.Sum512(nitroTPMBlob)

		report, err := sevsnp.VerifyAttestation(rawReport, certTable, snpReportData, nil, now)
		if err != nil {
			t.Fatalf("sevsnp.VerifyAttestation() error: %v", err)
		}
		if !bytes.Equal(report.ReportData, snpReportData[:]) {
			t.Error("SEV-SNP report_data does not match SHA-512(nitroTPMBlob)")
		}

		// Cross-check NewAttestationData JSON.
		got := sevsnp.NewAttestationData(report)
		gotJSON, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("marshaling sevsnp.NewAttestationData: %v", err)
		}
		if len(sevsnpEntry.RawData) > 0 {
			var fixtureCompact, gotCompact bytes.Buffer
			json.Compact(&fixtureCompact, sevsnpEntry.RawData)
			json.Compact(&gotCompact, gotJSON)
			if fixtureCompact.String() != gotCompact.String() {
				t.Errorf("SEV-SNP NewAttestationData JSON mismatch\ngot:     %s\nfixture: %s", gotCompact.String(), fixtureCompact.String())
			}
		}
	})

	// Step 3: Verify the chain breaks if we use the raw digest instead.
	t.Run("sevsnp fails with unchained digest", func(t *testing.T) {
		snpBlob, err := base64.StdEncoding.DecodeString(sevsnpEntry.Blob)
		if err != nil {
			t.Fatalf("decoding sevsnp blob: %v", err)
		}
		rawReport := snpBlob[:abi.ReportSize]
		certTable := snpBlob[abi.ReportSize:]

		// Using the original digest (not chained) should fail.
		_, err = sevsnp.VerifyAttestation(rawReport, certTable, digest, nil, now)
		if err == nil {
			t.Fatal("sevsnp.VerifyAttestation() should fail when using unchained digest")
		}
	})
}
