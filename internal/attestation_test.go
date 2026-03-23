package app

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eternisai/attestation-server/pkg/nitro"
	"github.com/eternisai/attestation-server/pkg/sevsnp"
	"github.com/eternisai/attestation-server/pkg/tdx"
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

// dependencyFixture mirrors the JSON format of the dependency attestation fixture.
// It extends chainedFixture with a Dependencies field containing nested reports.
type dependencyFixture struct {
	Time   string `json:"time"`
	Report struct {
		Evidence []struct {
			Kind    string          `json:"kind"`
			Blob    string          `json:"blob"`
			RawData json.RawMessage `json:"data"`
		} `json:"evidence"`
		Data         json.RawMessage   `json:"data"`
		Dependencies []json.RawMessage `json:"dependencies"`
	} `json:"report"`
}

// dependencyReport is used to parse each dependency's JSON.
type dependencyReport struct {
	Evidence []struct {
		Kind    string          `json:"kind"`
		Blob    string          `json:"blob"`
		RawData json.RawMessage `json:"data"`
	} `json:"evidence"`
	Data         json.RawMessage   `json:"data"`
	Dependencies []json.RawMessage `json:"dependencies"`
}

// TestDependencyAttestation_DiamondGraph verifies the full transitive
// dependency attestation fixture with a diamond dependency pattern:
//
//	A (NitroTPM+SEV-SNP) → {B (TDX), C (SEV-SNP)}
//	B → C (SEV-SNP)
//
// Service C appears twice: once as a direct dependency of A and once as
// a transitive dependency through B, forming a diamond. Both instances
// share the same TLS certificate and build info (same service, possibly
// different replicas).
//
// The top-level report has a public cert but no client cert (external
// Internet client at ingress). Each dependency report has a client cert
// matching the caller's private cert (mTLS within the dependency chain).
//
// The test verifies:
//  1. Top-level NitroTPM+SEV-SNP chained evidence
//  2. Top-level e2e: public cert present, no client cert (ingress)
//  3. Dependency nonce binding + client cert FP + crypto verification
//  4. Transitive C's nonce binding via B's digest
//  5. verifyDependencyReport succeeds for each dependency
//  6. Nonce mismatch / client cert FP mismatch are correctly rejected
func TestDependencyAttestation_DiamondGraph(t *testing.T) {
	path := filepath.Join("testdata", "dependencies_attestation.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	var f dependencyFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}

	now, err := time.Parse(time.RFC3339Nano, f.Time)
	if err != nil {
		t.Fatalf("parsing time: %v", err)
	}

	// Compute top-level digest from report data.
	var dataBuf bytes.Buffer
	if err := json.Compact(&dataBuf, f.Report.Data); err != nil {
		t.Fatalf("compacting data JSON: %v", err)
	}
	digest := sha512.Sum512(dataBuf.Bytes())
	nonceHex := hex.EncodeToString(digest[:])

	// --- Step 1: Verify top-level NitroTPM + SEV-SNP chained evidence ---

	t.Run("top-level NitroTPM verification", func(t *testing.T) {
		var tpmEntry *struct {
			Kind    string          `json:"kind"`
			Blob    string          `json:"blob"`
			RawData json.RawMessage `json:"data"`
		}
		for i := range f.Report.Evidence {
			if f.Report.Evidence[i].Kind == "nitrotpm" {
				tpmEntry = &f.Report.Evidence[i]
				break
			}
		}
		if tpmEntry == nil {
			t.Fatal("fixture missing nitrotpm evidence")
		}

		blob, err := base64.StdEncoding.DecodeString(tpmEntry.Blob)
		if err != nil {
			t.Fatalf("decoding nitrotpm blob: %v", err)
		}
		doc, err := nitro.VerifyAttestation(blob, digest[:], now)
		if err != nil {
			t.Fatalf("nitro.VerifyAttestation() error: %v", err)
		}

		got := nitro.NewAttestationData(doc)
		gotJSON, _ := json.Marshal(got)
		if len(tpmEntry.RawData) > 0 {
			var fixtureCompact, gotCompact bytes.Buffer
			json.Compact(&fixtureCompact, tpmEntry.RawData)
			json.Compact(&gotCompact, gotJSON)
			if fixtureCompact.String() != gotCompact.String() {
				t.Errorf("NitroTPM NewAttestationData JSON mismatch")
			}
		}
	})

	t.Run("top-level SEV-SNP chained verification", func(t *testing.T) {
		var tpmEntry, snpEntry *struct {
			Kind    string          `json:"kind"`
			Blob    string          `json:"blob"`
			RawData json.RawMessage `json:"data"`
		}
		for i := range f.Report.Evidence {
			switch f.Report.Evidence[i].Kind {
			case "nitrotpm":
				tpmEntry = &f.Report.Evidence[i]
			case "sevsnp":
				snpEntry = &f.Report.Evidence[i]
			}
		}
		if tpmEntry == nil || snpEntry == nil {
			t.Fatal("fixture missing nitrotpm or sevsnp evidence")
		}

		nitroTPMBlob, _ := base64.StdEncoding.DecodeString(tpmEntry.Blob)
		snpBlob, _ := base64.StdEncoding.DecodeString(snpEntry.Blob)

		snpReportData := sha512.Sum512(nitroTPMBlob)
		if len(snpBlob) < abi.ReportSize {
			t.Fatalf("sevsnp blob too short: %d < %d", len(snpBlob), abi.ReportSize)
		}
		report, err := sevsnp.VerifyAttestation(snpBlob[:abi.ReportSize], snpBlob[abi.ReportSize:], snpReportData, nil, now)
		if err != nil {
			t.Fatalf("sevsnp.VerifyAttestation() error: %v", err)
		}

		got := sevsnp.NewAttestationData(report)
		gotJSON, _ := json.Marshal(got)
		if len(snpEntry.RawData) > 0 {
			var fixtureCompact, gotCompact bytes.Buffer
			json.Compact(&fixtureCompact, snpEntry.RawData)
			json.Compact(&gotCompact, gotJSON)
			if fixtureCompact.String() != gotCompact.String() {
				t.Errorf("SEV-SNP NewAttestationData JSON mismatch")
			}
		}
	})

	// --- Step 2: Verify each dependency's nonce binding and evidence ---

	if len(f.Report.Dependencies) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(f.Report.Dependencies))
	}

	// Parse both dependencies.
	var deps [2]dependencyReport
	for i := 0; i < 2; i++ {
		if err := json.Unmarshal(f.Report.Dependencies[i], &deps[i]); err != nil {
			t.Fatalf("parsing dependency[%d]: %v", i, err)
		}
	}

	t.Run("dependency[0] TDX nonce and verification", func(t *testing.T) {
		dep := deps[0]
		if len(dep.Evidence) != 1 || dep.Evidence[0].Kind != "tdx" {
			t.Fatalf("expected single tdx evidence, got %v", dep.Evidence)
		}

		// Nonce in dependency's data must match top-level digest.
		var depData AttestationReportData
		if err := json.Unmarshal(dep.Data, &depData); err != nil {
			t.Fatalf("parsing dep data: %v", err)
		}
		if depData.Nonce != nonceHex {
			t.Errorf("dep[0] nonce = %q, want %q", depData.Nonce, nonceHex)
		}

		// Verify TDX evidence.
		var depDataBuf bytes.Buffer
		json.Compact(&depDataBuf, dep.Data)
		depDigest := sha512.Sum512(depDataBuf.Bytes())

		blob, _ := base64.StdEncoding.DecodeString(dep.Evidence[0].Blob)
		quote, err := tdx.VerifyQuote(blob, depDigest, now)
		if err != nil {
			t.Fatalf("tdx.VerifyQuote() error: %v", err)
		}

		got := tdx.NewAttestationData(quote)
		gotJSON, _ := json.Marshal(got)
		if len(dep.Evidence[0].RawData) > 0 {
			var fixtureCompact, gotCompact bytes.Buffer
			json.Compact(&fixtureCompact, dep.Evidence[0].RawData)
			json.Compact(&gotCompact, gotJSON)
			if fixtureCompact.String() != gotCompact.String() {
				t.Errorf("TDX NewAttestationData JSON mismatch")
			}
		}
	})

	// Extract and validate top-level TLS data.
	var topData AttestationReportData
	if err := json.Unmarshal(f.Report.Data, &topData); err != nil {
		t.Fatalf("parsing top-level data: %v", err)
	}

	t.Run("top-level e2e: public cert at ingress, no client cert", func(t *testing.T) {
		if topData.TLS == nil {
			t.Fatal("top-level report missing TLS data")
		}
		if topData.TLS.Public == nil || topData.TLS.Public.CertificateFingerprint == "" {
			t.Fatal("top-level report missing public certificate (ingress e2e)")
		}
		if topData.TLS.Client != nil {
			t.Error("top-level report should not have client cert (external client at ingress)")
		}
	})

	if topData.TLS == nil || topData.TLS.Private == nil {
		t.Fatal("top-level report missing TLS private cert data")
	}
	aPrivateFP := topData.TLS.Private.CertificateFingerprint

	t.Run("dependency[0] verifyDependencyReport", func(t *testing.T) {
		var report AttestationReport
		if err := json.Unmarshal(f.Report.Dependencies[0], &report); err != nil {
			t.Fatalf("parsing dependency: %v", err)
		}
		if err := verifyDependencyReport(&report, nonceHex, aPrivateFP, now); err != nil {
			t.Fatalf("verifyDependencyReport() error: %v", err)
		}
	})

	t.Run("dependency[1] SEV-SNP nonce and verification", func(t *testing.T) {
		dep := deps[1]
		if len(dep.Evidence) != 1 || dep.Evidence[0].Kind != "sevsnp" {
			t.Fatalf("expected single sevsnp evidence, got %v", dep.Evidence)
		}

		var depData AttestationReportData
		if err := json.Unmarshal(dep.Data, &depData); err != nil {
			t.Fatalf("parsing dep data: %v", err)
		}
		if depData.Nonce != nonceHex {
			t.Errorf("dep[1] nonce = %q, want %q", depData.Nonce, nonceHex)
		}

		// Verify SEV-SNP evidence (no chaining — standalone).
		var depDataBuf bytes.Buffer
		json.Compact(&depDataBuf, dep.Data)
		depDigest := sha512.Sum512(depDataBuf.Bytes())

		blob, _ := base64.StdEncoding.DecodeString(dep.Evidence[0].Blob)
		if len(blob) < abi.ReportSize {
			t.Fatalf("sevsnp blob too short")
		}
		report, err := sevsnp.VerifyAttestation(blob[:abi.ReportSize], blob[abi.ReportSize:], depDigest, nil, now)
		if err != nil {
			t.Fatalf("sevsnp.VerifyAttestation() error: %v", err)
		}

		got := sevsnp.NewAttestationData(report)
		gotJSON, _ := json.Marshal(got)
		if len(dep.Evidence[0].RawData) > 0 {
			var fixtureCompact, gotCompact bytes.Buffer
			json.Compact(&fixtureCompact, dep.Evidence[0].RawData)
			json.Compact(&gotCompact, gotJSON)
			if fixtureCompact.String() != gotCompact.String() {
				t.Errorf("SEV-SNP NewAttestationData JSON mismatch")
			}
		}
	})

	t.Run("dependency[1] verifyDependencyReport", func(t *testing.T) {
		var report AttestationReport
		if err := json.Unmarshal(f.Report.Dependencies[1], &report); err != nil {
			t.Fatalf("parsing dependency: %v", err)
		}
		if err := verifyDependencyReport(&report, nonceHex, aPrivateFP, now); err != nil {
			t.Fatalf("verifyDependencyReport() error: %v", err)
		}
	})

	// --- Step 3: Verify transitive C (nested inside B) ---

	t.Run("transitive C via B nonce and verification", func(t *testing.T) {
		if len(deps[0].Dependencies) != 1 {
			t.Fatalf("expected 1 nested dependency in dep[0], got %d", len(deps[0].Dependencies))
		}

		// Transitive C's nonce should be the hex digest of B's (dep[0]) report data.
		var bDataBuf bytes.Buffer
		json.Compact(&bDataBuf, deps[0].Data)
		bDigest := sha512.Sum512(bDataBuf.Bytes())
		bNonceHex := hex.EncodeToString(bDigest[:])

		var subDep dependencyReport
		if err := json.Unmarshal(deps[0].Dependencies[0], &subDep); err != nil {
			t.Fatalf("parsing nested dependency: %v", err)
		}

		var subData AttestationReportData
		if err := json.Unmarshal(subDep.Data, &subData); err != nil {
			t.Fatalf("parsing nested dep data: %v", err)
		}
		if subData.Nonce != bNonceHex {
			t.Errorf("nested dep nonce = %q, want %q", subData.Nonce, bNonceHex)
		}

		// Verify transitive C's SEV-SNP evidence.
		if len(subDep.Evidence) != 1 || subDep.Evidence[0].Kind != "sevsnp" {
			t.Fatalf("expected single sevsnp evidence in nested dep")
		}

		var subDataBuf bytes.Buffer
		json.Compact(&subDataBuf, subDep.Data)
		subDigest := sha512.Sum512(subDataBuf.Bytes())

		blob, _ := base64.StdEncoding.DecodeString(subDep.Evidence[0].Blob)
		if len(blob) < abi.ReportSize {
			t.Fatalf("sevsnp blob too short")
		}
		_, err := sevsnp.VerifyAttestation(blob[:abi.ReportSize], blob[abi.ReportSize:], subDigest, nil, now)
		if err != nil {
			t.Fatalf("sevsnp.VerifyAttestation() error: %v", err)
		}
	})

	// B's private cert fingerprint is what B presents as client cert to
	// transitive C.
	var bData AttestationReportData
	if err := json.Unmarshal(deps[0].Data, &bData); err != nil {
		t.Fatalf("parsing dep[0] data: %v", err)
	}
	if bData.TLS == nil || bData.TLS.Private == nil {
		t.Fatal("dep[0] missing TLS private cert data")
	}
	bPrivateFP := bData.TLS.Private.CertificateFingerprint

	t.Run("transitive C via B verifyDependencyReport", func(t *testing.T) {
		var bDataBuf bytes.Buffer
		json.Compact(&bDataBuf, deps[0].Data)
		bDigest := sha512.Sum512(bDataBuf.Bytes())
		bNonceHex := hex.EncodeToString(bDigest[:])

		var report AttestationReport
		if err := json.Unmarshal(deps[0].Dependencies[0], &report); err != nil {
			t.Fatalf("parsing nested dependency: %v", err)
		}
		if err := verifyDependencyReport(&report, bNonceHex, bPrivateFP, now); err != nil {
			t.Fatalf("verifyDependencyReport() error: %v", err)
		}
	})

	// --- Step 4: Verify nonce mismatch is rejected ---

	t.Run("dependency fails with wrong nonce", func(t *testing.T) {
		var report AttestationReport
		if err := json.Unmarshal(f.Report.Dependencies[0], &report); err != nil {
			t.Fatalf("parsing dependency: %v", err)
		}
		// Nonce check fires before client cert check, so the fingerprint is irrelevant here.
		err := verifyDependencyReport(&report, "0000000000000000", aPrivateFP, now)
		if err == nil {
			t.Fatal("verifyDependencyReport() should fail with wrong nonce")
		}
		if !bytes.Contains([]byte(err.Error()), []byte("nonce mismatch")) {
			t.Errorf("error %q does not contain 'nonce mismatch'", err.Error())
		}
	})

	t.Run("transitive C fails with A nonce instead of B nonce", func(t *testing.T) {
		// Using A's nonce for the transitive C (reached via B) should fail —
		// it must use B's digest, not A's.
		var report AttestationReport
		if err := json.Unmarshal(deps[0].Dependencies[0], &report); err != nil {
			t.Fatalf("parsing transitive dependency: %v", err)
		}
		err := verifyDependencyReport(&report, nonceHex, bPrivateFP, now)
		if err == nil {
			t.Fatal("verifyDependencyReport() should fail when using A's nonce for transitive C")
		}
	})

	// --- Step 5: Negative tests — tamper with fixture data ---

	t.Run("dependency[0] fails with wrong client cert FP", func(t *testing.T) {
		var report AttestationReport
		if err := json.Unmarshal(f.Report.Dependencies[0], &report); err != nil {
			t.Fatalf("parsing dependency: %v", err)
		}
		wrongFP := "0000000000000000000000000000000000000000000000000000000000000000"
		err := verifyDependencyReport(&report, nonceHex, wrongFP, now)
		if err == nil {
			t.Fatal("expected error for wrong client cert FP")
		}
		if !isE2EError(err) {
			t.Fatalf("expected e2e error, got: %v", err)
		}
	})

	t.Run("dependency[0] fails with empty client cert FP", func(t *testing.T) {
		// Tamper: replace the dependency's data to remove client cert.
		var depReport AttestationReport
		if err := json.Unmarshal(f.Report.Dependencies[0], &depReport); err != nil {
			t.Fatalf("parsing dependency: %v", err)
		}
		var depData AttestationReportData
		if err := json.Unmarshal(depReport.Data, &depData); err != nil {
			t.Fatalf("parsing dep data: %v", err)
		}
		depData.TLS.Client = nil
		tamperedData, _ := json.Marshal(depData)
		depReport.Data = json.RawMessage(tamperedData)

		// Nonce will still match but client cert is missing — e2e error.
		err := verifyDependencyReport(&depReport, nonceHex, aPrivateFP, now)
		if err == nil {
			t.Fatal("expected error for missing client cert in tampered dep")
		}
		if !isE2EError(err) {
			t.Fatalf("expected e2e error, got: %v", err)
		}
	})

	t.Run("dependency[0] tampered data fails crypto verification", func(t *testing.T) {
		// Tamper: modify the client cert FP in dep data. Nonce + client
		// cert check pass (we supply the tampered FP) but the crypto
		// evidence was signed over the original data, so it must fail.
		var depReport AttestationReport
		if err := json.Unmarshal(f.Report.Dependencies[0], &depReport); err != nil {
			t.Fatalf("parsing dependency: %v", err)
		}
		var depData AttestationReportData
		if err := json.Unmarshal(depReport.Data, &depData); err != nil {
			t.Fatalf("parsing dep data: %v", err)
		}
		tamperedFP := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		depData.TLS.Client.CertificateFingerprint = tamperedFP
		tamperedDataJSON, _ := json.Marshal(depData)
		depReport.Data = json.RawMessage(tamperedDataJSON)

		err := verifyDependencyReport(&depReport, nonceHex, tamperedFP, now)
		if err == nil {
			t.Fatal("expected crypto verification failure for tampered data")
		}
		// Should NOT be an e2e error — nonce+client cert checks pass,
		// but the TEE evidence doesn't match the tampered data hash.
		if isE2EError(err) {
			t.Fatalf("expected crypto error, got e2e error: %v", err)
		}
	})
}
