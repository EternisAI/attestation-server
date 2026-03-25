package nitro

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eternisai/attestation-server/pkg/hexbytes"
)

func TestToHexBytesMap(t *testing.T) {
	tests := []struct {
		name    string
		input   map[int][]byte
		wantNil bool
		wantLen int
		check   map[int]hexbytes.Bytes // entries to verify, nil means skip
	}{
		{
			name:    "nil map returns nil",
			input:   nil,
			wantNil: true,
		},
		{
			name:    "empty map returns empty map",
			input:   map[int][]byte{},
			wantNil: false,
			wantLen: 0,
		},
		{
			name:    "single entry",
			input:   map[int][]byte{0: {0xab}},
			wantNil: false,
			wantLen: 1,
			check:   map[int]hexbytes.Bytes{0: {0xab}},
		},
		{
			name:    "multiple entries",
			input:   map[int][]byte{0: {0x01, 0x02}, 1: {0x03}},
			wantNil: false,
			wantLen: 2,
			check:   map[int]hexbytes.Bytes{0: {0x01, 0x02}, 1: {0x03}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toHexBytesMap(tt.input)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("toHexBytesMap() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("toHexBytesMap() = nil, want non-nil")
			}
			if len(got) != tt.wantLen {
				t.Fatalf("toHexBytesMap() len = %d, want %d", len(got), tt.wantLen)
			}
			for k, wantV := range tt.check {
				gotV, ok := got[k]
				if !ok {
					t.Errorf("toHexBytesMap() missing key %d", k)
					continue
				}
				if len(gotV) != len(wantV) {
					t.Errorf("toHexBytesMap()[%d] len = %d, want %d", k, len(gotV), len(wantV))
					continue
				}
				for i := range wantV {
					if gotV[i] != wantV[i] {
						t.Errorf("toHexBytesMap()[%d][%d] = 0x%02x, want 0x%02x", k, i, gotV[i], wantV[i])
					}
				}
			}
		})
	}
}

func TestNewAttestationData(t *testing.T) {
	t.Run("with PCRs", func(t *testing.T) {
		doc := &AttestationDocument{
			ModuleID:  "i-abc123-enc0123456789abcdef0",
			Timestamp: 1700000000000,
			Digest:    "SHA384",
			PCRs:      map[int][]byte{0: {0x01, 0x02}, 1: {0x03}},
			Nonce:     []byte{0xaa, 0xbb},
		}

		got := NewAttestationData(doc)

		if got.Module != doc.ModuleID {
			t.Errorf("Module = %q, want %q", got.Module, doc.ModuleID)
		}

		wantTime := time.UnixMilli(1700000000000).UTC()
		if !got.Timestamp.Equal(wantTime) {
			t.Errorf("Timestamp = %v, want %v", got.Timestamp, wantTime)
		}

		if got.Digest != doc.Digest {
			t.Errorf("Digest = %q, want %q", got.Digest, doc.Digest)
		}

		if got.PCRs == nil {
			t.Fatal("PCRs is nil, want non-nil")
		}
		if len(got.PCRs) != 2 {
			t.Fatalf("PCRs len = %d, want 2", len(got.PCRs))
		}
		if got.PCRs[0][0] != 0x01 || got.PCRs[0][1] != 0x02 {
			t.Errorf("PCRs[0] = %v, want [01 02]", got.PCRs[0])
		}
		if got.PCRs[1][0] != 0x03 {
			t.Errorf("PCRs[1] = %v, want [03]", got.PCRs[1])
		}

		if got.NitroTPMPCRs != nil {
			t.Errorf("NitroTPMPCRs = %v, want nil", got.NitroTPMPCRs)
		}

		if len(got.Nonce) != 2 || got.Nonce[0] != 0xaa || got.Nonce[1] != 0xbb {
			t.Errorf("Nonce = %v, want [aa bb]", got.Nonce)
		}
	})

	t.Run("with NitroTPM PCRs", func(t *testing.T) {
		doc := &AttestationDocument{
			ModuleID:     "i-xyz789-enc9876543210fedcba0",
			Timestamp:    1700000000000,
			Digest:       "SHA384",
			NitroTPMPCRs: map[int][]byte{0: {0xff}, 4: {0x10, 0x20}},
			Nonce:        []byte{0xcc},
		}

		got := NewAttestationData(doc)

		if got.Module != doc.ModuleID {
			t.Errorf("Module = %q, want %q", got.Module, doc.ModuleID)
		}

		if got.PCRs != nil {
			t.Errorf("PCRs = %v, want nil", got.PCRs)
		}

		if got.NitroTPMPCRs == nil {
			t.Fatal("NitroTPMPCRs is nil, want non-nil")
		}
		if len(got.NitroTPMPCRs) != 2 {
			t.Fatalf("NitroTPMPCRs len = %d, want 2", len(got.NitroTPMPCRs))
		}
		if got.NitroTPMPCRs[0][0] != 0xff {
			t.Errorf("NitroTPMPCRs[0] = %v, want [ff]", got.NitroTPMPCRs[0])
		}
		if got.NitroTPMPCRs[4][0] != 0x10 || got.NitroTPMPCRs[4][1] != 0x20 {
			t.Errorf("NitroTPMPCRs[4] = %v, want [10 20]", got.NitroTPMPCRs[4])
		}

		if len(got.Nonce) != 1 || got.Nonce[0] != 0xcc {
			t.Errorf("Nonce = %v, want [cc]", got.Nonce)
		}
	})
}

// nitroFixture is the raw AttestationReport JSON returned by the attestation
// handler. The clock value for certificate validation is extracted from
// data.timestamp (RFC 3339, truncated to seconds).
type nitroFixture struct {
	Evidence []struct {
		Kind    string          `json:"kind"`
		Blob    string          `json:"blob"`
		RawData json.RawMessage `json:"data"`
	} `json:"evidence"`
	Data json.RawMessage `json:"data"`
}

func loadNitroFixture(t *testing.T, name string) *nitroFixture {
	t.Helper()
	path := filepath.Join("testdata", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", path, err)
	}
	var f nitroFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parsing fixture %s: %v", path, err)
	}
	return &f
}

// fixtureTime extracts and parses the timestamp from the fixture's data JSON.
func fixtureTime(t *testing.T, rawData json.RawMessage) time.Time {
	t.Helper()
	var ts struct {
		Timestamp string `json:"timestamp"`
	}
	if err := json.Unmarshal(rawData, &ts); err != nil {
		t.Fatalf("parsing data timestamp: %v", err)
	}
	now, err := time.Parse(time.RFC3339, ts.Timestamp)
	if err != nil {
		t.Fatalf("parsing timestamp %q: %v", ts.Timestamp, err)
	}
	return now
}

// deriveNonce compacts the fixture's raw data JSON (stripping whitespace
// while preserving key order) and returns its SHA-512 digest. This matches
// the production path where AttestationReportData is marshaled to compact
// JSON and hashed to produce the nonce.
func deriveNonce(t *testing.T, rawData json.RawMessage) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Compact(&buf, rawData); err != nil {
		t.Fatalf("compacting fixture data JSON: %v", err)
	}
	digest := sha512.Sum512(buf.Bytes())
	return digest[:]
}

func TestVerifyEvidence(t *testing.T) {
	fixtures := []struct {
		name     string
		filename string
	}{
		{"nsm", "nitronsm_attestation.json"},
		{"nitrotpm", "nitrotpm_attestation.json"},
	}

	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			f := loadNitroFixture(t, fx.filename)

			if len(f.Evidence) == 0 {
				t.Fatal("fixture has no evidence entries")
			}

			blob, err := base64.StdEncoding.DecodeString(f.Evidence[0].Blob)
			if err != nil {
				t.Fatalf("decoding blob: %v", err)
			}

			now := fixtureTime(t, f.Data)
			nonce := deriveNonce(t, f.Data)

			t.Run("valid", func(t *testing.T) {
				doc, err := VerifyEvidence(blob, nonce, now)
				if err != nil {
					t.Fatalf("VerifyEvidence() error: %v", err)
				}
				if doc.ModuleID == "" {
					t.Error("ModuleID is empty")
				}
				if doc.Digest == "" {
					t.Error("Digest is empty")
				}
				if doc.Timestamp == 0 {
					t.Error("Timestamp is zero")
				}
				if !bytes.Equal(doc.Nonce, nonce) {
					t.Error("Nonce in document does not match expected")
				}
				hasPCRs := len(doc.PCRs) > 0 || len(doc.NitroTPMPCRs) > 0
				if !hasPCRs {
					t.Error("no PCRs in document")
				}
				// NitroTPM documents use NitroTPMPCRs, NSM uses PCRs
				switch fx.name {
				case "nitrotpm":
					if len(doc.NitroTPMPCRs) != 24 {
						t.Errorf("NitroTPMPCRs count = %d, want 24", len(doc.NitroTPMPCRs))
					}
					if len(doc.PCRs) != 0 {
						t.Errorf("PCRs should be empty for nitrotpm, got %d", len(doc.PCRs))
					}
				case "nsm":
					if len(doc.PCRs) == 0 {
						t.Error("PCRs should be populated for nsm")
					}
					if len(doc.NitroTPMPCRs) != 0 {
						t.Errorf("NitroTPMPCRs should be empty for nsm, got %d", len(doc.NitroTPMPCRs))
					}
				}

				// Cross-check: verify that NewAttestationData produces JSON
				// consistent with the fixture's evidence data.
				got := NewAttestationData(doc)
				gotJSON, err := json.Marshal(got)
				if err != nil {
					t.Fatalf("marshaling NewAttestationData: %v", err)
				}
				fixtureEvidenceData := f.Evidence[0].RawData
				if len(fixtureEvidenceData) > 0 {
					var fixtureCompact, gotCompact bytes.Buffer
					json.Compact(&fixtureCompact, fixtureEvidenceData)
					json.Compact(&gotCompact, gotJSON)
					if fixtureCompact.String() != gotCompact.String() {
						t.Errorf("NewAttestationData JSON mismatch\ngot:     %s\nfixture: %s", gotCompact.String(), fixtureCompact.String())
					}
				}
			})

			t.Run("wrong nonce", func(t *testing.T) {
				wrongNonce := make([]byte, len(nonce))
				copy(wrongNonce, nonce)
				wrongNonce[0] ^= 0xFF
				_, err := VerifyEvidence(blob, wrongNonce, now)
				if err == nil {
					t.Fatal("VerifyEvidence() expected error for wrong nonce")
				}
			})

			t.Run("corrupted blob", func(t *testing.T) {
				corrupted := make([]byte, len(blob))
				copy(corrupted, blob)
				// Corrupt bytes in the COSE signature area
				corrupted[len(corrupted)/2] ^= 0xFF
				corrupted[len(corrupted)/2+1] ^= 0xFF
				_, err := VerifyEvidence(corrupted, nonce, now)
				if err == nil {
					t.Fatal("VerifyEvidence() expected error for corrupted blob")
				}
			})
		})
	}

	t.Run("empty blob", func(t *testing.T) {
		_, err := VerifyEvidence(nil, nil, time.Now())
		if err == nil {
			t.Fatal("VerifyEvidence() expected error for empty blob")
		}
	})
}
