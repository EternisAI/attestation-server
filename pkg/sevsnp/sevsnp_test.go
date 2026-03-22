package sevsnp

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
)

func TestHexBytes_MarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		h    HexBytes
		want string
	}{
		{name: "nil", h: HexBytes(nil), want: `""`},
		{name: "empty", h: HexBytes{}, want: `""`},
		{name: "two bytes", h: HexBytes{0xde, 0xad}, want: `"dead"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.h)
			if err != nil {
				t.Fatalf("MarshalJSON() error: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("MarshalJSON() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestDecomposeTCB(t *testing.T) {
	tests := []struct {
		name string
		v    uint64
		want TCBParts
	}{
		{
			name: "zero",
			v:    0,
			want: TCBParts{BootloaderSPL: 0, TEESPL: 0, SNPSPL: 0, MicrocodeSPL: 0},
		},
		{
			name: "known values",
			// byte 0 = 3, byte 1 = 7, byte 6 = 11, byte 7 = 13
			v: uint64(3) | uint64(7)<<8 | uint64(11)<<48 | uint64(13)<<56,
			want: TCBParts{
				BootloaderSPL: 3,
				TEESPL:        7,
				SNPSPL:        11,
				MicrocodeSPL:  13,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decomposeTCB(tt.v)
			if got != tt.want {
				t.Errorf("decomposeTCB(0x%x) = %+v, want %+v", tt.v, got, tt.want)
			}
		})
	}
}

func TestNewAttestationData(t *testing.T) {
	report := &spb.Report{
		Version:         2,
		GuestSvn:        1,
		Policy:          0x30000,
		FamilyId:        bytes.Repeat([]byte{0xAA}, 16),
		ImageId:         bytes.Repeat([]byte{0xBB}, 16),
		Vmpl:            0,
		ReportData:      bytes.Repeat([]byte{0xCC}, 64),
		Measurement:     bytes.Repeat([]byte{0xDD}, 48),
		HostData:        bytes.Repeat([]byte{0xEE}, 32),
		IdKeyDigest:     bytes.Repeat([]byte{0x11}, 48),
		AuthorKeyDigest: bytes.Repeat([]byte{0x22}, 48),
		ReportId:        bytes.Repeat([]byte{0x33}, 32),
		ReportIdMa:      bytes.Repeat([]byte{0x44}, 32),
		ChipId:          bytes.Repeat([]byte{0x55}, 64),
		CurrentTcb:      0x0807000000000201,
		ReportedTcb:     0,
		CommittedTcb:    0,
		LaunchTcb:       0,
		CurrentBuild:    5,
		CurrentMinor:    55,
		CurrentMajor:    1,
		CommittedBuild:  4,
		CommittedMinor:  54,
		CommittedMajor:  1,
		PlatformInfo:    0x03,
		SignerInfo:      0x04,
	}

	ad := NewAttestationData(report)

	// Scalar fields
	tests := []struct {
		name string
		got  any
		want any
	}{
		{"Version", ad.Version, uint32(2)},
		{"GuestSvn", ad.GuestSvn, uint32(1)},
		{"Policy", ad.Policy, uint64(0x30000)},
		{"VMPL", ad.VMPL, uint32(0)},
		{"PlatformInfo", ad.PlatformInfo, uint64(0x03)},
		{"SignerInfo", ad.SignerInfo, uint32(0x04)},
		// CurrentVersion
		{"CurrentVersion.Build", ad.CurrentVersion.Build, uint32(5)},
		{"CurrentVersion.Minor", ad.CurrentVersion.Minor, uint32(55)},
		{"CurrentVersion.Major", ad.CurrentVersion.Major, uint32(1)},
		// CommittedVersion
		{"CommittedVersion.Build", ad.CommittedVersion.Build, uint32(4)},
		{"CommittedVersion.Minor", ad.CommittedVersion.Minor, uint32(54)},
		{"CommittedVersion.Major", ad.CommittedVersion.Major, uint32(1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
			}
		})
	}

	// HexBytes fields
	hexTests := []struct {
		name string
		got  HexBytes
		want []byte
	}{
		{"FamilyID", ad.FamilyID, bytes.Repeat([]byte{0xAA}, 16)},
		{"ImageID", ad.ImageID, bytes.Repeat([]byte{0xBB}, 16)},
		{"ReportData", ad.ReportData, bytes.Repeat([]byte{0xCC}, 64)},
		{"Measurement", ad.Measurement, bytes.Repeat([]byte{0xDD}, 48)},
		{"HostData", ad.HostData, bytes.Repeat([]byte{0xEE}, 32)},
		{"IDKeyDigest", ad.IDKeyDigest, bytes.Repeat([]byte{0x11}, 48)},
		{"AuthorKeyDigest", ad.AuthorKeyDigest, bytes.Repeat([]byte{0x22}, 48)},
		{"ReportID", ad.ReportID, bytes.Repeat([]byte{0x33}, 32)},
		{"ReportIDMA", ad.ReportIDMA, bytes.Repeat([]byte{0x44}, 32)},
		{"ChipID", ad.ChipID, bytes.Repeat([]byte{0x55}, 64)},
	}
	for _, ht := range hexTests {
		t.Run(ht.name, func(t *testing.T) {
			if !bytes.Equal(ht.got, ht.want) {
				t.Errorf("%s = %x, want %x", ht.name, []byte(ht.got), ht.want)
			}
		})
	}

	// CurrentTCB decomposition: 0x0807000000000201
	// byte 0 = 0x01, byte 1 = 0x02, byte 6 = 0x07, byte 7 = 0x08
	wantCurrentTCB := decomposeTCB(0x0807000000000201)
	if ad.CurrentTCB != wantCurrentTCB {
		t.Errorf("CurrentTCB = %+v, want %+v", ad.CurrentTCB, wantCurrentTCB)
	}
	if ad.CurrentTCB.BootloaderSPL != 1 {
		t.Errorf("CurrentTCB.BootloaderSPL = %d, want 1", ad.CurrentTCB.BootloaderSPL)
	}
	if ad.CurrentTCB.TEESPL != 2 {
		t.Errorf("CurrentTCB.TEESPL = %d, want 2", ad.CurrentTCB.TEESPL)
	}
	if ad.CurrentTCB.SNPSPL != 7 {
		t.Errorf("CurrentTCB.SNPSPL = %d, want 7", ad.CurrentTCB.SNPSPL)
	}
	if ad.CurrentTCB.MicrocodeSPL != 8 {
		t.Errorf("CurrentTCB.MicrocodeSPL = %d, want 8", ad.CurrentTCB.MicrocodeSPL)
	}

	// Zero TCBs
	zeroTCB := TCBParts{0, 0, 0, 0}
	if ad.ReportedTCB != zeroTCB {
		t.Errorf("ReportedTCB = %+v, want %+v", ad.ReportedTCB, zeroTCB)
	}
	if ad.CommittedTCB != zeroTCB {
		t.Errorf("CommittedTCB = %+v, want %+v", ad.CommittedTCB, zeroTCB)
	}
	if ad.LaunchTCB != zeroTCB {
		t.Errorf("LaunchTCB = %+v, want %+v", ad.LaunchTCB, zeroTCB)
	}
}

// sevsnpFixture is the JSON format for SEV-SNP attestation test fixtures.
// "time" is an RFC 3339 timestamp within the certificate validity window.
// "response" is the exact attestation handler response containing "evidence"
// (with the base64-encoded blob) and "data" (the AttestationReportData whose
// SHA-512 digest was used as the 64-byte report_data in the SEV-SNP report).
type sevsnpFixture struct {
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

func loadSEVSNPFixture(t *testing.T, name string) *sevsnpFixture {
	t.Helper()
	path := filepath.Join("testdata", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", path, err)
	}
	var f sevsnpFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parsing fixture %s: %v", path, err)
	}
	return &f
}

// deriveReportData compacts the fixture's raw data JSON (stripping whitespace
// while preserving key order) and returns its SHA-512 digest. This matches
// the production path where AttestationReportData is marshaled to compact
// JSON and hashed to produce the report_data nonce.
func deriveReportData(t *testing.T, rawData json.RawMessage) [64]byte {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Compact(&buf, rawData); err != nil {
		t.Fatalf("compacting fixture data JSON: %v", err)
	}
	return sha512.Sum512(buf.Bytes())
}

func TestVerifyAttestation(t *testing.T) {
	fixtures := []struct {
		name     string
		filename string
	}{
		{"aws", "sevsnp_attestation_aws.json"},
		{"gcp", "sevsnp_attestation_gcp.json"},
	}

	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			f := loadSEVSNPFixture(t, fx.filename)

			if len(f.Report.Evidence) == 0 {
				t.Fatal("fixture has no evidence entries")
			}

			blob, err := base64.StdEncoding.DecodeString(f.Report.Evidence[0].Blob)
			if err != nil {
				t.Fatalf("decoding blob: %v", err)
			}

			now, err := time.Parse(time.RFC3339Nano, f.Time)
			if err != nil {
				t.Fatalf("parsing time: %v", err)
			}

			reportData := deriveReportData(t, f.Report.Data)

			// Split blob into raw report and certificate table.
			// SEV-SNP raw report is always abi.ReportSize (0x4A0 = 1184) bytes.
			if len(blob) < abi.ReportSize {
				t.Fatalf("blob too short for SEV-SNP report: %d < %d", len(blob), abi.ReportSize)
			}
			rawReport := blob[:abi.ReportSize]
			certTable := blob[abi.ReportSize:]

			t.Run("valid", func(t *testing.T) {
				report, err := VerifyAttestation(rawReport, certTable, reportData, nil, now)
				if err != nil {
					t.Fatalf("VerifyAttestation() error: %v", err)
				}
				if report.Version == 0 {
					t.Error("report Version is zero")
				}
				if !bytes.Equal(report.ReportData, reportData[:]) {
					t.Error("report ReportData does not match expected")
				}

				// Cross-check: verify that NewAttestationData produces JSON
				// consistent with the fixture's evidence data.
				got := NewAttestationData(report)
				gotJSON, err := json.Marshal(got)
				if err != nil {
					t.Fatalf("marshaling NewAttestationData: %v", err)
				}
				fixtureEvidenceData := f.Report.Evidence[0].RawData
				if len(fixtureEvidenceData) > 0 {
					var fixtureCompact, gotCompact bytes.Buffer
					json.Compact(&fixtureCompact, fixtureEvidenceData)
					json.Compact(&gotCompact, gotJSON)
					if fixtureCompact.String() != gotCompact.String() {
						t.Errorf("NewAttestationData JSON mismatch\ngot:    %s\nfixture: %s", gotCompact.String(), fixtureCompact.String())
					}
				}
			})

			t.Run("wrong report data", func(t *testing.T) {
				var wrong [64]byte
				copy(wrong[:], reportData[:])
				wrong[0] ^= 0xFF
				_, err := VerifyAttestation(rawReport, certTable, wrong, nil, now)
				if err == nil {
					t.Fatal("VerifyAttestation() expected error for wrong report data")
				}
			})

			t.Run("corrupted report", func(t *testing.T) {
				corrupted := make([]byte, len(rawReport))
				copy(corrupted, rawReport)
				// Corrupt bytes in the signature area near the end of the report
				corrupted[len(corrupted)-10] ^= 0xFF
				corrupted[len(corrupted)-11] ^= 0xFF
				_, err := VerifyAttestation(corrupted, certTable, reportData, nil, now)
				if err == nil {
					t.Fatal("VerifyAttestation() expected error for corrupted report")
				}
			})
		})
	}
}
