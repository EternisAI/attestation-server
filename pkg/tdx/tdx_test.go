package tdx

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/google/go-tdx-guest/proto/tdx"
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
			got, err := tt.h.MarshalJSON()
			if err != nil {
				t.Fatalf("MarshalJSON() returned error: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("MarshalJSON() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestNewAttestationData(t *testing.T) {
	t.Run("fully populated quote", func(t *testing.T) {
		qeSvn := []byte{0x01, 0x00}
		pceSvn := []byte{0x0E, 0x00}
		qeVendorID := bytes.Repeat([]byte{0xAA}, 16)
		teeTcbSvn := bytes.Repeat([]byte{0x03}, 16)
		mrSeam := bytes.Repeat([]byte{0x11}, 48)
		mrSignerSeam := bytes.Repeat([]byte{0x22}, 48)
		seamAttributes := bytes.Repeat([]byte{0x00}, 8)
		tdAttributes := bytes.Repeat([]byte{0x00}, 8)
		xfam := bytes.Repeat([]byte{0x00}, 8)
		mrTd := bytes.Repeat([]byte{0x33}, 48)
		mrConfigID := bytes.Repeat([]byte{0x44}, 48)
		mrOwner := bytes.Repeat([]byte{0x55}, 48)
		mrOwnerConfig := bytes.Repeat([]byte{0x66}, 48)
		rtmr0 := bytes.Repeat([]byte{0x77}, 48)
		rtmr1 := bytes.Repeat([]byte{0x88}, 48)
		rtmr2 := bytes.Repeat([]byte{0x99}, 48)
		rtmr3 := bytes.Repeat([]byte{0xAA}, 48)
		reportData := bytes.Repeat([]byte{0xBB}, 64)

		quote := &pb.QuoteV4{
			Header: &pb.Header{
				Version:    4,
				TeeType:    0x00000081,
				QeSvn:      qeSvn,
				PceSvn:     pceSvn,
				QeVendorId: qeVendorID,
			},
			TdQuoteBody: &pb.TDQuoteBody{
				TeeTcbSvn:      teeTcbSvn,
				MrSeam:         mrSeam,
				MrSignerSeam:   mrSignerSeam,
				SeamAttributes: seamAttributes,
				TdAttributes:   tdAttributes,
				Xfam:           xfam,
				MrTd:           mrTd,
				MrConfigId:     mrConfigID,
				MrOwner:        mrOwner,
				MrOwnerConfig:  mrOwnerConfig,
				Rtmrs:          [][]byte{rtmr0, rtmr1, rtmr2, rtmr3},
				ReportData:     reportData,
			},
		}

		got := NewAttestationData(quote)

		if got.Version != 4 {
			t.Errorf("Version = %d, want 4", got.Version)
		}
		if got.TeeType != 0x81 {
			t.Errorf("TeeType = 0x%x, want 0x81", got.TeeType)
		}
		if !bytes.Equal(got.QeSvn, qeSvn) {
			t.Errorf("QeSvn = %v, want %v", []byte(got.QeSvn), qeSvn)
		}
		if !bytes.Equal(got.PceSvn, pceSvn) {
			t.Errorf("PceSvn = %v, want %v", []byte(got.PceSvn), pceSvn)
		}
		if !bytes.Equal(got.QeVendorID, qeVendorID) {
			t.Errorf("QeVendorID = %v, want %v", []byte(got.QeVendorID), qeVendorID)
		}
		if !bytes.Equal(got.TeeTcbSvn, teeTcbSvn) {
			t.Errorf("TeeTcbSvn = %v, want %v", []byte(got.TeeTcbSvn), teeTcbSvn)
		}
		if !bytes.Equal(got.MrSeam, mrSeam) {
			t.Errorf("MrSeam = %v, want %v", []byte(got.MrSeam), mrSeam)
		}
		if !bytes.Equal(got.MrSignerSeam, mrSignerSeam) {
			t.Errorf("MrSignerSeam = %v, want %v", []byte(got.MrSignerSeam), mrSignerSeam)
		}
		if !bytes.Equal(got.SeamAttributes, seamAttributes) {
			t.Errorf("SeamAttributes = %v, want %v", []byte(got.SeamAttributes), seamAttributes)
		}
		if !bytes.Equal(got.TdAttributes, tdAttributes) {
			t.Errorf("TdAttributes = %v, want %v", []byte(got.TdAttributes), tdAttributes)
		}
		if !bytes.Equal(got.Xfam, xfam) {
			t.Errorf("Xfam = %v, want %v", []byte(got.Xfam), xfam)
		}
		if !bytes.Equal(got.MrTd, mrTd) {
			t.Errorf("MrTd = %v, want %v", []byte(got.MrTd), mrTd)
		}
		if !bytes.Equal(got.MrConfigID, mrConfigID) {
			t.Errorf("MrConfigID = %v, want %v", []byte(got.MrConfigID), mrConfigID)
		}
		if !bytes.Equal(got.MrOwner, mrOwner) {
			t.Errorf("MrOwner = %v, want %v", []byte(got.MrOwner), mrOwner)
		}
		if !bytes.Equal(got.MrOwnerConfig, mrOwnerConfig) {
			t.Errorf("MrOwnerConfig = %v, want %v", []byte(got.MrOwnerConfig), mrOwnerConfig)
		}
		if !bytes.Equal(got.ReportData, reportData) {
			t.Errorf("ReportData = %v, want %v", []byte(got.ReportData), reportData)
		}

		if len(got.Rtmrs) != 4 {
			t.Fatalf("Rtmrs len = %d, want 4", len(got.Rtmrs))
		}
		wantRtmrs := [][]byte{rtmr0, rtmr1, rtmr2, rtmr3}
		for i, want := range wantRtmrs {
			if !bytes.Equal(got.Rtmrs[i], want) {
				t.Errorf("Rtmrs[%d] = %v, want %v", i, []byte(got.Rtmrs[i]), want)
			}
		}
	})

	t.Run("nil header and body", func(t *testing.T) {
		quote := &pb.QuoteV4{}

		got := NewAttestationData(quote)

		if got.Version != 0 {
			t.Errorf("Version = %d, want 0", got.Version)
		}
		if got.TeeType != 0 {
			t.Errorf("TeeType = %d, want 0", got.TeeType)
		}
		if len(got.QeSvn) != 0 {
			t.Errorf("QeSvn = %v, want empty", []byte(got.QeSvn))
		}
		if len(got.PceSvn) != 0 {
			t.Errorf("PceSvn = %v, want empty", []byte(got.PceSvn))
		}
		if len(got.QeVendorID) != 0 {
			t.Errorf("QeVendorID = %v, want empty", []byte(got.QeVendorID))
		}
		if len(got.TeeTcbSvn) != 0 {
			t.Errorf("TeeTcbSvn = %v, want empty", []byte(got.TeeTcbSvn))
		}
		if len(got.MrSeam) != 0 {
			t.Errorf("MrSeam = %v, want empty", []byte(got.MrSeam))
		}
		if len(got.MrSignerSeam) != 0 {
			t.Errorf("MrSignerSeam = %v, want empty", []byte(got.MrSignerSeam))
		}
		if len(got.SeamAttributes) != 0 {
			t.Errorf("SeamAttributes = %v, want empty", []byte(got.SeamAttributes))
		}
		if len(got.TdAttributes) != 0 {
			t.Errorf("TdAttributes = %v, want empty", []byte(got.TdAttributes))
		}
		if len(got.Xfam) != 0 {
			t.Errorf("Xfam = %v, want empty", []byte(got.Xfam))
		}
		if len(got.MrTd) != 0 {
			t.Errorf("MrTd = %v, want empty", []byte(got.MrTd))
		}
		if len(got.MrConfigID) != 0 {
			t.Errorf("MrConfigID = %v, want empty", []byte(got.MrConfigID))
		}
		if len(got.MrOwner) != 0 {
			t.Errorf("MrOwner = %v, want empty", []byte(got.MrOwner))
		}
		if len(got.MrOwnerConfig) != 0 {
			t.Errorf("MrOwnerConfig = %v, want empty", []byte(got.MrOwnerConfig))
		}
		if len(got.ReportData) != 0 {
			t.Errorf("ReportData = %v, want empty", []byte(got.ReportData))
		}
		if len(got.Rtmrs) != 0 {
			t.Errorf("Rtmrs len = %d, want 0", len(got.Rtmrs))
		}
	})

	t.Run("empty RTMRs", func(t *testing.T) {
		quote := &pb.QuoteV4{
			Header: &pb.Header{
				Version: 4,
				TeeType: 0x00000081,
			},
			TdQuoteBody: &pb.TDQuoteBody{
				MrSeam: bytes.Repeat([]byte{0x11}, 48),
				Rtmrs:  nil,
			},
		}

		got := NewAttestationData(quote)

		if got.Version != 4 {
			t.Errorf("Version = %d, want 4", got.Version)
		}
		if got.TeeType != 0x81 {
			t.Errorf("TeeType = 0x%x, want 0x81", got.TeeType)
		}
		if !bytes.Equal(got.MrSeam, bytes.Repeat([]byte{0x11}, 48)) {
			t.Errorf("MrSeam mismatch")
		}
		if len(got.Rtmrs) != 0 {
			t.Errorf("Rtmrs len = %d, want 0", len(got.Rtmrs))
		}
	})
}

// tdxFixture is the JSON format for TDX attestation test fixtures.
// "time" is an RFC 3339 timestamp within the certificate validity window.
// "report" is the exact attestation handler response containing "evidence"
// (with the base64-encoded quote blob) and "data" (the AttestationReportData
// whose SHA-512 digest was used as the 64-byte report_data in the TDX quote).
type tdxFixture struct {
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

func loadTDXFixture(t *testing.T, name string) (*tdxFixture, bool) {
	t.Helper()
	path := filepath.Join("testdata", name)
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, false
	}
	if err != nil {
		t.Fatalf("reading fixture %s: %v", path, err)
	}
	var f tdxFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parsing fixture %s: %v", path, err)
	}
	return &f, true
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

func TestVerifyQuote(t *testing.T) {
	f, ok := loadTDXFixture(t, "tdx_attestation.json")
	if !ok {
		t.Skip("fixture testdata/tdx_attestation.json not found, skipping")
	}

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

	t.Run("valid", func(t *testing.T) {
		quote, err := VerifyQuote(blob, reportData, now)
		if err != nil {
			t.Fatalf("VerifyQuote() error: %v", err)
		}
		if quote.GetHeader().GetVersion() == 0 {
			t.Error("quote header Version is zero")
		}
		if !bytes.Equal(quote.GetTdQuoteBody().GetReportData(), reportData[:]) {
			t.Error("quote ReportData does not match expected")
		}

		// Cross-check: verify that NewAttestationData produces JSON
		// consistent with the fixture's evidence data.
		got := NewAttestationData(quote)
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
				t.Errorf("NewAttestationData JSON mismatch\ngot:     %s\nfixture: %s", gotCompact.String(), fixtureCompact.String())
			}
		}
	})

	t.Run("wrong report data", func(t *testing.T) {
		var wrong [64]byte
		copy(wrong[:], reportData[:])
		wrong[0] ^= 0xFF
		_, err := VerifyQuote(blob, wrong, now)
		if err == nil {
			t.Fatal("VerifyQuote() expected error for wrong report data")
		}
	})

	t.Run("corrupted quote signature", func(t *testing.T) {
		// The TDX quote has a signature area after the header and body.
		// Corrupt bytes in the signature region (starts after the
		// 48-byte header + 584-byte TD quote body = offset 632).
		corrupted := make([]byte, len(blob))
		copy(corrupted, blob)
		if len(corrupted) > 700 {
			corrupted[650] ^= 0xFF
			corrupted[651] ^= 0xFF
		} else {
			corrupted[len(corrupted)/2] ^= 0xFF
		}
		_, err := VerifyQuote(corrupted, reportData, now)
		if err == nil {
			t.Fatal("VerifyQuote() expected error for corrupted quote")
		}
	})

	t.Run("truncated quote", func(t *testing.T) {
		_, err := VerifyQuote(blob[:100], reportData, now)
		if err == nil {
			t.Fatal("VerifyQuote() expected error for truncated quote")
		}
	})
}
