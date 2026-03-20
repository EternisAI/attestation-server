package app

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/client"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
)

// TDX manages the TDX guest device for attestation.
// All device access is serialized by an internal mutex because the underlying
// device issues multiple ioctls per quote request and has no built-in
// synchronization.
type TDX struct {
	mu  sync.Mutex
	dev client.Device
}

// OpenTDX opens the TDX guest device for attestation.
func OpenTDX() (*TDX, error) {
	dev, err := client.OpenDevice()
	if err != nil {
		return nil, fmt.Errorf("opening tdx device: %w", err)
	}
	return &TDX{dev: dev}, nil
}

// Close closes the TDX guest device.
func (t *TDX) Close() error {
	return t.dev.Close()
}

// Attest requests a TDX attestation quote incorporating the given report data.
// It returns the raw quote bytes and the verified parsed QuoteV4.
func (t *TDX) Attest(reportData [64]byte) ([]byte, *pb.QuoteV4, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	rawQuote, err := client.GetRawQuote(t.dev, reportData)
	if err != nil {
		return nil, nil, fmt.Errorf("tdx quote request failed: %w", err)
	}

	quote, err := verifyTDXQuote(rawQuote, reportData)
	if err != nil {
		return nil, nil, err
	}

	return rawQuote, quote, nil
}

// verifyTDXQuote parses the raw quote, verifies the ECDSA-P256 signature and
// PCK certificate chain against Intel's embedded trust root (offline, no
// collateral fetching or CRL check), and validates that the report data field
// matches the expected value.
func verifyTDXQuote(rawQuote []byte, expectedReportData [64]byte) (*pb.QuoteV4, error) {
	parsed, err := abi.QuoteToProto(rawQuote)
	if err != nil {
		return nil, fmt.Errorf("parsing tdx quote: %w", err)
	}

	quote, ok := parsed.(*pb.QuoteV4)
	if !ok {
		return nil, fmt.Errorf("unexpected tdx quote type: %T", parsed)
	}

	opts := &verify.Options{
		CheckRevocations: false,
		GetCollateral:    false,
		Now:              time.Now(),
	}
	if err := verify.TdxQuote(quote, opts); err != nil {
		return nil, fmt.Errorf("tdx quote verification failed: %w", err)
	}

	if !bytes.Equal(quote.GetTdQuoteBody().GetReportData(), expectedReportData[:]) {
		return nil, fmt.Errorf("tdx report data mismatch")
	}

	return quote, nil
}

// TDXAttestationData contains select fields from a verified TDX attestation
// quote, included in the API response for convenience.
type TDXAttestationData struct {
	Version        uint32     `json:"version"`
	TeeType        uint32     `json:"tee_type"`
	QeSvn          HexBytes   `json:"qe_svn"`
	PceSvn         HexBytes   `json:"pce_svn"`
	QeVendorID     HexBytes   `json:"qe_vendor_id"`
	TeeTcbSvn      HexBytes   `json:"tee_tcb_svn"`
	MrSeam         HexBytes   `json:"mr_seam"`
	MrSignerSeam   HexBytes   `json:"mr_signer_seam"`
	SeamAttributes HexBytes   `json:"seam_attributes"`
	TdAttributes   HexBytes   `json:"td_attributes"`
	Xfam           HexBytes   `json:"xfam"`
	MrTd           HexBytes   `json:"mr_td"`
	MrConfigID     HexBytes   `json:"mr_config_id"`
	MrOwner        HexBytes   `json:"mr_owner"`
	MrOwnerConfig  HexBytes   `json:"mr_owner_config"`
	Rtmrs          []HexBytes `json:"rtmrs"`
	ReportData     HexBytes   `json:"report_data"`
}

func tdxAttestationData(quote *pb.QuoteV4) *TDXAttestationData {
	h := quote.GetHeader()
	body := quote.GetTdQuoteBody()

	rtmrs := make([]HexBytes, len(body.GetRtmrs()))
	for i, r := range body.GetRtmrs() {
		rtmrs[i] = HexBytes(r)
	}

	return &TDXAttestationData{
		Version:        h.GetVersion(),
		TeeType:        h.GetTeeType(),
		QeSvn:          HexBytes(h.GetQeSvn()),
		PceSvn:         HexBytes(h.GetPceSvn()),
		QeVendorID:     HexBytes(h.GetQeVendorId()),
		TeeTcbSvn:      HexBytes(body.GetTeeTcbSvn()),
		MrSeam:         HexBytes(body.GetMrSeam()),
		MrSignerSeam:   HexBytes(body.GetMrSignerSeam()),
		SeamAttributes: HexBytes(body.GetSeamAttributes()),
		TdAttributes:   HexBytes(body.GetTdAttributes()),
		Xfam:           HexBytes(body.GetXfam()),
		MrTd:           HexBytes(body.GetMrTd()),
		MrConfigID:     HexBytes(body.GetMrConfigId()),
		MrOwner:        HexBytes(body.GetMrOwner()),
		MrOwnerConfig:  HexBytes(body.GetMrOwnerConfig()),
		Rtmrs:          rtmrs,
		ReportData:     HexBytes(body.GetReportData()),
	}
}
