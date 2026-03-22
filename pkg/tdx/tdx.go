package tdx

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/client"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
)

// HexBytes is a byte slice that serializes to a hex-encoded JSON string
// instead of the default base64.
type HexBytes []byte

func (h HexBytes) MarshalJSON() ([]byte, error) {
	return []byte(`"` + hex.EncodeToString(h) + `"`), nil
}

// intelSGXRootCAPEM is the Intel SGX Root CA certificate used to verify the
// PCK certificate chain in TDX attestation quotes.
// Downloaded from https://certificates.trustedservices.intel.com/IntelSGXRootCA.der
// SHA-256 fingerprint: 44A0196B2B99F889B8E149E95B807A350E74249643998E85A7CBB8CCFAB674D3
const intelSGXRootCAPEM = `-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----`

var intelSGXRootPool = func() *x509.CertPool {
	block, _ := pem.Decode([]byte(intelSGXRootCAPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("parsing embedded Intel SGX root CA: " + err.Error())
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}()

// Device manages the TDX quote provider for attestation.
// All access is serialized by an internal mutex for safe concurrent use.
type Device struct {
	mu sync.Mutex
	qp client.QuoteProvider
}

// Open initializes the TDX quote provider for attestation.
// It uses the ConfigFS-based QuoteProvider which is the non-deprecated path
// supported by modern kernels (the legacy /dev/tdx_guest ioctl returns ENOTTY
// for quote requests on these systems).
func Open() (*Device, error) {
	qp, err := client.GetQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("getting tdx quote provider: %w", err)
	}
	if err := qp.IsSupported(); err != nil {
		return nil, fmt.Errorf("tdx quote provider not supported: %w", err)
	}
	return &Device{qp: qp}, nil
}

// Close is a no-op; the ConfigFS quote provider holds no persistent resources.
func (t *Device) Close() error {
	return nil
}

// Attest requests a TDX attestation quote incorporating the given report data.
// It returns the raw quote bytes and the verified parsed QuoteV4.
func (t *Device) Attest(reportData [64]byte) ([]byte, *pb.QuoteV4, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	rawQuote, err := client.GetRawQuote(t.qp, reportData)
	if err != nil {
		return nil, nil, fmt.Errorf("tdx quote request failed: %w", err)
	}

	quote, err := VerifyQuote(rawQuote, reportData, time.Now())
	if err != nil {
		return nil, nil, err
	}

	return rawQuote, quote, nil
}

// VerifyQuote parses the raw quote, verifies the ECDSA-P256 signature and
// PCK certificate chain against the Intel SGX Root CA (offline, no collateral
// fetching or CRL check), and validates that the report data field matches the
// expected value.
func VerifyQuote(rawQuote []byte, expectedReportData [64]byte, now time.Time) (*pb.QuoteV4, error) {
	parsed, err := abi.QuoteToProto(rawQuote)
	if err != nil {
		return nil, fmt.Errorf("parsing tdx quote: %w", err)
	}

	quote, ok := parsed.(*pb.QuoteV4)
	if !ok {
		return nil, fmt.Errorf("unexpected tdx quote type: %T", parsed)
	}

	if now.IsZero() {
		now = time.Now()
	}
	opts := &verify.Options{
		CheckRevocations: false,
		GetCollateral:    false,
		TrustedRoots:     intelSGXRootPool,
		Now:              now,
	}
	if err := verify.TdxQuote(quote, opts); err != nil {
		return nil, fmt.Errorf("tdx quote verification failed: %w", err)
	}

	if !bytes.Equal(quote.GetTdQuoteBody().GetReportData(), expectedReportData[:]) {
		return nil, fmt.Errorf("tdx report data mismatch")
	}

	return quote, nil
}

// AttestationData contains select fields from a verified TDX attestation
// quote, included in the API response for convenience.
type AttestationData struct {
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

// NewAttestationData extracts the select API response fields from a verified
// TDX QuoteV4.
func NewAttestationData(quote *pb.QuoteV4) *AttestationData {
	h := quote.GetHeader()
	body := quote.GetTdQuoteBody()

	rtmrs := make([]HexBytes, len(body.GetRtmrs()))
	for i, r := range body.GetRtmrs() {
		rtmrs[i] = HexBytes(r)
	}

	return &AttestationData{
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
