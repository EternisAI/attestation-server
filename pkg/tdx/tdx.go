// Package tdx implements Intel TDX (Trust Domain Extensions) guest
// attestation: quote retrieval via ConfigFS and offline ECDSA-P256
// signature verification against the embedded Intel SGX Root CA.
package tdx

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/client"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"

	"github.com/eternisai/attestation-server/pkg/hexbytes"
)

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
// No mutex is needed because the ConfigFS-based QuoteProvider is stateless
// (empty struct) and creates an isolated temporary directory per request.
// The kernel's ConfigFS subsystem handles concurrent access internally.
type Device struct {
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
	rawQuote, err := t.GetEvidence(reportData)
	if err != nil {
		return nil, nil, err
	}

	quote, err := VerifyEvidence(rawQuote, reportData, time.Now())
	if err != nil {
		return nil, nil, err
	}

	return rawQuote, quote, nil
}

// GetEvidence retrieves the raw TDX attestation quote incorporating the given
// report data, without performing verification. Use VerifyEvidence to verify
// the returned quote separately, or use Attest for combined retrieval and
// verification.
func (t *Device) GetEvidence(reportData [64]byte) ([]byte, error) {
	rawQuote, err := client.GetRawQuote(t.qp, reportData)
	if err != nil {
		return nil, fmt.Errorf("tdx quote request failed: %w", err)
	}
	return rawQuote, nil
}

// VerifyEvidence parses the raw quote, verifies the ECDSA-P256 signature and
// PCK certificate chain against the Intel SGX Root CA (offline, no collateral
// fetching or CRL check), and validates that the report data field matches the
// expected value.
func VerifyEvidence(rawQuote []byte, expectedReportData [64]byte, now time.Time) (*pb.QuoteV4, error) {
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
	Version        uint32           `json:"version"`
	TeeType        uint32           `json:"tee_type"`
	QeSvn          hexbytes.Bytes   `json:"qe_svn"`
	PceSvn         hexbytes.Bytes   `json:"pce_svn"`
	QeVendorID     hexbytes.Bytes   `json:"qe_vendor_id"`
	TeeTcbSvn      hexbytes.Bytes   `json:"tee_tcb_svn"`
	MrSeam         hexbytes.Bytes   `json:"mr_seam"`
	MrSignerSeam   hexbytes.Bytes   `json:"mr_signer_seam"`
	SeamAttributes hexbytes.Bytes   `json:"seam_attributes"`
	TdAttributes   hexbytes.Bytes   `json:"td_attributes"`
	Xfam           hexbytes.Bytes   `json:"xfam"`
	MrTd           hexbytes.Bytes   `json:"mr_td"`
	MrConfigID     hexbytes.Bytes   `json:"mr_config_id"`
	MrOwner        hexbytes.Bytes   `json:"mr_owner"`
	MrOwnerConfig  hexbytes.Bytes   `json:"mr_owner_config"`
	Rtmrs          []hexbytes.Bytes `json:"rtmrs"`
	ReportData     hexbytes.Bytes   `json:"report_data"`
}

// NewAttestationData extracts the select API response fields from a verified
// TDX QuoteV4.
func NewAttestationData(quote *pb.QuoteV4) *AttestationData {
	h := quote.GetHeader()
	body := quote.GetTdQuoteBody()

	rtmrs := make([]hexbytes.Bytes, len(body.GetRtmrs()))
	for i, r := range body.GetRtmrs() {
		rtmrs[i] = hexbytes.Bytes(r)
	}

	return &AttestationData{
		Version:        h.GetVersion(),
		TeeType:        h.GetTeeType(),
		QeSvn:          hexbytes.Bytes(h.GetQeSvn()),
		PceSvn:         hexbytes.Bytes(h.GetPceSvn()),
		QeVendorID:     hexbytes.Bytes(h.GetQeVendorId()),
		TeeTcbSvn:      hexbytes.Bytes(body.GetTeeTcbSvn()),
		MrSeam:         hexbytes.Bytes(body.GetMrSeam()),
		MrSignerSeam:   hexbytes.Bytes(body.GetMrSignerSeam()),
		SeamAttributes: hexbytes.Bytes(body.GetSeamAttributes()),
		TdAttributes:   hexbytes.Bytes(body.GetTdAttributes()),
		Xfam:           hexbytes.Bytes(body.GetXfam()),
		MrTd:           hexbytes.Bytes(body.GetMrTd()),
		MrConfigID:     hexbytes.Bytes(body.GetMrConfigId()),
		MrOwner:        hexbytes.Bytes(body.GetMrOwner()),
		MrOwnerConfig:  hexbytes.Bytes(body.GetMrOwnerConfig()),
		Rtmrs:          rtmrs,
		ReportData:     hexbytes.Bytes(body.GetReportData()),
	}
}
