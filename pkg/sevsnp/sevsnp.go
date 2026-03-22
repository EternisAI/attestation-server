package sevsnp

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/client"
	"github.com/google/go-sev-guest/kds"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify/trust"
)

// HexBytes is a byte slice that serializes to a hex-encoded JSON string
// instead of the default base64.
type HexBytes []byte

func (h HexBytes) MarshalJSON() ([]byte, error) {
	return []byte(`"` + hex.EncodeToString(h) + `"`), nil
}

// Device manages the SEV-SNP guest device for attestation.
// All device access is serialized by an internal mutex because the underlying
// LinuxDevice performs multiple ioctls per attestation request and has no
// built-in synchronization.
type Device struct {
	mu  sync.Mutex
	dev client.Device
}

// Open opens the SEV-SNP guest device for attestation.
func Open() (*Device, error) {
	dev, err := client.OpenDevice()
	if err != nil {
		return nil, fmt.Errorf("opening sev-snp device: %w", err)
	}
	return &Device{dev: dev}, nil
}

// Close closes the SEV-SNP guest device.
func (s *Device) Close() error {
	return s.dev.Close()
}

// Attest requests a SEV-SNP extended attestation report incorporating the given
// report data at the specified VMPL. It returns the concatenated raw report +
// certificate table (parseable by abi.ReportCertsToProto) and the verified
// parsed report.
func (s *Device) Attest(reportData [64]byte, vmpl int) ([]byte, *spb.Report, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rawReport, certTable, err := client.GetRawExtendedReportAtVmpl(s.dev, reportData, vmpl)
	if err != nil {
		return nil, nil, fmt.Errorf("sev-snp attestation request failed: %w", err)
	}

	report, err := VerifyAttestation(rawReport, certTable, reportData, s.dev.Product(), time.Now())
	if err != nil {
		return nil, nil, err
	}

	blob := make([]byte, len(rawReport)+len(certTable))
	copy(blob, rawReport)
	copy(blob[len(rawReport):], certTable)

	return blob, report, nil
}

// VerifyAttestation parses the raw report and certificate table, verifies
// the ECDSA-P384 signature against AMD's embedded trust roots (offline, no
// CRL check), and validates that the report data field matches the expected
// value.
//
// We perform verification manually instead of delegating to
// verify.SnpAttestation because go-sev-guest (as of v0.14.1) has three
// issues that prevent it from working on cloud platforms like AWS Nitro:
//
//  1. Policy "must be zero" check: abi.ReportToProto rejects reports whose
//     guest policy contains bits the library does not yet recognise (e.g.
//     bit 25 = PageSwapDisable, ABI rev 1.58). We work around this in
//     reportToProto by masking unknown bits before parsing, then restoring
//     the original policy value in the returned report.
//     See https://github.com/google/go-sev-guest/pull/181
//
//  2. Malformed ASK/ARK in the certificate table: some hypervisors (AWS
//     Nitro) populate the extended report's certificate table with ASK/ARK
//     entries that x509.ParseCertificate rejects. The standard library path
//     (verify.SnpAttestation → decodeCerts → ProductCerts.Decode) attempts
//     to parse these and fails. We bypass this by resolving the endorsement
//     key (VCEK/VLEK) directly and verifying its certificate chain against
//     AMD's embedded root certificates (trustedRoots), which are parsed
//     once at init time from the PEM bundles shipped with go-sev-guest.
//
//  3. Signature verification over reconstructed bytes: verify.SnpAttestation
//     calls SnpProtoReportSignature, which reconstructs the raw report from
//     the protobuf (ReportToAbiBytes) and re-validates the format. Because
//     the proto carries a sanitised policy (issue 1), the reconstructed
//     bytes differ from what the hardware actually signed, causing ECDSA
//     verification to fail. We verify the signature directly against the
//     original raw report bytes instead.
func VerifyAttestation(rawReport, certTable []byte, expectedReportData [64]byte, product *spb.SevProduct, now time.Time) (*spb.Report, error) {
	if now.IsZero() {
		now = time.Now()
	}

	report, origPolicy, err := reportToProto(rawReport)
	if err != nil {
		return nil, fmt.Errorf("parsing sev-snp report: %w", err)
	}

	certs := new(abi.CertTable)
	if err := certs.Unmarshal(certTable); err != nil {
		return nil, fmt.Errorf("parsing sev-snp certificate table: %w", err)
	}
	chain := certs.Proto()

	info, err := abi.ParseSignerInfo(report.GetSignerInfo())
	if err != nil {
		return nil, fmt.Errorf("parsing sev-snp signer info: %w", err)
	}

	// Resolve the endorsement key (VCEK or VLEK) certificate from the
	// report's certificate table.
	var ekCert []byte
	switch info.SigningKey {
	case abi.VcekReportSigner:
		ekCert = chain.GetVcekCert()
	case abi.VlekReportSigner:
		ekCert = chain.GetVlekCert()
	}
	if len(ekCert) == 0 {
		return nil, fmt.Errorf("sev-snp certificate table missing %v cert", info.SigningKey)
	}
	endorsementKey, err := trust.ParseCert(ekCert)
	if err != nil {
		return nil, fmt.Errorf("parsing sev-snp %v cert: %w", info.SigningKey, err)
	}

	// Determine the product line (Milan, Genoa, Turin) from the
	// endorsement key's x509 extensions so we can look up the correct
	// AMD root certificates.
	exts, err := kds.CertificateExtensions(endorsementKey, info.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("parsing sev-snp certificate extensions: %w", err)
	}
	prod, err := kds.ParseProductName(exts.ProductName, info.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("parsing sev-snp product name: %w", err)
	}
	productLine := kds.ProductLine(prod)

	// Verify the endorsement key's certificate chain against AMD's
	// embedded root certificates, trying both VCEK and VLEK roots for the
	// product line until one succeeds.
	roots, ok := trustedRoots[productLine]
	if !ok {
		return nil, fmt.Errorf("sev-snp: no trusted roots for product line %q", productLine)
	}
	var verifyErr error
	for _, root := range roots {
		verifyOpts := root.ProductCerts.X509Options(now, info.SigningKey)
		if verifyOpts == nil {
			continue
		}
		if _, err := endorsementKey.Verify(*verifyOpts); err != nil {
			verifyErr = err
			continue
		}
		verifyErr = nil
		break
	}
	if verifyErr != nil {
		return nil, fmt.Errorf("sev-snp certificate chain verification failed: %w", verifyErr)
	}

	// Verify the report signature directly against the original raw
	// report bytes (see issue 3 in the function doc comment).
	sigDER, err := abi.ReportToSignatureDER(rawReport)
	if err != nil {
		return nil, fmt.Errorf("sev-snp: could not interpret report signature: %w", err)
	}
	if err := endorsementKey.CheckSignature(x509.ECDSAWithSHA384, abi.SignedComponent(rawReport), sigDER); err != nil {
		return nil, fmt.Errorf("sev-snp report signature verification failed: %w", err)
	}

	if !bytes.Equal(report.ReportData, expectedReportData[:]) {
		return nil, fmt.Errorf("sev-snp report data mismatch")
	}

	// Restore the original policy (including bits the library doesn't yet
	// recognise) so callers and the API response reflect the real hardware
	// value.
	report.Policy = origPolicy

	return report, nil
}

// trustedRoots contains AMD's embedded root certificates (ASK + ARK) for
// all supported product lines, for both VCEK and VLEK signing keys. These
// are parsed once at init time from the PEM bundles shipped with
// go-sev-guest and used to verify the endorsement key's certificate chain
// without relying on the ASK/ARK entries in the report's certificate table
// (see issue 2 in VerifyAttestation's doc comment).
var trustedRoots = func() map[string][]*trust.AMDRootCerts {
	roots := make(map[string][]*trust.AMDRootCerts)
	for _, cfg := range []struct {
		product   string
		vcekBytes []byte
		vlekBytes []byte
	}{
		{"Milan", trust.AskArkMilanVcekBytes, trust.AskArkMilanVlekBytes},
		{"Genoa", trust.AskArkGenoaVcekBytes, trust.AskArkGenoaVlekBytes},
		{"Turin", trust.AskArkTurinVcekBytes, trust.AskArkTurinVlekBytes},
	} {
		vcek := &trust.AMDRootCerts{ProductLine: cfg.product, ProductCerts: &trust.ProductCerts{}}
		if err := vcek.ProductCerts.FromKDSCertBytes(trimPEM(cfg.vcekBytes)); err != nil {
			panic("parsing embedded " + cfg.product + " VCEK certs: " + err.Error())
		}
		vlek := &trust.AMDRootCerts{ProductLine: cfg.product, ProductCerts: &trust.ProductCerts{}}
		if err := vlek.ProductCerts.FromKDSCertBytes(trimPEM(cfg.vlekBytes)); err != nil {
			panic("parsing embedded " + cfg.product + " VLEK certs: " + err.Error())
		}
		roots[cfg.product] = []*trust.AMDRootCerts{vcek, vlek}
	}
	return roots
}()

// trimPEM removes trailing whitespace from PEM-encoded certificate bundles.
// Some embedded PEM files in go-sev-guest have trailing \r\n bytes that
// cause kds.ParseProductCertChain to reject them.
func trimPEM(data []byte) []byte {
	return []byte(strings.TrimRight(string(data), " \t\r\n"))
}

// policyKnownBits is a mask of all policy bits recognized by the version
// of go-sev-guest linked into this binary (v0.14.1: bits 0–24). Bits
// outside this mask may be set by hypervisors (e.g. AWS Nitro sets bit 25
// = PageSwapDisable from ABI rev 1.58) before the library adds support
// for them, causing abi.ReportToProto to reject the report with
// "malformed guest policy: mbz range policy[…] not all zero".
//
// Support for bit 25 (PageSwapDisable, ABI 1.58) is added in:
//
//	https://github.com/google/go-sev-guest/pull/181
//
// This workaround can be removed once we upgrade to a release that
// includes PR #181.
const policyKnownBits uint64 = (1 << 25) - 1 // bits 0–24

// reportToProto parses a raw SEV-SNP report into a protobuf, working around
// strict "must be zero" policy checks in go-sev-guest that reject reports
// from hypervisors using newer policy bits. Returns the parsed report (with
// the policy sanitized to only known bits) and the original policy value.
// The caller must keep the proto policy sanitized during verification, then
// restore origPolicy afterward if exposing it externally.
func reportToProto(raw []byte) (report *spb.Report, origPolicy uint64, err error) {
	if len(raw) < abi.ReportSize {
		return nil, 0, fmt.Errorf("report too short: %d < %d", len(raw), abi.ReportSize)
	}

	// Read the original policy (little-endian uint64 at offset 0x08).
	origPolicy = binary.LittleEndian.Uint64(raw[0x08:0x10])

	// If unknown bits are set, parse a sanitized copy so abi.ReportToProto
	// does not reject it.
	if origPolicy & ^policyKnownBits != 0 {
		sanitized := make([]byte, len(raw))
		copy(sanitized, raw)
		binary.LittleEndian.PutUint64(sanitized[0x08:0x10], origPolicy&policyKnownBits)

		report, err = abi.ReportToProto(sanitized)
		return report, origPolicy, err
	}

	report, err = abi.ReportToProto(raw)
	return report, origPolicy, err
}

// AttestationData contains select fields from a verified SEV-SNP
// attestation report, included in the API response for convenience.
type AttestationData struct {
	Version          uint32   `json:"version"`
	GuestSvn         uint32   `json:"guest_svn"`
	Policy           uint64   `json:"policy"`
	FamilyID         HexBytes `json:"family_id"`
	ImageID          HexBytes `json:"image_id"`
	VMPL             uint32   `json:"vmpl"`
	ReportData       HexBytes `json:"report_data"`
	Measurement      HexBytes `json:"measurement"`
	HostData         HexBytes `json:"host_data"`
	IDKeyDigest      HexBytes `json:"id_key_digest"`
	AuthorKeyDigest  HexBytes `json:"author_key_digest"`
	ReportID         HexBytes `json:"report_id"`
	ReportIDMA       HexBytes `json:"report_id_ma"`
	ChipID           HexBytes `json:"chip_id"`
	CurrentTCB       TCBParts `json:"current_tcb"`
	ReportedTCB      TCBParts `json:"reported_tcb"`
	CommittedTCB     TCBParts `json:"committed_tcb"`
	LaunchTCB        TCBParts `json:"launch_tcb"`
	CurrentVersion   Firmware `json:"current_version"`
	CommittedVersion Firmware `json:"committed_version"`
	PlatformInfo     uint64   `json:"platform_info"`
	SignerInfo       uint32   `json:"signer_info"`
}

// TCBParts holds the decomposed components of a 64-bit TCB version.
type TCBParts struct {
	BootloaderSPL uint8 `json:"bootloader_spl"`
	TEESPL        uint8 `json:"tee_spl"`
	SNPSPL        uint8 `json:"snp_spl"`
	MicrocodeSPL  uint8 `json:"microcode_spl"`
}

// Firmware holds firmware version information.
type Firmware struct {
	Build uint32 `json:"build"`
	Minor uint32 `json:"minor"`
	Major uint32 `json:"major"`
}

// NewAttestationData extracts the select API response fields from a verified
// SEV-SNP report.
func NewAttestationData(report *spb.Report) *AttestationData {
	return &AttestationData{
		Version:         report.Version,
		GuestSvn:        report.GuestSvn,
		Policy:          report.Policy,
		FamilyID:        HexBytes(report.FamilyId),
		ImageID:         HexBytes(report.ImageId),
		VMPL:            report.Vmpl,
		ReportData:      HexBytes(report.ReportData),
		Measurement:     HexBytes(report.Measurement),
		HostData:        HexBytes(report.HostData),
		IDKeyDigest:     HexBytes(report.IdKeyDigest),
		AuthorKeyDigest: HexBytes(report.AuthorKeyDigest),
		ReportID:        HexBytes(report.ReportId),
		ReportIDMA:      HexBytes(report.ReportIdMa),
		ChipID:          HexBytes(report.ChipId),
		CurrentTCB:      decomposeTCB(report.CurrentTcb),
		ReportedTCB:     decomposeTCB(report.ReportedTcb),
		CommittedTCB:    decomposeTCB(report.CommittedTcb),
		LaunchTCB:       decomposeTCB(report.LaunchTcb),
		CurrentVersion: Firmware{
			Build: report.CurrentBuild,
			Minor: report.CurrentMinor,
			Major: report.CurrentMajor,
		},
		CommittedVersion: Firmware{
			Build: report.CommittedBuild,
			Minor: report.CommittedMinor,
			Major: report.CommittedMajor,
		},
		PlatformInfo: report.PlatformInfo,
		SignerInfo:   report.SignerInfo,
	}
}

func decomposeTCB(v uint64) TCBParts {
	parts := kds.DecomposeTCBVersion(kds.TCBVersion(v))
	return TCBParts{
		BootloaderSPL: parts.BlSpl,
		TEESPL:        parts.TeeSpl,
		SNPSPL:        parts.SnpSpl,
		MicrocodeSPL:  parts.UcodeSpl,
	}
}
