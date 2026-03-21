package sevsnp

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/client"
	"github.com/google/go-sev-guest/kds"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"
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

	report, err := VerifyAttestation(rawReport, certTable, reportData, s.dev.Product())
	if err != nil {
		return nil, nil, err
	}

	blob := make([]byte, len(rawReport)+len(certTable))
	copy(blob, rawReport)
	copy(blob[len(rawReport):], certTable)

	return blob, report, nil
}

// VerifyAttestation parses the raw report and certificate table, verifies
// the ECDSA-P384 signature against AMD's built-in trust roots (offline, no CRL
// check), and validates that the report data field matches the expected value.
func VerifyAttestation(rawReport, certTable []byte, expectedReportData [64]byte, product *spb.SevProduct) (*spb.Report, error) {
	report, err := abi.ReportToProto(rawReport)
	if err != nil {
		return nil, fmt.Errorf("parsing sev-snp report: %w", err)
	}

	certs := new(abi.CertTable)
	if err := certs.Unmarshal(certTable); err != nil {
		return nil, fmt.Errorf("parsing sev-snp certificate table: %w", err)
	}

	attestation := &spb.Attestation{
		Report:           report,
		CertificateChain: certs.Proto(),
		Product:          product,
	}

	opts := &verify.Options{
		DisableCertFetching: true,
		CheckRevocations:    false,
		Now:                 time.Now(),
	}
	if err := verify.SnpAttestation(attestation, opts); err != nil {
		return nil, fmt.Errorf("sev-snp signature verification failed: %w", err)
	}

	if !bytes.Equal(report.ReportData, expectedReportData[:]) {
		return nil, fmt.Errorf("sev-snp report data mismatch")
	}

	return report, nil
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
