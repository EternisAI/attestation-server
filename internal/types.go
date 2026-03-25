package app

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/goccy/go-json"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	pb "github.com/google/go-tdx-guest/proto/tdx"

	"github.com/eternisai/attestation-server/pkg/hexbytes"
	"github.com/eternisai/attestation-server/pkg/nitro"
)

// BuildInfo holds SLSA provenance metadata mirroring the Fulcio certificate
// extensions defined by sigstore. These fields are populated from a
// build-time JSON file and included in every attestation response. When
// cosign verification is enabled, each field is compared against the
// corresponding OID extension in the Fulcio signing certificate.
//
// Field definitions: https://github.com/sigstore/fulcio/blob/v1.8.5/pkg/certificate/extensions.go#L60
type BuildInfo struct {
	// Reference to specific build instructions that are responsible for signing.
	BuildSignerURI string `json:"BuildSignerURI,omitempty"`

	// Immutable reference to the specific version of the build instructions that is responsible for signing.
	BuildSignerDigest string `json:"BuildSignerDigest,omitempty"`

	// Specifies whether the build took place in platform-hosted cloud infrastructure or customer/self-hosted infrastructure.
	RunnerEnvironment string `json:"RunnerEnvironment,omitempty"`

	// Source repository URL that the build was based on.
	SourceRepositoryURI string `json:"SourceRepositoryURI,omitempty"`

	// Immutable reference to a specific version of the source code that the build was based upon.
	SourceRepositoryDigest string `json:"SourceRepositoryDigest,omitempty"`

	// Source Repository Ref that the build run was based upon.
	SourceRepositoryRef string `json:"SourceRepositoryRef,omitempty"`

	// Immutable identifier for the source repository the workflow was based upon.
	SourceRepositoryIdentifier string `json:"SourceRepositoryIdentifier,omitempty"`

	// Source repository owner URL of the owner of the source repository that the build was based on.
	SourceRepositoryOwnerURI string `json:"SourceRepositoryOwnerURI,omitempty"`

	// Immutable identifier for the owner of the source repository that the workflow was based upon.
	SourceRepositoryOwnerIdentifier string `json:"SourceRepositoryOwnerIdentifier,omitempty"`

	// Build Config URL to the top-level/initiating build instructions.
	BuildConfigURI string `json:"BuildConfigURI,omitempty"`

	// Immutable reference to the specific version of the top-level/initiating build instructions.
	BuildConfigDigest string `json:"BuildConfigDigest,omitempty"`

	// Event or action that initiated the build.
	BuildTrigger string `json:"BuildTrigger,omitempty"`

	// Run Invocation URL to uniquely identify the build execution.
	RunInvocationURI string `json:"RunInvocationURI,omitempty"`

	// Source repository visibility at the time of the build.
	SourceRepositoryVisibility string `json:"SourceRepositoryVisibility,omitempty"`

	// Deployment target for a workflow or job.
	DeploymentEnvironment string `json:"DeploymentEnvironment,omitempty"`
}

// AttestationReport is the top-level JSON response returned by the
// attestation endpoint. It pairs the attestation evidence (hardware-signed
// blobs) with the report data that was hashed into the evidence nonce.
// Data is stored as json.RawMessage so that the pre-marshaled report data
// bytes used for the nonce digest appear byte-for-byte identical in the
// response.
type AttestationReport struct {
	Evidence     []*AttestationEvidence `json:"evidence"`
	Data         json.RawMessage        `json:"data"`
	Dependencies []json.RawMessage      `json:"dependencies,omitempty"`
}

// AttestationEvidence holds one piece of hardware attestation evidence.
// Kind identifies the TEE type (e.g. "nitronsm", "nitrotpm", "sevsnp", "tdx").
// Blob is the raw attestation document/quote. Data contains parsed fields
// from the verified evidence for convenience.
type AttestationEvidence struct {
	Kind string `json:"kind"`
	Blob []byte `json:"blob"`
	Data any    `json:"data,omitempty"`
}

// AttestationReportData contains everything the server binds into the
// attestation nonce via SHA-512 hashing. A verifier can recompute the hash
// from these fields and check it against the nonce inside the evidence blob.
type AttestationReportData struct {
	RequestID    string         `json:"request_id"`
	Nonce        string         `json:"nonce,omitempty"`
	BuildInfo    *BuildInfo     `json:"build_info"`
	TLS          *TLSReportData `json:"tls"`
	Endorsements []string       `json:"endorsements"`
	UserData     map[string]any `json:"user_data,omitempty"`
	SecureBoot   *bool          `json:"secure_boot,omitempty"`
	TPMData      *TPMData       `json:"tpm,omitempty"`
}

// TPMData holds TPM PCR values along with the hash algorithm used.
// The structure mirrors the Nitro attestation document's PCR format.
type TPMData struct {
	Digest string                 `json:"digest"`
	PCRs   map[int]hexbytes.Bytes `json:"pcrs"`
}

// TLSReportData groups TLS certificate fingerprints for the server's public
// and private certificates as well as the client certificate (from XFCC header).
type TLSReportData struct {
	Client  *TLSCertificateData `json:"client,omitempty"`
	Public  *TLSCertificateData `json:"public,omitempty"`
	Private *TLSCertificateData `json:"private,omitempty"`
}

// TLSCertificateData holds SHA-256 hex-encoded fingerprints of a certificate
// and its public key (SPKI DER).
type TLSCertificateData struct {
	CertificateFingerprint string `json:"certificate"`
	PublicKeyFingerprint   string `json:"public_key,omitempty"`
}

// EndorsementDocument holds golden measurement values keyed by evidence type.
// The JSON keys match the evidence kind strings used in attestation reports.
type EndorsementDocument struct {
	NitroNSM *PCREndorsement `json:"nitronsm,omitempty"`
	NitroTPM *PCREndorsement `json:"nitrotpm,omitempty"`
	SEVSNP   *string         `json:"sevsnp,omitempty"`
	TDX      *TDXEndorsement `json:"tdx,omitempty"`
	TPM      *PCREndorsement `json:"tpm,omitempty"`
}

// PCREndorsement wraps the "Measurements" object used by NitroNSM, NitroTPM,
// and generic TPM endorsements.
type PCREndorsement struct {
	Measurements PCRGoldenValues `json:"Measurements"`
}

// DigestBytes maps canonical hash algorithm names to their output size in bytes.
var DigestBytes = map[string]int{
	"SHA1":   20,
	"SHA256": 32,
	"SHA384": 48,
	"SHA512": 64,
}

// PCRGoldenValues holds a hash algorithm identifier and a set of PCR index →
// hex-encoded golden value pairs. The JSON representation uses dynamic keys
// ("HashAlgorithm", "PCR0", "PCR1", …, "PCR24") which are handled by a
// custom UnmarshalJSON.
//
// HashAlgorithm is mandatory and must start with a canonical algorithm name
// (SHA1, SHA256, SHA384, SHA512). The first whitespace-separated token is
// uppercased and matched; trailing tokens (e.g. "{ ... }" in Nitro-style
// values) are ignored. The canonical name is stored.
type PCRGoldenValues struct {
	HashAlgorithm string
	PCRs          map[int]string
}

// UnmarshalJSON parses a JSON object with "HashAlgorithm" and dynamic "PCR\d+"
// keys into the PCRGoldenValues struct.
func (v *PCRGoldenValues) UnmarshalJSON(data []byte) error {
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	algRaw, ok := raw["HashAlgorithm"]
	if !ok || algRaw == "" {
		return fmt.Errorf("HashAlgorithm is required")
	}
	canon := strings.ToUpper(strings.Fields(algRaw)[0])
	if _, valid := DigestBytes[canon]; !valid {
		return fmt.Errorf("unsupported HashAlgorithm %q (expected SHA1, SHA256, SHA384, or SHA512)", canon)
	}
	v.HashAlgorithm = canon

	digestSize := DigestBytes[canon]
	v.PCRs = make(map[int]string)
	for key, val := range raw {
		if key == "HashAlgorithm" {
			continue
		}
		if !strings.HasPrefix(key, "PCR") {
			continue
		}
		idx, err := strconv.Atoi(key[3:])
		if err != nil {
			return fmt.Errorf("invalid PCR key %q: %w", key, err)
		}
		if idx < 0 || idx > 24 {
			return fmt.Errorf("PCR index %d out of range 0-24", idx)
		}
		if val == "" {
			return fmt.Errorf("PCR%d: empty value", idx)
		}
		decoded, err := hex.DecodeString(val)
		if err != nil {
			return fmt.Errorf("PCR%d: invalid hex: %w", idx, err)
		}
		if len(decoded) != digestSize {
			return fmt.Errorf("PCR%d: value is %d bytes, expected %d for %s", idx, len(decoded), digestSize, canon)
		}
		v.PCRs[idx] = val
	}
	return nil
}

// TDXEndorsement holds TDX-specific golden measurements. All fields are
// optional; only present fields are validated.
type TDXEndorsement struct {
	MRTD  string `json:"MRTD,omitempty"`
	RTMR0 string `json:"RTMR0,omitempty"`
	RTMR1 string `json:"RTMR1,omitempty"`
	RTMR2 string `json:"RTMR2,omitempty"`
}

// parsedSelfAttestation holds parsed results from startup self-attestation,
// used for endorsement validation against golden measurements.
type parsedSelfAttestation struct {
	nitroNSMDoc  *nitro.AttestationDocument
	nitroTPMDoc  *nitro.AttestationDocument
	sevSNPReport *spb.Report
	tdxQuote     *pb.QuoteV4
	tpmPCRs      map[int]hexbytes.Bytes
}

// parsedDependencyEvidence holds parsed evidence from a verified dependency report.
type parsedDependencyEvidence struct {
	nitroNSMDoc  *nitro.AttestationDocument
	nitroTPMDoc  *nitro.AttestationDocument
	sevSNPReport *spb.Report
	tdxQuote     *pb.QuoteV4
}
