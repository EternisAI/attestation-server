package nitro

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// HexBytes is a byte slice that serializes to a hex-encoded JSON string
// instead of the default base64.
type HexBytes []byte

func (h HexBytes) MarshalJSON() ([]byte, error) {
	return []byte(`"` + hex.EncodeToString(h) + `"`), nil
}

// awsNitroRootCAPEM is the AWS Nitro Enclaves root certificate (Root-G1)
// downloaded from https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
// SHA-256 fingerprint: 641A0321A3E244EFE456463195D606317ED7CDCC3C1756E09893F3C68F79BB5B
const awsNitroRootCAPEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`

var awsNitroRootCA = func() *x509.Certificate {
	block, _ := pem.Decode([]byte(awsNitroRootCAPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("parsing embedded AWS Nitro root CA: " + err.Error())
	}
	return cert
}()

// coseAlgES384 is the COSE algorithm identifier for ECDSA w/ SHA-384.
const coseAlgES384 = -35

// AttestationDocument is the full deserialized Nitro attestation document
// as defined by the AWS spec. Both NSM and NitroTPM documents share this
// structure; the only difference is the PCR field name ("pcrs" vs "nitrotpm_pcrs").
// After deserialization exactly one of PCRs or NitroTPMPCRs will be populated.
//
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation-document-validate.html#doc-def
type AttestationDocument struct {
	ModuleID     string         `cbor:"module_id"`
	Timestamp    uint64         `cbor:"timestamp"`
	Digest       string         `cbor:"digest"`
	PCRs         map[int][]byte `cbor:"pcrs"`
	NitroTPMPCRs map[int][]byte `cbor:"nitrotpm_pcrs"`
	Certificate  []byte         `cbor:"certificate"`
	CABundle     [][]byte       `cbor:"cabundle"`
	PublicKey    []byte         `cbor:"public_key"`
	UserData     []byte         `cbor:"user_data"`
	Nonce        []byte         `cbor:"nonce"`
}

// AttestationData contains select fields from a verified Nitro attestation
// document, included in the API response for convenience. Exactly one of PCRs
// or NitroTPMPCRs is populated depending on the evidence type.
type AttestationData struct {
	Module       string           `json:"module"`
	Timestamp    time.Time        `json:"timestamp"`
	Digest       string           `json:"digest"`
	PCRs         map[int]HexBytes `json:"pcrs,omitempty"`
	NitroTPMPCRs map[int]HexBytes `json:"nitrotpm_pcrs,omitempty"`
	Nonce        HexBytes         `json:"nonce,omitempty"`
}

// NewAttestationData extracts the select API response fields from a verified
// AttestationDocument.
func NewAttestationData(doc *AttestationDocument) *AttestationData {
	return &AttestationData{
		Module:       doc.ModuleID,
		Timestamp:    time.UnixMilli(int64(doc.Timestamp)).UTC(),
		Digest:       doc.Digest,
		PCRs:         toHexBytesMap(doc.PCRs),
		NitroTPMPCRs: toHexBytesMap(doc.NitroTPMPCRs),
		Nonce:        HexBytes(doc.Nonce),
	}
}

func toHexBytesMap(m map[int][]byte) map[int]HexBytes {
	if m == nil {
		return nil
	}
	out := make(map[int]HexBytes, len(m))
	for k, v := range m {
		out[k] = HexBytes(v)
	}
	return out
}

// VerifyAttestation parses a COSE_Sign1-wrapped Nitro attestation
// document, verifies the COSE ES384 signature and certificate chain against
// the well-known AWS Nitro root CA, checks that the nonce matches, and returns
// the full deserialized document. Works for both NSM and NitroTPM
// attestation documents.
func VerifyAttestation(blob, expectedNonce []byte, now time.Time) (*AttestationDocument, error) {
	// --- 1. Parse COSE_Sign1 envelope ---
	// COSE_Sign1 = [protected, unprotected, payload, signature]
	// fxamacker/cbor strips the CBOR tag 18 transparently.
	var cose [4]cbor.RawMessage
	if err := cbor.Unmarshal(blob, &cose); err != nil {
		return nil, fmt.Errorf("decoding COSE_Sign1 envelope: %w", err)
	}

	var protectedBytes []byte
	if err := cbor.Unmarshal(cose[0], &protectedBytes); err != nil {
		return nil, fmt.Errorf("decoding COSE protected header: %w", err)
	}

	var payload []byte
	if err := cbor.Unmarshal(cose[2], &payload); err != nil {
		return nil, fmt.Errorf("decoding COSE payload: %w", err)
	}

	var signature []byte
	if err := cbor.Unmarshal(cose[3], &signature); err != nil {
		return nil, fmt.Errorf("decoding COSE signature: %w", err)
	}

	// Verify the protected header specifies ES384.
	var protectedHeader map[int]int
	if err := cbor.Unmarshal(protectedBytes, &protectedHeader); err != nil {
		return nil, fmt.Errorf("decoding COSE protected header map: %w", err)
	}
	if alg := protectedHeader[1]; alg != coseAlgES384 {
		return nil, fmt.Errorf("unsupported COSE algorithm %d (expected ES384/%d)", alg, coseAlgES384)
	}

	// --- 2. Decode attestation document ---
	var doc AttestationDocument
	if err := cbor.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("decoding attestation document: %w", err)
	}

	// --- 3. Verify certificate chain ---
	leafCert, err := x509.ParseCertificate(doc.Certificate)
	if err != nil {
		return nil, fmt.Errorf("parsing leaf certificate: %w", err)
	}

	intermediates := x509.NewCertPool()
	for i, der := range doc.CABundle {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing CA bundle certificate %d: %w", i, err)
		}
		intermediates.AddCert(c)
	}

	roots := x509.NewCertPool()
	roots.AddCert(awsNitroRootCA)

	if _, err := leafCert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
	}); err != nil {
		return nil, fmt.Errorf("certificate chain verification failed: %w", err)
	}

	// --- 4. Verify COSE ES384 signature ---
	ecKey, ok := leafCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("leaf certificate public key is not ECDSA")
	}

	// ES384 signature is r || s, each 48 bytes.
	if len(signature) != 96 {
		return nil, fmt.Errorf("invalid ES384 signature length %d (expected 96)", len(signature))
	}

	// Sig_structure = ["Signature1", protected, external_aad, payload]
	sigInput, err := cbor.Marshal([]any{"Signature1", protectedBytes, []byte{}, payload})
	if err != nil {
		return nil, fmt.Errorf("encoding COSE Sig_structure: %w", err)
	}

	hash := sha512.Sum384(sigInput)
	r := new(big.Int).SetBytes(signature[:48])
	s := new(big.Int).SetBytes(signature[48:])
	if !ecdsa.Verify(ecKey, hash[:], r, s) {
		return nil, fmt.Errorf("COSE signature verification failed")
	}

	// --- 5. Verify nonce ---
	if !bytes.Equal(doc.Nonce, expectedNonce) {
		return nil, fmt.Errorf("nonce mismatch")
	}

	return &doc, nil
}
