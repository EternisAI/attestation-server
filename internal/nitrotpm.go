package app

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
)

const (
	tpmDevicePath = "/dev/tpm0"

	// TPM2 command tags.
	tpmSTSessions uint16 = 0x8002

	// TPM2 command codes.
	tpmCCNVDefineSpace   uint32 = 0x0000012A
	tpmCCNVUndefineSpace uint32 = 0x00000122
	tpmCCNVWrite         uint32 = 0x00000137
	tpmCCNVRead          uint32 = 0x0000014E
	tpmCCVendorNSM       uint32 = 0x20000001

	// TPM2 well-known handles.
	tpmRSPW    uint32 = 0x40000009 // password session handle
	tpmRHOwner uint32 = 0x40000001

	// NV index configuration.
	nvIndex      uint32 = 0x01000001
	nvBufferSize uint16 = 8192
	nvMaxChunk   int    = 1024

	// NV attributes (TPMA_NV).
	// Bit positions per TCG TPM 2.0 Part 2 and tpm2-tss/tss2_tpm2_types.h.
	nvAttrAuthWrite uint32 = 0x00000004 // bit 2:  TPMA_NV_AUTHWRITE
	nvAttrAuthRead  uint32 = 0x00040000 // bit 18: TPMA_NV_AUTHREAD
	nvAttrNoDA      uint32 = 0x02000000 // bit 25: TPMA_NV_NO_DA

	// Hash algorithms.
	tpmAlgSHA256 uint16 = 0x000B
)

// NitroTPM manages the TPM device for NitroTPM attestation.
// All device access is serialized by an internal mutex.
type NitroTPM struct {
	mu  sync.Mutex
	dev *os.File
}

// OpenNitroTPM opens the TPM device for attestation.
//
// The device is opened via syscall.Open so that the file descriptor stays in
// blocking mode. Go's os.OpenFile puts fds into non-blocking mode and routes
// I/O through the runtime poller (epoll), which does not work reliably with
// the /dev/tpm0 character device: the TPM driver's poll() may report "ready"
// before the response is actually available, causing read() to return 0 bytes.
func OpenNitroTPM() (*NitroTPM, error) {
	fd, err := syscall.Open(tpmDevicePath, syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", tpmDevicePath, err)
	}
	f := os.NewFile(uintptr(fd), tpmDevicePath)
	return &NitroTPM{dev: f}, nil
}

// Close closes the TPM device.
func (n *NitroTPM) Close() error {
	return n.dev.Close()
}

// Attest obtains an NSM attestation document via the NitroTPM vendor command.
// The nonce is included in the CBOR-encoded NSM attestation request sent through
// the TPM NV buffer.
func (n *NitroTPM) Attest(nonce []byte) ([]byte, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Clean up any leftover NV space from a previous failed attestation.
	_ = n.nvUndefineSpace()

	if err := n.nvDefineSpace(); err != nil {
		return nil, fmt.Errorf("defining nv space: %w", err)
	}
	defer func() { _ = n.nvUndefineSpace() }()

	reqData, err := cbor.Marshal((&request.Attestation{Nonce: nonce}).Encoded())
	if err != nil {
		return nil, fmt.Errorf("encoding nsm request: %w", err)
	}

	if err := n.nvWriteAll(reqData); err != nil {
		return nil, fmt.Errorf("writing request to nv: %w", err)
	}

	if err := n.vendorNSMRequest(); err != nil {
		return nil, fmt.Errorf("vendor nsm request: %w", err)
	}

	respData, err := n.nvReadAll()
	if err != nil {
		return nil, fmt.Errorf("reading response from nv: %w", err)
	}

	var resp response.Response
	if err := cbor.NewDecoder(bytes.NewReader(respData)).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decoding nsm response: %w", err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("nsm returned error: %s", resp.Error)
	}
	if resp.Attestation == nil || resp.Attestation.Document == nil {
		return nil, fmt.Errorf("nsm response missing attestation document")
	}
	return resp.Attestation.Document, nil
}

// nvDefineSpace allocates an NV index for the NSM request/response buffer.
func (n *NitroTPM) nvDefineSpace() error {
	// TPMS_NV_PUBLIC: nvIndex(4) + nameAlg(2) + attributes(4) + authPolicy(2, empty) + dataSize(2)
	nvPub := make([]byte, 0, 14)
	nvPub = binary.BigEndian.AppendUint32(nvPub, nvIndex)
	nvPub = binary.BigEndian.AppendUint16(nvPub, tpmAlgSHA256)
	nvPub = binary.BigEndian.AppendUint32(nvPub, nvAttrAuthWrite|nvAttrAuthRead|nvAttrNoDA)
	nvPub = binary.BigEndian.AppendUint16(nvPub, 0) // empty authPolicy
	nvPub = binary.BigEndian.AppendUint16(nvPub, nvBufferSize)

	// Parameters: TPM2B_AUTH (empty) + TPM2B_NV_PUBLIC
	params := make([]byte, 0, 2+2+len(nvPub))
	params = binary.BigEndian.AppendUint16(params, 0)                  // TPM2B_AUTH: empty
	params = binary.BigEndian.AppendUint16(params, uint16(len(nvPub))) // TPM2B_NV_PUBLIC size
	params = append(params, nvPub...)

	_, err := n.execCommand(tpmCCNVDefineSpace, []uint32{tpmRHOwner}, params)
	return err
}

// nvUndefineSpace frees the NV index.
func (n *NitroTPM) nvUndefineSpace() error {
	_, err := n.execCommand(tpmCCNVUndefineSpace, []uint32{tpmRHOwner, nvIndex}, nil)
	return err
}

// nvWrite writes a chunk of data to the NV index at the given offset.
func (n *NitroTPM) nvWrite(data []byte, offset uint16) error {
	// Parameters: TPM2B_MAX_NV_BUFFER + offset
	params := make([]byte, 0, 2+len(data)+2)
	params = binary.BigEndian.AppendUint16(params, uint16(len(data)))
	params = append(params, data...)
	params = binary.BigEndian.AppendUint16(params, offset)

	_, err := n.execCommand(tpmCCNVWrite, []uint32{nvIndex, nvIndex}, params)
	return err
}

// nvWriteAll writes all data to the NV index, chunking as needed.
func (n *NitroTPM) nvWriteAll(data []byte) error {
	for off := 0; off < len(data); off += nvMaxChunk {
		end := off + nvMaxChunk
		if end > len(data) {
			end = len(data)
		}
		if err := n.nvWrite(data[off:end], uint16(off)); err != nil {
			return err
		}
	}
	return nil
}

// nvRead reads a chunk of data from the NV index at the given offset.
func (n *NitroTPM) nvRead(size, offset uint16) ([]byte, error) {
	params := make([]byte, 0, 4)
	params = binary.BigEndian.AppendUint16(params, size)
	params = binary.BigEndian.AppendUint16(params, offset)

	resp, err := n.execCommand(tpmCCNVRead, []uint32{nvIndex, nvIndex}, params)
	if err != nil {
		return nil, err
	}

	// Response parameters: TPM2B_MAX_NV_BUFFER (2-byte size prefix + data)
	if len(resp) < 2 {
		return nil, fmt.Errorf("nv read response too short")
	}
	dataSize := binary.BigEndian.Uint16(resp[0:2])
	if int(dataSize)+2 > len(resp) {
		return nil, fmt.Errorf("nv read data exceeds response")
	}
	return resp[2 : 2+dataSize], nil
}

// nvReadAll reads the full NV buffer contents.
func (n *NitroTPM) nvReadAll() ([]byte, error) {
	buf := make([]byte, 0, nvBufferSize)
	for off := uint16(0); off < nvBufferSize; off += uint16(nvMaxChunk) {
		remaining := nvBufferSize - off
		chunk := uint16(nvMaxChunk)
		if remaining < chunk {
			chunk = remaining
		}
		data, err := n.nvRead(chunk, off)
		if err != nil {
			return nil, err
		}
		buf = append(buf, data...)
	}
	return buf, nil
}

// vendorNSMRequest sends the AWS NitroTPM vendor command that triggers the NSM
// to process the request stored in the NV buffer and write the response back.
func (n *NitroTPM) vendorNSMRequest() error {
	_, err := n.execCommand(tpmCCVendorNSM, []uint32{nvIndex, nvIndex}, nil)
	return err
}

// execCommand sends a raw TPM2 command (with password auth) and returns the
// response parameters.
func (n *NitroTPM) execCommand(cc uint32, handles []uint32, params []byte) ([]byte, error) {
	cmd := buildTPMCommand(cc, handles, params)

	if _, err := n.dev.Write(cmd); err != nil {
		return nil, fmt.Errorf("writing to tpm: %w", err)
	}

	// The fd is in blocking mode (opened via syscall.Open, wrapped with
	// os.NewFile), so read() blocks until the TPM response is ready and
	// returns the complete response in a single call.
	buf := make([]byte, 4096)
	nr, err := n.dev.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("reading from tpm: %w", err)
	}
	if nr < 10 {
		return nil, fmt.Errorf("tpm response too short: %d bytes", nr)
	}

	resp := buf[:nr]
	rc := binary.BigEndian.Uint32(resp[6:10])
	if rc != 0 {
		return nil, fmt.Errorf("tpm response code 0x%08X", rc)
	}

	// ST_SESSIONS responses include a 4-byte parameterSize field after the
	// header, followed by the actual response parameters.
	if nr > 14 {
		paramSize := binary.BigEndian.Uint32(resp[10:14])
		if 14+int(paramSize) > nr {
			return nil, fmt.Errorf("tpm response parameter size exceeds data")
		}
		return resp[14 : 14+paramSize], nil
	}

	return nil, nil
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

// verifyNitroTPMAttestation parses a COSE_Sign1-wrapped NitroTPM attestation
// document, verifies the COSE signature and certificate chain against the
// well-known AWS Nitro root CA, checks that the nonce matches, and returns
// the select attestation data fields for the API response.
func verifyNitroTPMAttestation(blob, expectedNonce []byte) (*NitroTPMAttestationData, error) {
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
	var doc NitroTPMAttestationDocument
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

	return &NitroTPMAttestationData{
		Module:       doc.ModuleID,
		Timestamp:    time.UnixMilli(int64(doc.Timestamp)).UTC(),
		Digest:       doc.Digest,
		NitroTPMPCRs: doc.NitroTPMPCRs,
		Nonce:        doc.Nonce,
	}, nil
}

// buildTPMCommand constructs a TPM2 command with TPM_ST_SESSIONS tag and
// password-based authorization (TPM_RS_PW, empty auth value).
//
// Wire format:
//
//	tag(2) | size(4) | cc(4) | handles(4*N) | authAreaSize(4) | authArea(9) | params
func buildTPMCommand(cc uint32, handles []uint32, params []byte) []byte {
	const authAreaLen = 9 // TPM_RS_PW(4) + nonceSize(2) + attrs(1) + hmacSize(2)

	handleLen := 4 * len(handles)
	totalSize := 10 + handleLen + 4 + authAreaLen + len(params)

	buf := make([]byte, 0, totalSize)

	// Header
	buf = binary.BigEndian.AppendUint16(buf, tpmSTSessions)
	buf = binary.BigEndian.AppendUint32(buf, uint32(totalSize))
	buf = binary.BigEndian.AppendUint32(buf, cc)

	// Handle area
	for _, h := range handles {
		buf = binary.BigEndian.AppendUint32(buf, h)
	}

	// Authorization area (password session, empty auth)
	buf = binary.BigEndian.AppendUint32(buf, authAreaLen) // authorization size
	buf = binary.BigEndian.AppendUint32(buf, tpmRSPW)     // session handle: TPM_RS_PW
	buf = binary.BigEndian.AppendUint16(buf, 0)           // nonceCaller: empty
	buf = append(buf, 0)                                  // session attributes: 0
	buf = binary.BigEndian.AppendUint16(buf, 0)           // HMAC/auth: empty

	// Parameters
	buf = append(buf, params...)

	return buf
}
