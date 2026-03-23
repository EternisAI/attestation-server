package nitro

import (
	"fmt"
	"sync"
	"time"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

// NSM manages the Nitro NSM device session for attestation.
// All device access is serialized by an internal mutex because the nsm
// library does not synchronize the underlying ioctl syscall on the shared
// /dev/nsm fd.
type NSM struct {
	mu   sync.Mutex
	sess *nsm.Session
}

// OpenNSM opens the default NSM session for attestation.
func OpenNSM() (*NSM, error) {
	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, fmt.Errorf("opening nsm session: %w", err)
	}
	return &NSM{sess: sess}, nil
}

// Close closes the NSM session.
func (n *NSM) Close() error {
	return n.sess.Close()
}

// Attest obtains an NSM attestation document with the given nonce, verifies
// the COSE signature and certificate chain, and returns both the raw blob
// and the parsed document. Verification uses the same VerifyEvidence
// function that external verifiers would use, catching corrupted device
// output before it reaches callers.
func (n *NSM) Attest(nonce []byte) ([]byte, *AttestationDocument, error) {
	blob, err := n.GetEvidence(nonce)
	if err != nil {
		return nil, nil, err
	}
	doc, err := VerifyEvidence(blob, nonce, time.Now())
	if err != nil {
		return nil, nil, err
	}
	return blob, doc, nil
}

// GetEvidence obtains the raw NSM attestation document (COSE_Sign1 blob)
// with the given nonce, without performing verification. Use
// VerifyEvidence to verify the returned blob separately, or use Attest
// for combined retrieval and verification.
func (n *NSM) GetEvidence(nonce []byte) ([]byte, error) {
	n.mu.Lock()
	res, err := n.sess.Send(&request.Attestation{
		Nonce: nonce,
	})
	n.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("nsm attestation request failed: %w", err)
	}
	if res.Error != "" {
		return nil, fmt.Errorf("nsm returned error: %s", res.Error)
	}
	if res.Attestation == nil {
		return nil, fmt.Errorf("nsm response missing attestation field")
	}
	if res.Attestation.Document == nil {
		return nil, fmt.Errorf("nsm response missing attestation document")
	}
	return res.Attestation.Document, nil
}
