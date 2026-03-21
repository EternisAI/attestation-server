package nitro

import (
	"fmt"
	"sync"

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

// Attest obtains an NSM attestation document with the given nonce.
func (n *NSM) Attest(nonce []byte) ([]byte, error) {
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
