// Package hexbytes provides a []byte wrapper that JSON-serializes as a
// hex-encoded string instead of the standard library's base64 encoding.
// Used throughout the attestation API to represent binary measurements,
// digests, and nonces in human-readable form.
package hexbytes

import (
	"encoding/hex"
	"fmt"
)

// Bytes is a byte slice that serializes to a hex-encoded JSON string
// instead of the default base64.
type Bytes []byte

// MarshalJSON encodes the byte slice as a JSON string containing
// lowercase hexadecimal characters (e.g. "deadbeef").
func (h Bytes) MarshalJSON() ([]byte, error) {
	return []byte(`"` + hex.EncodeToString(h) + `"`), nil
}

// UnmarshalJSON decodes a hex-encoded JSON string back into raw bytes.
// An empty string unmarshals to nil (not an empty slice).
func (h *Bytes) UnmarshalJSON(data []byte) error {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return fmt.Errorf("hexbytes: expected JSON string")
	}
	s := string(data[1 : len(data)-1])
	if s == "" {
		*h = nil
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("hexbytes: invalid hex: %w", err)
	}
	*h = b
	return nil
}
