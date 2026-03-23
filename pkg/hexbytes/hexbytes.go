package hexbytes

import (
	"encoding/hex"
	"fmt"
)

// Bytes is a byte slice that serializes to a hex-encoded JSON string
// instead of the default base64.
type Bytes []byte

func (h Bytes) MarshalJSON() ([]byte, error) {
	return []byte(`"` + hex.EncodeToString(h) + `"`), nil
}

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
