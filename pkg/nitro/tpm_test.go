package nitro

import (
	"encoding/binary"
	"testing"
)

func TestBuildTPMCommand(t *testing.T) {
	tests := []struct {
		name       string
		cc         uint32
		handles    []uint32
		params     []byte
		wantLen    int
		checkBytes func(t *testing.T, buf []byte)
	}{
		{
			name:    "no handles no params",
			cc:      0x0000012A,
			handles: nil,
			params:  nil,
			wantLen: 23, // 10 + 0 + 4 + 9
			checkBytes: func(t *testing.T, buf []byte) {
				// Tag: TPM_ST_SESSIONS = 0x8002
				if buf[0] != 0x80 || buf[1] != 0x02 {
					t.Errorf("tag = [%02x %02x], want [80 02]", buf[0], buf[1])
				}

				// Size field
				size := binary.BigEndian.Uint32(buf[2:6])
				if size != 23 {
					t.Errorf("size field = %d, want 23", size)
				}

				// Command code
				cc := binary.BigEndian.Uint32(buf[6:10])
				if cc != 0x0000012A {
					t.Errorf("cc = 0x%08X, want 0x0000012A", cc)
				}

				// Auth area size (starts right after header since no handles)
				authSize := binary.BigEndian.Uint32(buf[10:14])
				if authSize != 9 {
					t.Errorf("auth area size = %d, want 9", authSize)
				}

				// TPM_RS_PW
				pw := binary.BigEndian.Uint32(buf[14:18])
				if pw != 0x40000009 {
					t.Errorf("TPM_RS_PW = 0x%08X, want 0x40000009", pw)
				}

				// Nonce (2 bytes, empty)
				nonce := binary.BigEndian.Uint16(buf[18:20])
				if nonce != 0 {
					t.Errorf("nonce = 0x%04X, want 0x0000", nonce)
				}

				// Session attributes
				if buf[20] != 0x00 {
					t.Errorf("session attrs = 0x%02X, want 0x00", buf[20])
				}

				// HMAC (2 bytes, empty)
				hmac := binary.BigEndian.Uint16(buf[21:23])
				if hmac != 0 {
					t.Errorf("hmac = 0x%04X, want 0x0000", hmac)
				}
			},
		},
		{
			name:    "two handles with params",
			cc:      0x00000137,
			handles: []uint32{0x01000001, 0x01000001},
			params:  []byte{0x00, 0x04, 0xDE, 0xAD, 0x00, 0x00},
			wantLen: 37, // 10 + 8 + 4 + 9 + 6
			checkBytes: func(t *testing.T, buf []byte) {
				// Size field matches expected total length
				size := binary.BigEndian.Uint32(buf[2:6])
				if size != 37 {
					t.Errorf("size field = %d, want 37", size)
				}

				// Command code
				cc := binary.BigEndian.Uint32(buf[6:10])
				if cc != 0x00000137 {
					t.Errorf("cc = 0x%08X, want 0x00000137", cc)
				}

				// First handle at offset 10
				h1 := binary.BigEndian.Uint32(buf[10:14])
				if h1 != 0x01000001 {
					t.Errorf("handle[0] = 0x%08X, want 0x01000001", h1)
				}

				// Second handle at offset 14
				h2 := binary.BigEndian.Uint32(buf[14:18])
				if h2 != 0x01000001 {
					t.Errorf("handle[1] = 0x%08X, want 0x01000001", h2)
				}

				// Auth area size at offset 18
				authSize := binary.BigEndian.Uint32(buf[18:22])
				if authSize != 9 {
					t.Errorf("auth area size = %d, want 9", authSize)
				}

				// TPM_RS_PW at offset 22
				pw := binary.BigEndian.Uint32(buf[22:26])
				if pw != 0x40000009 {
					t.Errorf("TPM_RS_PW = 0x%08X, want 0x40000009", pw)
				}

				// Params at end (offset 31)
				wantParams := []byte{0x00, 0x04, 0xDE, 0xAD, 0x00, 0x00}
				for i, b := range wantParams {
					if buf[31+i] != b {
						t.Errorf("params[%d] = 0x%02X, want 0x%02X", i, buf[31+i], b)
					}
				}
			},
		},
		{
			name:    "one handle no params",
			cc:      0x0000014E,
			handles: []uint32{0x01000001},
			params:  nil,
			wantLen: 27, // 10 + 4 + 4 + 9
			checkBytes: func(t *testing.T, buf []byte) {
				// Just verify size field consistency
				size := binary.BigEndian.Uint32(buf[2:6])
				if size != 27 {
					t.Errorf("size field = %d, want 27", size)
				}

				// Handle at offset 10
				h := binary.BigEndian.Uint32(buf[10:14])
				if h != 0x01000001 {
					t.Errorf("handle[0] = 0x%08X, want 0x01000001", h)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildTPMCommand(tt.cc, tt.handles, tt.params)

			if len(got) != tt.wantLen {
				t.Fatalf("len(buildTPMCommand()) = %d, want %d", len(got), tt.wantLen)
			}

			// Verify that the size field in the header always matches the actual buffer length.
			sizeField := binary.BigEndian.Uint32(got[2:6])
			if int(sizeField) != len(got) {
				t.Errorf("size field (%d) does not match actual length (%d)", sizeField, len(got))
			}

			if tt.checkBytes != nil {
				tt.checkBytes(t, got)
			}
		})
	}
}
