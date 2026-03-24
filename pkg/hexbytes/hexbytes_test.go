package hexbytes

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestBytes_MarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		h    Bytes
		want string
	}{
		{name: "nil", h: Bytes(nil), want: `""`},
		{name: "empty", h: Bytes{}, want: `""`},
		{name: "deadbeef", h: Bytes{0xde, 0xad, 0xbe, 0xef}, want: `"deadbeef"`},
		{name: "single zero byte", h: Bytes{0x00}, want: `"00"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.MarshalJSON()
			if err != nil {
				t.Fatalf("MarshalJSON() returned error: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("MarshalJSON() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestBytes_MarshalJSON_inStruct(t *testing.T) {
	type wrapper struct {
		Data Bytes `json:"data"`
	}
	w := wrapper{Data: Bytes{0xca, 0xfe}}
	got, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("json.Marshal() returned error: %v", err)
	}
	want := `{"data":"cafe"}`
	if string(got) != want {
		t.Errorf("json.Marshal() = %s, want %s", got, want)
	}
}

func TestBytes_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Bytes
		wantErr bool
	}{
		{name: "empty string", input: `""`, want: nil},
		{name: "deadbeef", input: `"deadbeef"`, want: Bytes{0xde, 0xad, 0xbe, 0xef}},
		{name: "single zero byte", input: `"00"`, want: Bytes{0x00}},
		{name: "not a string", input: `123`, wantErr: true},
		{name: "invalid hex", input: `"zzzz"`, wantErr: true},
		{name: "odd length hex", input: `"abc"`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var h Bytes
			err := h.UnmarshalJSON([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatal("UnmarshalJSON() expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalJSON() returned error: %v", err)
			}
			if !bytes.Equal(h, tt.want) {
				t.Errorf("UnmarshalJSON() = %v, want %v", h, tt.want)
			}
		})
	}
}

func TestBytes_RoundTrip_inMap(t *testing.T) {
	original := map[int]Bytes{
		0:  {0xab, 0xcd},
		10: {0xef},
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	var decoded map[int]Bytes
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if len(decoded) != len(original) {
		t.Fatalf("len = %d, want %d", len(decoded), len(original))
	}
	for k, want := range original {
		got, ok := decoded[k]
		if !ok {
			t.Errorf("missing key %d", k)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("key %d = %v, want %v", k, got, want)
		}
	}
}

// FuzzBytes_UnmarshalJSON ensures UnmarshalJSON never panics on
// arbitrary input. HexBytes values are deserialized from untrusted
// attestation responses and endorsement documents.
func FuzzBytes_UnmarshalJSON(f *testing.F) {
	f.Add([]byte(`"deadbeef"`))
	f.Add([]byte(`""`))
	f.Add([]byte(`123`))
	f.Add([]byte(`"zzzz"`))
	f.Add([]byte(`"abc"`))
	f.Add([]byte(``))
	f.Add([]byte(`"`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var h Bytes
		h.UnmarshalJSON(data)
	})
}

// FuzzBytes_RoundTrip verifies that marshal→unmarshal is lossless
// for arbitrary byte slices.
func FuzzBytes_RoundTrip(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xde, 0xad, 0xbe, 0xef})
	f.Fuzz(func(t *testing.T, data []byte) {
		h := Bytes(data)
		encoded, err := h.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON error: %v", err)
		}
		var decoded Bytes
		if err := decoded.UnmarshalJSON(encoded); err != nil {
			t.Fatalf("UnmarshalJSON error: %v", err)
		}
		if !bytes.Equal(decoded, data) {
			t.Errorf("round-trip mismatch: got %v, want %v", decoded, data)
		}
	})
}
