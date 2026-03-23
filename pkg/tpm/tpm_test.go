package tpm

import (
	"bytes"
	"fmt"
	"testing"
)

func TestPcrBitmap(t *testing.T) {
	allPCRs := make([]int, 24)
	for i := range allPCRs {
		allPCRs[i] = i
	}

	tests := []struct {
		name string
		pcrs []int
		want []byte
	}{
		{name: "nil input", pcrs: nil, want: []byte{0x00, 0x00, 0x00}},
		{name: "empty slice", pcrs: []int{}, want: []byte{0x00, 0x00, 0x00}},
		{name: "pcr 0", pcrs: []int{0}, want: []byte{0x01, 0x00, 0x00}},
		{name: "pcr 7", pcrs: []int{7}, want: []byte{0x80, 0x00, 0x00}},
		{name: "pcr 8", pcrs: []int{8}, want: []byte{0x00, 0x01, 0x00}},
		{name: "pcr 15", pcrs: []int{15}, want: []byte{0x00, 0x80, 0x00}},
		{name: "pcr 16", pcrs: []int{16}, want: []byte{0x00, 0x00, 0x01}},
		{name: "pcr 23", pcrs: []int{23}, want: []byte{0x00, 0x00, 0x80}},
		{name: "pcrs 0-7", pcrs: []int{0, 1, 2, 3, 4, 5, 6, 7}, want: []byte{0xFF, 0x00, 0x00}},
		{name: "all 24 pcrs", pcrs: allPCRs, want: []byte{0xFF, 0xFF, 0xFF}},
		{name: "pcr 24 out of range", pcrs: []int{24}, want: []byte{0x00, 0x00, 0x00}},
		{name: "pcr -1 negative", pcrs: []int{-1}, want: []byte{0x00, 0x00, 0x00}},
		{name: "mixed valid and invalid", pcrs: []int{0, 24, -1}, want: []byte{0x01, 0x00, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pcrBitmap(tt.pcrs)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("pcrBitmap(%v) = %v, want %v", tt.pcrs, got, tt.want)
			}
		})
	}
}

func TestPcrIsSelected(t *testing.T) {
	tests := []struct {
		name      string
		pcrSelect []byte
		pcr       int
		want      bool
	}{
		{name: "pcr 0 set in first byte", pcrSelect: []byte{0x01, 0x00, 0x00}, pcr: 0, want: true},
		{name: "pcr 1 not set in first byte", pcrSelect: []byte{0x01, 0x00, 0x00}, pcr: 1, want: false},
		{name: "pcr 7 set in first byte", pcrSelect: []byte{0x80, 0x00, 0x00}, pcr: 7, want: true},
		{name: "pcr 8 set in second byte", pcrSelect: []byte{0x00, 0x01, 0x00}, pcr: 8, want: true},
		{name: "pcr 23 set in third byte", pcrSelect: []byte{0x00, 0x00, 0x80}, pcr: 23, want: true},
		{name: "pcr 0 in empty slice", pcrSelect: []byte{}, pcr: 0, want: false},
		{name: "pcr 24 out of range", pcrSelect: []byte{0xFF, 0xFF, 0xFF}, pcr: 24, want: false},
		{name: "pcr 0 in all-set bitmap", pcrSelect: []byte{0xFF, 0xFF, 0xFF}, pcr: 0, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pcrIsSelected(tt.pcrSelect, tt.pcr)
			if got != tt.want {
				t.Errorf("pcrIsSelected(%v, %d) = %v, want %v",
					fmt.Sprintf("%#v", tt.pcrSelect), tt.pcr, got, tt.want)
			}
		})
	}
}
