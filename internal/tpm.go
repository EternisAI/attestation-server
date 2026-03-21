package app

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

const tpmRMDevicePath = "/dev/tpmrm0"

// ReadTPMPCRs opens the TPM resource manager device, reads all 24 PCR values
// for the given hash algorithm, and returns them as hex-encoded strings keyed
// by PCR index.
func ReadTPMPCRs(alg tpm2.TPMAlgID) (map[string]string, error) {
	t, err := linuxtpm.Open(tpmRMDevicePath)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", tpmRMDevicePath, err)
	}
	defer t.Close()

	const numPCRs = 24
	result := make(map[string]string, numPCRs)

	// Build initial set of all PCR indices to read.
	remaining := make([]int, numPCRs)
	for i := range remaining {
		remaining[i] = i
	}

	// TPM may return a subset of requested PCRs per call due to buffer limits.
	for len(remaining) > 0 {
		sel := tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      alg,
					PCRSelect: pcrBitmap(remaining),
				},
			},
		}

		resp, err := tpm2.PCRRead{PCRSelectionIn: sel}.Execute(t)
		if err != nil {
			return nil, fmt.Errorf("pcr read: %w", err)
		}

		// Find the returned selection bitmap for our algorithm.
		var returned []byte
		for _, s := range resp.PCRSelectionOut.PCRSelections {
			if s.Hash == alg {
				returned = s.PCRSelect
				break
			}
		}

		var digestIdx int
		var next []int
		for _, pcr := range remaining {
			if pcrIsSelected(returned, pcr) {
				if digestIdx >= len(resp.PCRValues.Digests) {
					return nil, fmt.Errorf("pcr %d selected in response but no digest available", pcr)
				}
				result[strconv.Itoa(pcr)] = hex.EncodeToString(resp.PCRValues.Digests[digestIdx].Buffer)
				digestIdx++
			} else {
				next = append(next, pcr)
			}
		}

		if len(next) == len(remaining) {
			return nil, fmt.Errorf("tpm returned no pcr values for pcrs %v", remaining)
		}
		remaining = next
	}

	return result, nil
}

// pcrBitmap builds a 3-byte PCR selection bitmap for PCRs 0–23.
func pcrBitmap(pcrs []int) []byte {
	bm := make([]byte, 3)
	for _, pcr := range pcrs {
		if pcr >= 0 && pcr < 24 {
			bm[pcr/8] |= 1 << uint(pcr%8)
		}
	}
	return bm
}

// pcrIsSelected reports whether the given PCR index is set in a selection bitmap.
func pcrIsSelected(pcrSelect []byte, pcr int) bool {
	byteIdx := pcr / 8
	if byteIdx >= len(pcrSelect) {
		return false
	}
	return pcrSelect[byteIdx]&(1<<uint(pcr%8)) != 0
}
