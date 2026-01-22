// Package tpm2 provides TPM 2.0 attestation using github.com/google/go-tpm
package tpm2

import (
	"fmt"
	"io"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const defaultTPMPath = "/dev/tpmrm0"

// OpenTPM opens a connection to the TPM device
func OpenTPM() (transport.TPMCloser, error) {
	// Try /dev/tpmrm0 first (resource manager), then /dev/tpm0
	paths := []string{"/dev/tpmrm0", "/dev/tpm0"}

	var lastErr error
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			lastErr = err
			continue
		}

		t, err := transport.OpenTPM(path)
		if err != nil {
			lastErr = err
			continue
		}
		return t, nil
	}

	return nil, fmt.Errorf("failed to open TPM: %w", lastErr)
}

// CreatePrimary creates a primary key under the owner hierarchy
func CreatePrimary(t transport.TPM) (*tpm2.CreatePrimaryResponse, error) {
	primary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}

	return primary.Execute(t)
}

// FlushContext flushes a TPM handle
func FlushContext(t transport.TPM, handle tpm2.TPMHandle) error {
	flush := tpm2.FlushContext{
		FlushHandle: handle,
	}
	_, err := flush.Execute(t)
	return err
}

// ReadPCRs reads the specified PCR values
func ReadPCRs(t transport.TPM, pcrs []int) (map[int][]byte, error) {
	pcrSelector, err := createPCRSelector(pcrs)
	if err != nil {
		return nil, err
	}

	pcrRead := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: pcrSelector,
				},
			},
		},
	}

	resp, err := pcrRead.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("failed to read PCRs: %w", err)
	}

	result := make(map[int][]byte)
	for i, digest := range resp.PCRValues.Digests {
		if i < len(pcrs) {
			result[pcrs[i]] = digest.Buffer
		}
	}

	return result, nil
}

// createPCRSelector creates a PCR selection bitmap for the given PCR indices
func createPCRSelector(pcrs []int) ([]byte, error) {
	const sizeOfPCRSelect = 3
	mask := make([]byte, sizeOfPCRSelect)

	for _, n := range pcrs {
		if n >= 8*sizeOfPCRSelect {
			return nil, fmt.Errorf("PCR index %d is out of range", n)
		}
		mask[n>>3] |= 1 << (n & 0x7)
	}

	return mask, nil
}

// GetTPMInfo returns basic TPM information
func GetTPMInfo(t transport.TPM) (manufacturer string, err error) {
	caps := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTManufacturer),
		PropertyCount: 1,
	}

	resp, err := caps.Execute(t)
	if err != nil {
		return "", fmt.Errorf("failed to get TPM capabilities: %w", err)
	}

	props, err := resp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return "", err
	}

	if len(props.TPMProperty) > 0 {
		mfr := props.TPMProperty[0].Value
		manufacturer = string([]byte{
			byte(mfr >> 24),
			byte(mfr >> 16),
			byte(mfr >> 8),
			byte(mfr),
		})
	}

	return manufacturer, nil
}

// TPMCloser wraps transport.TPMCloser for convenience
type TPMCloser = transport.TPMCloser

// TPM wraps transport.TPM for convenience
type TPM = transport.TPM

// Ensure io.Closer is implemented
var _ io.Closer = (TPMCloser)(nil)
