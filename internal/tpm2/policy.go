// Package tpm2 provides TPM 2.0 attestation using github.com/google/go-tpm
package tpm2

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"rootseal/pkg/api"
)

// PCRPolicy defines expected PCR values for attestation verification
type PCRPolicy struct {
	// PCRs maps PCR index to expected digest (SHA256)
	// If a PCR is not in the map, any value is accepted
	PCRs map[int][]byte

	// RequiredPCRs lists PCR indices that must be present in the quote
	RequiredPCRs []int

	// AllowAnyPCRValues if true, skips PCR value verification (useful for initial enrollment)
	AllowAnyPCRValues bool
}

// DefaultRequiredPCRs are the PCRs required by default for attestation
// PCR 0:  BIOS/UEFI firmware measurements
// PCR 2:  Option ROMs code
// PCR 7:  Secure Boot state
var DefaultRequiredPCRs = []int{0, 2, 7}

// DefaultBootPCRPolicy returns a policy that requires standard boot PCRs
// but doesn't enforce specific values (useful for heterogeneous environments)
func DefaultBootPCRPolicy() *PCRPolicy {
	return NewPCRPolicy(DefaultRequiredPCRs, true)
}

// NewPCRPolicy creates a PCR policy with the specified required PCRs
func NewPCRPolicy(requiredPCRs []int, allowAnyValues bool) *PCRPolicy {
	return &PCRPolicy{
		RequiredPCRs:      requiredPCRs,
		AllowAnyPCRValues: allowAnyValues,
	}
}

// ParsePCRList parses a comma-separated list of PCR indices (e.g., "0,2,7,11")
func ParsePCRList(s string) ([]int, error) {
	if s == "" {
		return DefaultRequiredPCRs, nil
	}

	parts := strings.Split(s, ",")
	pcrs := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		idx, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid PCR index %q: %w", p, err)
		}
		if idx < 0 || idx > 23 {
			return nil, fmt.Errorf("PCR index %d out of range (0-23)", idx)
		}
		pcrs = append(pcrs, idx)
	}
	return pcrs, nil
}

// StrictPCRPolicy creates a policy with specific expected PCR values
func StrictPCRPolicy(expectedPCRs map[int][]byte) *PCRPolicy {
	required := make([]int, 0, len(expectedPCRs))
	for idx := range expectedPCRs {
		required = append(required, idx)
	}
	return &PCRPolicy{
		PCRs:              expectedPCRs,
		RequiredPCRs:      required,
		AllowAnyPCRValues: false,
	}
}

// Verify checks if the provided PCR values match the policy
func (p *PCRPolicy) Verify(pcrs []*api.PCRValue) error {
	if p == nil {
		return nil // No policy = allow all
	}

	// Build a map of provided PCRs for easy lookup
	providedPCRs := make(map[int][]byte)
	for _, pcr := range pcrs {
		providedPCRs[int(pcr.Index)] = pcr.Digest
	}

	// Check that all required PCRs are present
	for _, required := range p.RequiredPCRs {
		if _, ok := providedPCRs[required]; !ok {
			return fmt.Errorf("required PCR %d not present in quote", required)
		}
	}

	// If we're allowing any values, we're done
	if p.AllowAnyPCRValues {
		return nil
	}

	// Verify specific PCR values
	for idx, expected := range p.PCRs {
		provided, ok := providedPCRs[idx]
		if !ok {
			return fmt.Errorf("expected PCR %d not present in quote", idx)
		}
		if !bytes.Equal(provided, expected) {
			return fmt.Errorf("PCR %d value mismatch: expected %x, got %x", idx, expected, provided)
		}
	}

	return nil
}
