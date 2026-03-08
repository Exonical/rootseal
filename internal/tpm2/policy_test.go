package tpm2

import (
	"testing"

	"rootseal/pkg/api"
)

// --- ParsePCRList ---

func TestParsePCRList_Empty(t *testing.T) {
	pcrs, err := ParsePCRList("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pcrs) != len(DefaultRequiredPCRs) {
		t.Errorf("len: got %d want %d", len(pcrs), len(DefaultRequiredPCRs))
	}
}

func TestParsePCRList_Valid(t *testing.T) {
	pcrs, err := ParsePCRList("0,2,7")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []int{0, 2, 7}
	if len(pcrs) != len(want) {
		t.Fatalf("len: got %d want %d", len(pcrs), len(want))
	}
	for i, v := range want {
		if pcrs[i] != v {
			t.Errorf("pcrs[%d]: got %d want %d", i, pcrs[i], v)
		}
	}
}

func TestParsePCRList_WithSpaces(t *testing.T) {
	pcrs, err := ParsePCRList("0, 2, 7")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pcrs) != 3 {
		t.Errorf("len: got %d want 3", len(pcrs))
	}
}

func TestParsePCRList_InvalidIndex(t *testing.T) {
	_, err := ParsePCRList("abc")
	if err == nil {
		t.Error("expected error for invalid PCR index")
	}
}

func TestParsePCRList_OutOfRange(t *testing.T) {
	_, err := ParsePCRList("99")
	if err == nil {
		t.Error("expected error for out-of-range PCR index")
	}
}

func TestParsePCRList_NegativeIndex(t *testing.T) {
	_, err := ParsePCRList("-1")
	if err == nil {
		t.Error("expected error for negative PCR index")
	}
}

// --- PCRPolicy.Verify ---

func makePCRValues(pcrs map[int][]byte) []*api.PCRValue {
	out := make([]*api.PCRValue, 0, len(pcrs))
	for idx, digest := range pcrs {
		out = append(out, &api.PCRValue{Index: int32(idx), Digest: digest})
	}
	return out
}

func TestPCRPolicy_NilAllowsAll(t *testing.T) {
	var p *PCRPolicy
	if err := p.Verify(nil); err != nil {
		t.Errorf("nil policy should allow all: %v", err)
	}
}

func TestPCRPolicy_RequiredPresent(t *testing.T) {
	p := NewPCRPolicy([]int{0, 7}, true)
	vals := makePCRValues(map[int][]byte{
		0: {0x01},
		7: {0x02},
	})
	if err := p.Verify(vals); err != nil {
		t.Errorf("expected pass with required PCRs present: %v", err)
	}
}

func TestPCRPolicy_RequiredMissing(t *testing.T) {
	p := NewPCRPolicy([]int{0, 7}, true)
	vals := makePCRValues(map[int][]byte{
		0: {0x01},
		// PCR 7 missing
	})
	if err := p.Verify(vals); err == nil {
		t.Error("expected error when required PCR missing")
	}
}

func TestPCRPolicy_AllowAnyValues(t *testing.T) {
	p := NewPCRPolicy([]int{0}, true)
	// PCR present but any digest is fine
	vals := makePCRValues(map[int][]byte{0: {0xDE, 0xAD}})
	if err := p.Verify(vals); err != nil {
		t.Errorf("AllowAnyValues should not check digest: %v", err)
	}
}

func TestPCRPolicy_StrictMatch(t *testing.T) {
	expected := map[int][]byte{
		0: {0x01, 0x02, 0x03},
	}
	p := StrictPCRPolicy(expected)
	vals := makePCRValues(map[int][]byte{
		0: {0x01, 0x02, 0x03},
	})
	if err := p.Verify(vals); err != nil {
		t.Errorf("exact match should pass: %v", err)
	}
}

func TestPCRPolicy_StrictMismatch(t *testing.T) {
	expected := map[int][]byte{
		0: {0x01, 0x02, 0x03},
	}
	p := StrictPCRPolicy(expected)
	vals := makePCRValues(map[int][]byte{
		0: {0xFF, 0xFF, 0xFF},
	})
	if err := p.Verify(vals); err == nil {
		t.Error("expected error on digest mismatch")
	}
}

func TestPCRPolicy_StrictMissingPCR(t *testing.T) {
	expected := map[int][]byte{
		0: {0x01},
		7: {0x02},
	}
	p := StrictPCRPolicy(expected)
	vals := makePCRValues(map[int][]byte{
		0: {0x01},
		// PCR 7 absent
	})
	if err := p.Verify(vals); err == nil {
		t.Error("expected error when strict policy PCR absent from quote")
	}
}

func TestDefaultBootPCRPolicy_AllowsAnyValues(t *testing.T) {
	p := DefaultBootPCRPolicy()
	if !p.AllowAnyPCRValues {
		t.Error("DefaultBootPCRPolicy should allow any PCR values")
	}
	if len(p.RequiredPCRs) != len(DefaultRequiredPCRs) {
		t.Errorf("required PCRs: got %d want %d", len(p.RequiredPCRs), len(DefaultRequiredPCRs))
	}
}
