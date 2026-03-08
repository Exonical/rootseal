package tpm2

import (
	"testing"
)

func TestCreatePCRSelector_Basic(t *testing.T) {
	// PCR 0 → byte 0 bit 0; PCR 1 → byte 0 bit 1; PCR 7 → byte 0 bit 7
	mask, err := createPCRSelector([]int{0, 1, 7})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mask) != 3 {
		t.Fatalf("mask length: got %d want 3", len(mask))
	}
	// byte 0 should have bits 0,1,7 set = 0b10000011 = 0x83
	if mask[0] != 0x83 {
		t.Errorf("mask[0]: got 0x%02x want 0x83", mask[0])
	}
	if mask[1] != 0 || mask[2] != 0 {
		t.Errorf("mask[1]/mask[2] should be zero: got 0x%02x 0x%02x", mask[1], mask[2])
	}
}

func TestCreatePCRSelector_PCR8To15(t *testing.T) {
	// PCR 8 → byte 1 bit 0
	mask, err := createPCRSelector([]int{8})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mask[1] != 0x01 {
		t.Errorf("mask[1]: got 0x%02x want 0x01", mask[1])
	}
}

func TestCreatePCRSelector_Empty(t *testing.T) {
	mask, err := createPCRSelector([]int{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, b := range mask {
		if b != 0 {
			t.Errorf("mask[%d] = 0x%02x, want 0 for empty PCR list", i, b)
		}
	}
}

func TestCreatePCRSelector_OutOfRange(t *testing.T) {
	_, err := createPCRSelector([]int{24})
	if err == nil {
		t.Error("expected error for PCR index 24 (out of 3-byte range)")
	}
}

func TestCreatePCRSelector_MaxValid(t *testing.T) {
	// PCR 23 is the highest valid index (byte 2 bit 7)
	mask, err := createPCRSelector([]int{23})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mask[2] != 0x80 {
		t.Errorf("mask[2]: got 0x%02x want 0x80", mask[2])
	}
}
