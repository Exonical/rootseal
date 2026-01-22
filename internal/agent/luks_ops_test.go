package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/siderolabs/go-blockdevice/v2/encryption"
)

// mockChanger implements LUKSChanger for testing ReplaceKeyInPlace
type mockChanger struct {
	setCalled bool
	old, new  *encryption.Key
	fail      bool
}

func (m *mockChanger) SetKey(ctx context.Context, devname string, oldKey, newKey *encryption.Key) error {
	m.setCalled = true
	m.old, m.new = oldKey, newKey
	if m.fail {
		return errors.New("setkey failed")
	}
	return nil
}

// mockOperator implements LUKSOperator for testing AddNewAndRemoveOld
type mockOperator struct {
	addCalled    bool
	addDev       string
	addKeyNew    *encryption.Key
	addKeyAuth   *encryption.Key
	removeCalls  []int
	removeOnSlot int // slot that succeeds, -1 for none
}

func (m *mockOperator) AddKey(ctx context.Context, devname string, key, newKey *encryption.Key) error {
	m.addCalled = true
	m.addDev = devname
	m.addKeyAuth = key
	m.addKeyNew = newKey
	return nil
}

func (m *mockOperator) RemoveKey(ctx context.Context, devname string, slot int, key *encryption.Key) error {
	m.removeCalls = append(m.removeCalls, slot)
	if slot == m.removeOnSlot {
		return nil
	}
	return errors.New("no match")
}

func TestReplaceKeyInPlace_Success(t *testing.T) {
	mc := &mockChanger{}
	oldKey := encryption.NewKey(1, []byte{0x01})
	newKey := encryption.NewKey(1, []byte{0x02})
	ctx := context.Background()
	if err := ReplaceKeyInPlace(ctx, mc, "/dev/fake", oldKey, newKey); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if !mc.setCalled || mc.old != oldKey || mc.new != newKey {
		t.Fatalf("SetKey not called with expected args")
	}
}

func TestReplaceKeyInPlace_Failure(t *testing.T) {
	mc := &mockChanger{fail: true}
	oldKey := encryption.NewKey(1, []byte{0x01})
	newKey := encryption.NewKey(1, []byte{0x02})
	ctx := context.Background()
	if err := ReplaceKeyInPlace(ctx, mc, "/dev/fake", oldKey, newKey); err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestAddNewAndRemoveOld_OrderAndRemoval(t *testing.T) {
	mo := &mockOperator{removeOnSlot: 5}
	newKey := encryption.NewKey(1, []byte{0x0a})
	auth := encryption.NewKey(1, []byte{0x0b})
	ctx := context.Background()
	if err := AddNewAndRemoveOld(ctx, mo, "/dev/fake", newKey, auth); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if !mo.addCalled {
		t.Fatalf("AddKey should be called before removal")
	}
	if len(mo.removeCalls) == 0 || mo.removeCalls[len(mo.removeCalls)-1] != 5 {
		t.Fatalf("expected removal to succeed on slot 5, calls=%v", mo.removeCalls)
	}
}

func TestAddNewAndRemoveOld_NoRemovalMatch(t *testing.T) {
	mo := &mockOperator{removeOnSlot: -1}
	newKey := encryption.NewKey(1, []byte{0x0a})
	auth := encryption.NewKey(1, []byte{0x0b})
	ctx := context.Background()
	if err := AddNewAndRemoveOld(ctx, mo, "/dev/fake", newKey, auth); err == nil {
		t.Fatalf("expected error, got nil")
	}
}
