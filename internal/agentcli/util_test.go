package agentcli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSecureZero(t *testing.T) {
	s := []byte{0x01, 0x02, 0x03, 0xFF}
	SecureZero(s)
	for i, b := range s {
		if b != 0 {
			t.Errorf("byte[%d] = %d, want 0", i, b)
		}
	}
}

func TestSecureZero_Empty(t *testing.T) {
	SecureZero(nil)
	SecureZero([]byte{})
}

func TestWriteJSON0600_Creates(t *testing.T) {
	dir := t.TempDir()
	payload := map[string]string{"key": "value"}

	if err := WriteJSON0600(dir, "out.json", payload); err != nil {
		t.Fatalf("WriteJSON0600 error: %v", err)
	}

	path := filepath.Join(dir, "out.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat error: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("permissions: got %o want 600", perm)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal error: %v", err)
	}
	if got["key"] != "value" {
		t.Errorf("json content: got %v want key=value", got)
	}
}

func TestWriteJSON0600_MkdirAll(t *testing.T) {
	base := t.TempDir()
	nested := filepath.Join(base, "a", "b", "c")

	if err := WriteJSON0600(nested, "f.json", struct{}{}); err != nil {
		t.Fatalf("WriteJSON0600 error with nested dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(nested, "f.json")); err != nil {
		t.Errorf("file not created: %v", err)
	}
}
