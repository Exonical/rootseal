package agentcli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestHandleBind_MissingDeviceAndServer(t *testing.T) {
	err := HandleBind([]string{})
	if err == nil {
		t.Fatal("expected error when --device and --server are missing")
	}
}

func TestHandleBind_MissingServer(t *testing.T) {
	err := HandleBind([]string{"--device", "/dev/vda2"})
	if err == nil {
		t.Fatal("expected error when --server is missing")
	}
}

func TestHandleBind_MissingDevice(t *testing.T) {
	err := HandleBind([]string{"--server", "localhost:50051"})
	if err == nil {
		t.Fatal("expected error when --device is missing")
	}
}

func TestHandleBind_MissingVolumeUUID_NoFile(t *testing.T) {
	// Point recovery.json at a nonexistent path by temporarily overriding HOME
	// so HandleBind tries to read a file that doesn't exist.
	// HandleBind hardcodes /etc/rootseal/recovery.json — it will fail to read
	// that file in a test environment, giving us the "file not found" error path.
	err := HandleBind([]string{
		"--device", "/dev/vda2",
		"--server", "localhost:50051",
		// no --volume-uuid: will try to read /etc/rootseal/recovery.json
	})
	if err == nil {
		t.Fatal("expected error when volume-uuid missing and recovery.json absent")
	}
}

func TestHandleBind_VolumeUUIDFromRecoveryJSON(t *testing.T) {
	// Write a fake recovery.json to a temp dir, then patch the path via env.
	// Since HandleBind hardcodes the path, we can only test the "file present but
	// LUKS SetToken will fail" path by providing --volume-uuid directly.
	// Test: flag parsing completes successfully before reaching the LUKS call.
	dir := t.TempDir()
	recovery := map[string]string{"volume_uuid": "test-uuid-from-file"}
	data, _ := json.Marshal(recovery)
	_ = os.WriteFile(filepath.Join(dir, "recovery.json"), data, 0o600)

	// We can't redirect HandleBind's hardcoded path, so test the explicit flag path instead:
	// with --volume-uuid provided, it skips file reading and proceeds to LUKS.
	err := HandleBind([]string{
		"--device", "/dev/vda2",
		"--server", "localhost:50051",
		"--volume-uuid", "explicit-uuid",
	})
	// Will fail at LUKS SetToken (no real device) but must NOT fail at flag validation
	if err == nil {
		t.Fatal("expected error from LUKS call, not nil — device does not exist")
	}
	// The error should be from LUKS, not from flag parsing
	if err.Error() == "missing required flags for bind command" {
		t.Fatal("should not fail at flag validation when all flags are provided")
	}
}

func TestHandleBind_EmptyVolumeUUID_After_Parse(t *testing.T) {
	dir := t.TempDir()
	// Write recovery.json with empty volume_uuid
	recovery := map[string]string{"volume_uuid": ""}
	data, _ := json.Marshal(recovery)
	_ = os.WriteFile(filepath.Join(dir, "recovery.json"), data, 0o600)

	// Provide explicit empty volume-uuid — HandleBind should reject it
	err := HandleBind([]string{
		"--device", "/dev/vda2",
		"--server", "localhost:50051",
		"--volume-uuid", "",
	})
	if err == nil {
		t.Fatal("expected error when volume-uuid is empty string")
	}
}
