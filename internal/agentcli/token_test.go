package agentcli

import (
	"encoding/json"
	"testing"
)

func TestRootsealToken_RoundTrip(t *testing.T) {
	orig := &RootsealToken{
		Type:       "rootseal",
		Keyslots:   []string{"0"},
		VolumeUUID: "83581238-15ed-481f-b896-06e248dd1d23",
		Server:     "192.168.122.1:50051",
		KeyVersion: 7,
		SealedKey:  "abc123==",
	}

	b, err := orig.Bytes()
	if err != nil {
		t.Fatalf("Bytes() error: %v", err)
	}

	decoded := &RootsealToken{}
	if err := decoded.Decode(b); err != nil {
		t.Fatalf("Decode() error: %v", err)
	}

	if decoded.Type != orig.Type {
		t.Errorf("Type: got %q want %q", decoded.Type, orig.Type)
	}
	if decoded.VolumeUUID != orig.VolumeUUID {
		t.Errorf("VolumeUUID: got %q want %q", decoded.VolumeUUID, orig.VolumeUUID)
	}
	if decoded.Server != orig.Server {
		t.Errorf("Server: got %q want %q", decoded.Server, orig.Server)
	}
	if decoded.KeyVersion != orig.KeyVersion {
		t.Errorf("KeyVersion: got %d want %d", decoded.KeyVersion, orig.KeyVersion)
	}
	if decoded.SealedKey != orig.SealedKey {
		t.Errorf("SealedKey: got %q want %q", decoded.SealedKey, orig.SealedKey)
	}
}

func TestRootsealToken_MinimalFields(t *testing.T) {
	tok := &RootsealToken{
		Type:       "rootseal",
		VolumeUUID: "some-uuid",
		Server:     "host:50051",
	}

	b, err := tok.Bytes()
	if err != nil {
		t.Fatalf("Bytes() error: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json.Unmarshal error: %v", err)
	}

	if _, ok := m["sealed_key"]; ok {
		t.Error("sealed_key should be omitted when empty")
	}
	if _, ok := m["key_version"]; ok {
		t.Error("key_version should be omitted when zero")
	}
}

func TestRootsealToken_TypeField(t *testing.T) {
	tok := &RootsealToken{Type: "rootseal", VolumeUUID: "u", Server: "s"}
	b, err := tok.Bytes()
	if err != nil {
		t.Fatalf("Bytes() error: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json.Unmarshal error: %v", err)
	}
	if m["type"] != "rootseal" {
		t.Errorf("type field: got %v want %q", m["type"], "rootseal")
	}
}

func TestRootsealToken_DecodeGarbage(t *testing.T) {
	tok := &RootsealToken{}
	if err := tok.Decode([]byte("not json")); err == nil {
		t.Error("expected error decoding garbage JSON")
	}
}
