package agentcli

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/siderolabs/go-blockdevice/v2/encryption/luks"
)

// RootsealToken represents the LUKS2 token metadata for rootseal NBDE
// Implements token.Token interface from go-blockdevice/v2/encryption/token
type RootsealToken struct {
	Type       string   `json:"type"`
	Keyslots   []string `json:"keyslots"`
	VolumeUUID string   `json:"volume_uuid"`
	Server     string   `json:"server"`
	KeyVersion int      `json:"key_version,omitempty"`
}

// Bytes implements token.Token interface
func (t *RootsealToken) Bytes() ([]byte, error) {
	return json.Marshal(t)
}

// Decode implements token.Token interface
func (t *RootsealToken) Decode(in []byte) error {
	return json.Unmarshal(in, t)
}

// ReadRootsealToken reads the rootseal token from a LUKS device header
func ReadRootsealToken(device string) (*RootsealToken, error) {
	luksDev := luks.New(luks.AESXTSPlain64Cipher)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Try reading tokens from slots 0-31
	for slot := 0; slot < 32; slot++ {
		token := &RootsealToken{}
		err := luksDev.ReadToken(ctx, device, slot, token)
		if err != nil {
			// Token not found at this slot, continue
			continue
		}
		if token.Type == "rootseal" {
			return token, nil
		}
	}

	return nil, errors.New("no rootseal token found in LUKS header")
}
