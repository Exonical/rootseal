package agentcli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/siderolabs/go-blockdevice/v2/encryption"
	"github.com/siderolabs/go-blockdevice/v2/encryption/luks"
)

// HandleBind binds a LUKS device to rootseal by writing a token to the LUKS header
func HandleBind(args []string) error {
	fs := flag.NewFlagSet("bind", flag.ExitOnError)
	device := fs.String("device", "", "Path to the LUKS device (required)")
	serverAddr := fs.String("server", "", "Control plane server address (host:port)")
	volumeUUID := fs.String("volume-uuid", "", "Volume UUID (from postimaging, or read from /etc/rootseal/recovery.json)")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed parsing flags: %w", err)
	}

	if *device == "" || *serverAddr == "" {
		fs.Usage()
		return errors.New("missing required flags for bind command")
	}

	// If volume UUID not provided, try to read from recovery.json
	if *volumeUUID == "" {
		data, err := os.ReadFile("/etc/rootseal/recovery.json")
		if err != nil {
			return fmt.Errorf("volume-uuid not provided and failed to read /etc/rootseal/recovery.json: %w", err)
		}
		var recovery struct {
			VolumeUUID string `json:"volume_uuid"`
		}
		if err := json.Unmarshal(data, &recovery); err != nil {
			return fmt.Errorf("failed to parse recovery.json: %w", err)
		}
		*volumeUUID = recovery.VolumeUUID
	}

	if *volumeUUID == "" {
		return errors.New("volume-uuid is required")
	}

	log.Printf("Binding LUKS device %s to rootseal (volume: %s, server: %s)", *device, *volumeUUID, *serverAddr)

	// Create the rootseal token with empty keyslots (token is not bound to specific keyslots)
	rootsealToken := &RootsealToken{
		Type:       "rootseal",
		Keyslots:   []string{},
		VolumeUUID: *volumeUUID,
		Server:     *serverAddr,
	}

	tokenJSON, _ := rootsealToken.Bytes()
	log.Printf("Token JSON: %s", string(tokenJSON))

	// Use go-blockdevice LUKS provider to set the token
	luksDev := luks.New(luks.AESXTSPlain64Cipher)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// SetToken with slot -1 means use next available slot
	if err := luksDev.SetToken(ctx, *device, encryption.AnyKeyslot, rootsealToken); err != nil {
		return fmt.Errorf("failed to set token in LUKS header: %w", err)
	}

	log.Printf("Successfully bound device %s for NBDE unlock", *device)
	return nil
}
