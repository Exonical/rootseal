package agentcli

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"rootseal/internal/tpm2"
)

// HandleUnseal handles the 'unseal' subcommand - decrypts TPM-sealed key from LUKS token
func HandleUnseal(args []string) error {
	fs := flag.NewFlagSet("unseal", flag.ExitOnError)
	device := fs.String("device", "", "LUKS device path (e.g., /dev/sda2)")
	keyOnly := fs.Bool("key-only", false, "Output only the raw key (for piping to cryptsetup)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *device == "" {
		return fmt.Errorf("--device is required")
	}

	// Read the rootseal token from LUKS header
	token, err := ReadRootsealToken(*device)
	if err != nil {
		return fmt.Errorf("failed to read rootseal token: %w", err)
	}

	if token.SealedKey == "" {
		return fmt.Errorf("no sealed key found in LUKS token - device may not be enrolled with TPM sealing")
	}

	// Decode the sealed key
	sealedKey, err := base64.StdEncoding.DecodeString(token.SealedKey)
	if err != nil {
		return fmt.Errorf("failed to decode sealed key: %w", err)
	}

	// Open TPM and unseal
	attestor, err := tpm2.NewAttestor()
	if err != nil {
		return fmt.Errorf("failed to open TPM: %w", err)
	}
	defer func() { _ = attestor.Close() }()

	// Unseal the key using TPM (no PCR binding)
	key, err := attestor.Unseal(sealedKey, nil)
	if err != nil {
		return fmt.Errorf("failed to unseal key: %w", err)
	}

	if *keyOnly {
		// Output raw key for piping
		_, _ = os.Stdout.Write(key)
	} else {
		fmt.Printf("Successfully unsealed key for volume %s\n", token.VolumeUUID)
		fmt.Printf("Key (hex): %x\n", key)
	}

	return nil
}
