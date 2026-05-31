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

	// Unseal the key using the same PCR binding that was used during sealing.
	// If the token has no seal_pcrs field (legacy enrollment), fall back to nil.
	key, err := attestor.Unseal(sealedKey, token.SealPCRs)
	if err != nil {
		return fmt.Errorf("failed to unseal key: %w", err)
	}
	// Minimize the key's lifetime in memory: wipe it as soon as we are done.
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	if *keyOnly {
		// Output the raw key bytes only, for piping directly into cryptsetup's
		// stdin. The key is never rendered to a terminal or formatted into a
		// log line.
		_, _ = os.Stdout.Write(key)
	} else {
		// Never print the unsealed key. Report success only; use --key-only to
		// pipe the raw key to cryptsetup.
		fmt.Printf("Successfully unsealed key for volume %s\n", token.VolumeUUID)
		fmt.Fprintln(os.Stderr, "key not printed; re-run with --key-only to pipe the raw key to cryptsetup")
	}

	return nil
}
