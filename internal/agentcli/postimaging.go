package agentcli

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/term"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/siderolabs/go-blockdevice/v2/encryption"
	"github.com/siderolabs/go-blockdevice/v2/encryption/luks"

	"rootseal/internal/agent"
	"rootseal/internal/tpm2"
	"rootseal/pkg/api"
)

// HandlePostImaging runs the post-imaging workflow
func HandlePostImaging(args []string) error {
	fs := flag.NewFlagSet("postimaging", flag.ExitOnError)
	device := fs.String("device", "", "Path to the LUKS device (required)")
	currentPassword := fs.String("current-password", "", "Current LUKS password ('-' to prompt)")
	serverAddr := fs.String("server", "", "Control plane server address (host:port)")
	noKillOld := fs.Bool("no-kill-old", false, "Do not remove the old key slot after adding the new one")
	replaceInPlace := fs.Bool("replace-in-place", false, "Replace the old passphrase in-place (luksChangeKey) instead of add+remove")
	compatLuks2crypt := fs.Bool("compat-luks2crypt", false, "Also write legacy cache file at /etc/luks2crypt/crypt_recovery_key.json")
	enrollTPM := fs.Bool("tpm", false, "Enroll TPM for attestation-based unlock")
	akBlobPath := fs.String("ak-blob", "/etc/rootseal/ak.blob", "Path to save AK blob for TPM attestation")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed parsing flags: %w", err)
	}

	if *device == "" || *currentPassword == "" || *serverAddr == "" {
		fs.Usage()
		return errors.New("missing required flags for postimaging command")
	}

	log.Println("--- Running Post-Imaging Workflow ---")

	// 1. Gather system info
	log.Println("1. Gathering system info...")
	sysInfo, err := GatherSystemInfo(*device)
	if err != nil {
		return fmt.Errorf("failed to gather system info: %w", err)
	}
	log.Printf("  - Hostname: %s, Username: %s, Serial: %s", sysInfo.Hostname, sysInfo.Username, sysInfo.Serial)

	// 2. Obtain current passphrase
	log.Println("2. Obtaining and verifying current passphrase...")
	var currentPass []byte
	if *currentPassword == "-" {
		fmt.Fprint(os.Stderr, "Enter current LUKS password: ")
		pass, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Fprintln(os.Stderr)
		currentPass = pass
	} else {
		currentPass = []byte(*currentPassword)
	}
	defer SecureZero(currentPass)

	log.Println("  - Verifying passphrase...")
	luksDev := luks.New(luks.AESXTSPlain64Cipher)
	key := encryption.NewKey(encryption.AnyKeyslot, currentPass)

	luksCtx, luksCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer luksCancel()

	valid, err := luksDev.CheckKey(luksCtx, *device, key)
	if err != nil {
		return fmt.Errorf("failed to check key: %w", err)
	}
	if !valid {
		return errors.New("invalid LUKS passphrase")
	}
	log.Println("  - Passphrase verified.")

	// 3. Generate new recovery key
	log.Println("3. Generating new recovery key...")
	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		return fmt.Errorf("failed to generate new key: %w", err)
	}
	defer SecureZero(newKey)

	// 4. Escrow key to control plane
	log.Println("4. Escrowing key to control plane...")

	conn, err := grpc.NewClient(*serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()
	c := api.NewAgentServiceClient(conn)

	// Optionally enroll TPM for attestation-based unlock
	var tpmEnrollment *api.TPMEnrollment
	if *enrollTPM {
		log.Println("  - Enrolling TPM for attestation...")
		attestor, err := tpm2.NewAttestor()
		if err != nil {
			return fmt.Errorf("failed to open TPM: %w", err)
		}
		defer attestor.Close()

		if err := attestor.CreateAK(); err != nil {
			return fmt.Errorf("failed to create AK: %w", err)
		}

		tpmEnrollment, err = attestor.GetEnrollment()
		if err != nil {
			return fmt.Errorf("failed to get TPM enrollment: %w", err)
		}

		akBlob, err := attestor.MarshalAK()
		if err != nil {
			return fmt.Errorf("failed to marshal AK: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(*akBlobPath), 0700); err != nil {
			return fmt.Errorf("failed to create directory for AK blob: %w", err)
		}
		if err := os.WriteFile(*akBlobPath, akBlob, 0600); err != nil {
			return fmt.Errorf("failed to write AK blob: %w", err)
		}
		log.Printf("  - TPM AK saved to %s", *akBlobPath)
	}

	// Call PostImaging RPC
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	postImagingRes, err := c.PostImaging(ctx, &api.PostImagingRequest{
		DevicePath:      *device,
		Hostname:        sysInfo.Hostname,
		Username:        sysInfo.Username,
		Serial:          sysInfo.Serial,
		CurrentPassword: currentPass,
		NewRecoveryKey:  newKey,
		Labels:          sysInfo.Labels,
		TpmEnrollment:   tpmEnrollment,
	})
	if err != nil {
		return fmt.Errorf("PostImaging RPC failed: %w", err)
	}
	log.Printf("  - Escrowed key for volume UUID: %s (version %d)", postImagingRes.GetVolume().GetUuid(), postImagingRes.GetVersion().GetValue())
	if *enrollTPM {
		log.Println("  - TPM enrollment sent to server")
	}

	// Make copies of keys for LUKS operations (original slices will be zeroed on return)
	newKeyCopy := make([]byte, len(newKey))
	copy(newKeyCopy, newKey)
	authKeyCopy := make([]byte, len(currentPass))
	copy(authKeyCopy, currentPass)
	newKeyObj := encryption.NewKey(1, newKeyCopy)
	authKey := encryption.NewKey(encryption.AnyKeyslot, authKeyCopy)

	// Create fresh context for LUKS key operations
	luksKeyCtx, luksKeyCancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer luksKeyCancel()

	if *replaceInPlace {
		log.Println("5. Replacing old key in-place (luksChangeKey)...")
		if err := agent.ReplaceKeyInPlace(luksKeyCtx, luksDev, *device, authKey, newKeyObj); err != nil {
			return err
		}
		log.Println("  - Old key replaced in-place.")
	} else {
		if *noKillOld {
			log.Println("5. Installing new key into LUKS slot...")
			if err := luksDev.AddKey(luksKeyCtx, *device, authKey, newKeyObj); err != nil {
				return fmt.Errorf("failed to add new key to LUKS device: %w", err)
			}
			log.Println("  - New recovery key added.")
			log.Println("6. Skipping old key slot removal (--no-kill-old)")
		} else {
			log.Println("5-6. Installing new key and removing old...")
			if err := agent.AddNewAndRemoveOld(luksKeyCtx, luksDev, *device, newKeyObj, authKey, nil); err != nil {
				return err
			}
			log.Println("  - New recovery key added and old removed.")
		}
	}

	// 7. Write LUKS token to device header (stores server/UUID for unlock)
	log.Println("7. Writing rootseal token to LUKS header...")
	rootsealToken := &RootsealToken{
		Type:       "rootseal",
		Keyslots:   []string{},
		VolumeUUID: postImagingRes.GetVolume().GetUuid(),
		Server:     *serverAddr,
		KeyVersion: int(postImagingRes.GetVersion().GetValue()),
	}

	tokenCtx, tokenCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer tokenCancel()

	if err := luksDev.SetToken(tokenCtx, *device, encryption.AnyKeyslot, rootsealToken); err != nil {
		return fmt.Errorf("failed to write LUKS token: %w", err)
	}
	log.Printf("  - Token written to LUKS header (server: %s, volume: %s)", *serverAddr, postImagingRes.GetVolume().GetUuid())

	// 8. Write legacy compat files if requested
	if *compatLuks2crypt {
		log.Println("8. Writing legacy cache files...")
		cache := struct {
			Schema            string            `json:"schema"`
			Hostname          string            `json:"hostname"`
			Serial            string            `json:"serial"`
			VolumeUUID        string            `json:"volume_uuid"`
			DevicePath        string            `json:"device_path"`
			KeyVersion        int32             `json:"key_version"`
			CreatedAt         string            `json:"created_at"`
			RecoveryKeyB64URL string            `json:"recovery_key_b64url"`
			CryptorAPI        string            `json:"rootseal_api"`
			Annotations       map[string]string `json:"annotations"`
		}{
			Schema:            "rootseal.v1",
			Hostname:          sysInfo.Hostname,
			Serial:            sysInfo.Serial,
			VolumeUUID:        postImagingRes.GetVolume().GetUuid(),
			DevicePath:        *device,
			KeyVersion:        postImagingRes.GetVersion().GetValue(),
			CreatedAt:         time.Now().UTC().Format(time.RFC3339),
			RecoveryKeyB64URL: base64.RawURLEncoding.EncodeToString(newKey),
			CryptorAPI:        "https://" + *serverAddr,
			Annotations: map[string]string{
				"source": "postimaging",
			},
		}
		if err := WriteJSON0600("/etc/luks2crypt", "crypt_recovery_key.json", cache); err != nil {
			return fmt.Errorf("failed to write compat cache: %w", err)
		}
	}

	log.Println("9. Reporting success to control plane...")
	log.Println("--- Post-Imaging Workflow Complete ---")

	return nil
}
