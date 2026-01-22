package agentcli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/siderolabs/go-blockdevice/v2/encryption"
	"github.com/siderolabs/go-blockdevice/v2/encryption/luks"

	"rootseal/internal/tpm2"
	"rootseal/pkg/api"
)

// HandleUnlock unlocks a LUKS device using a key from the control plane
func HandleUnlock(args []string) error {
	fs := flag.NewFlagSet("unlock", flag.ExitOnError)
	device := fs.String("device", "", "Path to the LUKS device (required)")
	serverAddr := fs.String("server", "", "Control plane server address (host:port)")
	volumeUUID := fs.String("volume-uuid", "", "Volume UUID (reads from LUKS token if not provided)")
	name := fs.String("name", "", "Name for the unlocked device (default: luks-<device>)")
	timeout := fs.Int("timeout", 30, "Timeout in seconds for server connection")
	keyOnly := fs.Bool("key-only", false, "Only output the key to stdout (for use with rootseal --key-file=-)")
	useTPM := fs.Bool("tpm", false, "Use TPM attestation for authentication")
	akBlobPath := fs.String("ak-blob", "/etc/rootseal/ak.blob", "Path to stored AK blob for TPM attestation")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed parsing flags: %w", err)
	}

	if *device == "" {
		fs.Usage()
		return errors.New("missing required flags for unlock command")
	}

	// If volume UUID not provided, read from LUKS token
	if *volumeUUID == "" || *serverAddr == "" {
		token, err := ReadRootsealToken(*device)
		if err != nil {
			return fmt.Errorf("failed to read rootseal token from LUKS header: %w", err)
		}
		if *volumeUUID == "" {
			*volumeUUID = token.VolumeUUID
		}
		if *serverAddr == "" {
			*serverAddr = token.Server
		}
	}

	if *volumeUUID == "" || *serverAddr == "" {
		return errors.New("volume-uuid and server are required (provide via flags or LUKS token)")
	}

	hostname, _ := os.Hostname()

	log.Printf("Unlocking %s (volume: %s) via %s", *device, *volumeUUID, *serverAddr)

	// Connect to control plane
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeout)*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(*serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	client := api.NewLuksManagerClient(conn)

	// Request the key - either with TPM attestation or without
	var resp *api.KeyResponse
	if *useTPM {
		resp, err = getKeyWithTPMAttestation(ctx, client, *volumeUUID, *akBlobPath)
		if err != nil {
			return fmt.Errorf("TPM-attested key retrieval failed: %w", err)
		}
	} else {
		resp, err = client.GetKey(ctx, &api.KeyRequest{
			VolumeUuid: *volumeUUID,
			Hostname:   hostname,
			Version:    0, // Latest
		})
		if err != nil {
			return fmt.Errorf("failed to get key from server: %w", err)
		}
	}

	log.Printf("Retrieved key (version %d)", resp.GetKeyVersion())

	recoveryKey := resp.GetWrappedKey()

	if *keyOnly {
		os.Stdout.Write(recoveryKey)
		return nil
	}

	// Determine device mapper name
	dmName := *name
	if dmName == "" {
		dmName = "luks-" + filepath.Base(*device)
	}

	// Unlock the device
	luksDev := luks.New(luks.AESXTSPlain64Cipher)
	key := encryption.NewKey(encryption.AnyKeyslot, recoveryKey)

	mappedPath, err := luksDev.Open(ctx, *device, dmName, key)
	if err != nil {
		return fmt.Errorf("failed to unlock device: %w", err)
	}

	log.Printf("Successfully unlocked %s as %s", *device, mappedPath)
	return nil
}

// getKeyWithTPMAttestation retrieves the key using TPM attestation
func getKeyWithTPMAttestation(ctx context.Context, client api.LuksManagerClient, volumeUUID, akBlobPath string) (*api.KeyResponse, error) {
	log.Println("Using TPM attestation for key retrieval")

	akBlob, err := os.ReadFile(akBlobPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read AK blob from %s: %w", akBlobPath, err)
	}

	attestor, err := tpm2.NewAttestor()
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM: %w", err)
	}
	defer attestor.Close()

	if err := attestor.LoadAK(akBlob); err != nil {
		return nil, fmt.Errorf("failed to load AK: %w", err)
	}

	log.Println("  - Requesting nonce from server...")
	nonceResp, err := client.GetNonce(ctx, &api.NonceRequest{
		VolumeUuid: volumeUUID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get nonce: %w", err)
	}

	log.Println("  - Generating TPM quote...")
	quote, err := attestor.GenerateQuote(nonceResp.GetNonce(), tpm2.DefaultRequiredPCRs)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TPM quote: %w", err)
	}

	akPublic, err := attestor.GetAKPublic()
	if err != nil {
		return nil, fmt.Errorf("failed to get AK public: %w", err)
	}

	log.Println("  - Requesting key with TPM attestation...")
	resp, err := client.GetKeyWithAttestation(ctx, &api.AttestationKeyRequest{
		VolumeUuid: volumeUUID,
		Nonce:      nonceResp.GetNonce(),
		Quote:      quote,
		AkPublic:   akPublic,
	})
	if err != nil {
		return nil, fmt.Errorf("attested key request failed: %w", err)
	}

	log.Println("  - TPM attestation successful")
	return resp, nil
}
