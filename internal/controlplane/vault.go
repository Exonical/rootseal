package controlplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

// VaultService handles Vault operations
type VaultService struct {
	client      *vault.Client
	transitPath string
	keyName     string
	kvPath      string
}

// NewVaultService creates a new Vault service
func NewVaultService(client *vault.Client, transitPath, keyName, kvPath string) *VaultService {
	return &VaultService{
		client:      client,
		transitPath: transitPath,
		keyName:     keyName,
		kvPath:      kvPath,
	}
}

// EncryptResponse represents the response from Vault Transit encrypt
type EncryptResponse struct {
	Ciphertext string
	KeyVersion int
}

// WrapKey encrypts a key using Vault Transit
func (v *VaultService) WrapKey(ctx context.Context, plaintext []byte) (*EncryptResponse, error) {
	// Base64 encode the plaintext as required by Vault Transit
	encoded := base64.StdEncoding.EncodeToString(plaintext)

	req := schema.TransitEncryptRequest{
		Plaintext: encoded,
	}

	resp, err := v.client.Secrets.TransitEncrypt(ctx, v.keyName, req, vault.WithMountPath(v.transitPath))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key with Vault Transit: %w", err)
	}

	// Debug log the response data
	slog.Debug("vault transit encrypt response", "data", resp.Data)

	ciphertext, ok := resp.Data["ciphertext"].(string)
	if !ok {
		return nil, fmt.Errorf("ciphertext not found in response")
	}

	// Handle key_version which may come as float64, int, int32, int64, or json.Number
	var keyVersion int
	switch v := resp.Data["key_version"].(type) {
	case float64:
		keyVersion = int(v)
	case float32:
		keyVersion = int(v)
	case int:
		keyVersion = v
	case int32:
		keyVersion = int(v)
	case int64:
		keyVersion = int(v)
	case json.Number:
		i, err := v.Int64()
		if err != nil {
			return nil, fmt.Errorf("failed to parse key_version as int: %w", err)
		}
		keyVersion = int(i)
	case nil:
		// key_version not present, default to 1
		keyVersion = 1
	default:
		return nil, fmt.Errorf("key_version unexpected type %T (value: %v) in response", resp.Data["key_version"], resp.Data["key_version"])
	}

	return &EncryptResponse{
		Ciphertext: ciphertext,
		KeyVersion: keyVersion,
	}, nil
}

// UnwrapKey decrypts a key using Vault Transit
func (v *VaultService) UnwrapKey(ctx context.Context, ciphertext string) ([]byte, error) {
	req := schema.TransitDecryptRequest{
		Ciphertext: ciphertext,
	}

	resp, err := v.client.Secrets.TransitDecrypt(ctx, v.keyName, req, vault.WithMountPath(v.transitPath))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key with Vault Transit: %w", err)
	}

	// Base64 decode the plaintext
	plaintextStr, ok := resp.Data["plaintext"].(string)
	if !ok {
		return nil, fmt.Errorf("plaintext not found in response")
	}

	plaintext, err := base64.StdEncoding.DecodeString(plaintextStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode plaintext from Vault: %w", err)
	}

	return plaintext, nil
}

// StoreKeyMetadata stores key metadata in Vault KV
func (v *VaultService) StoreKeyMetadata(ctx context.Context, path string, metadata map[string]interface{}) error {
	req := schema.KvV2WriteRequest{
		Data: metadata,
	}

	_, err := v.client.Secrets.KvV2Write(ctx, path, req, vault.WithMountPath(v.kvPath))
	if err != nil {
		return fmt.Errorf("failed to store key metadata in Vault KV: %w", err)
	}

	return nil
}

// GetKeyMetadata retrieves key metadata from Vault KV
func (v *VaultService) GetKeyMetadata(ctx context.Context, path string) (map[string]interface{}, error) {
	resp, err := v.client.Secrets.KvV2Read(ctx, path, vault.WithMountPath(v.kvPath))
	if err != nil {
		return nil, fmt.Errorf("failed to read key metadata from Vault KV: %w", err)
	}

	return resp.Data.Data, nil
}
