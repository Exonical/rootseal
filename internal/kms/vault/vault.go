// Package vault provides a HashiCorp Vault KMS provider
package vault

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"

	"rootseal/internal/kms"
)

// Provider implements kms.Provider using HashiCorp Vault Transit
type Provider struct {
	client      *vault.Client
	transitPath string
	keyName     string
}

// NewProvider creates a new Vault KMS provider
func NewProvider(cfg *kms.Config) (kms.Provider, error) {
	if cfg.Vault == nil {
		return nil, fmt.Errorf("vault configuration is required")
	}

	client, err := vault.New(
		vault.WithAddress(cfg.Vault.Address),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	if cfg.Vault.Token != "" {
		if err := client.SetToken(cfg.Vault.Token); err != nil {
			return nil, fmt.Errorf("failed to set vault token: %w", err)
		}
	}

	if cfg.Vault.Namespace != "" {
		if err := client.SetNamespace(cfg.Vault.Namespace); err != nil {
			return nil, fmt.Errorf("failed to set vault namespace: %w", err)
		}
	}

	return &Provider{
		client:      client,
		transitPath: cfg.Vault.TransitPath,
		keyName:     cfg.Vault.KeyName,
	}, nil
}

// NewProviderWithClient creates a provider with an existing Vault client
func NewProviderWithClient(client *vault.Client, transitPath, keyName string) *Provider {
	return &Provider{
		client:      client,
		transitPath: transitPath,
		keyName:     keyName,
	}
}

// Name returns the provider name
func (p *Provider) Name() string {
	return "vault"
}

// WrapKey encrypts a key using Vault Transit
func (p *Provider) WrapKey(ctx context.Context, plaintext []byte) (*kms.WrapResult, error) {
	encoded := base64.StdEncoding.EncodeToString(plaintext)

	req := schema.TransitEncryptRequest{
		Plaintext: encoded,
	}

	resp, err := p.client.Secrets.TransitEncrypt(ctx, p.keyName, req, vault.WithMountPath(p.transitPath))
	if err != nil {
		return nil, fmt.Errorf("vault transit encrypt failed: %w", err)
	}

	ciphertext, ok := resp.Data["ciphertext"].(string)
	if !ok {
		return nil, fmt.Errorf("ciphertext not found in vault response")
	}

	keyVersion := parseKeyVersion(resp.Data["key_version"])

	return &kms.WrapResult{
		Ciphertext: []byte(ciphertext),
		KeyID:      p.keyName,
		KeyVersion: keyVersion,
		Algorithm:  "aes256-gcm96",
		Provider:   "vault",
		Extra: map[string]string{
			"transit_path": p.transitPath,
		},
	}, nil
}

// UnwrapKey decrypts a key using Vault Transit
func (p *Provider) UnwrapKey(ctx context.Context, wrapped *kms.WrappedKey) ([]byte, error) {
	req := schema.TransitDecryptRequest{
		Ciphertext: string(wrapped.Ciphertext),
	}

	resp, err := p.client.Secrets.TransitDecrypt(ctx, p.keyName, req, vault.WithMountPath(p.transitPath))
	if err != nil {
		return nil, fmt.Errorf("vault transit decrypt failed: %w", err)
	}

	plaintextStr, ok := resp.Data["plaintext"].(string)
	if !ok {
		return nil, fmt.Errorf("plaintext not found in vault response")
	}

	plaintext, err := base64.StdEncoding.DecodeString(plaintextStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode plaintext: %w", err)
	}

	return plaintext, nil
}

// GenerateDataKey generates a new data key and wraps it
func (p *Provider) GenerateDataKey(ctx context.Context, keySize int) (*kms.DataKey, error) {
	// Generate random key locally
	plaintext := make([]byte, keySize)
	if _, err := rand.Read(plaintext); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	// Wrap the key
	wrapped, err := p.WrapKey(ctx, plaintext)
	if err != nil {
		// Zero out plaintext on error
		for i := range plaintext {
			plaintext[i] = 0
		}
		return nil, err
	}

	return &kms.DataKey{
		Plaintext: plaintext,
		Wrapped:   wrapped,
	}, nil
}

// Close releases resources
func (p *Provider) Close() error {
	return nil
}

// parseKeyVersion extracts key version from various types
func parseKeyVersion(v interface{}) int {
	switch val := v.(type) {
	case float64:
		return int(val)
	case float32:
		return int(val)
	case int:
		return val
	case int32:
		return int(val)
	case int64:
		return int(val)
	case json.Number:
		i, _ := val.Int64()
		return int(i)
	default:
		return 1
	}
}
