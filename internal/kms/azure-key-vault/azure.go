// Package azurekeyvault provides an Azure Key Vault KMS provider
package azurekeyvault

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"rootseal/internal/kms"
)

func init() {
	kms.RegisterProvider("azure-keyvault", func(cfg *kms.Config) (kms.Provider, error) {
		return NewProvider(cfg)
	})
}

// Provider implements kms.Provider using Azure Key Vault
type Provider struct {
	client     *azkeys.Client
	keyName    string
	keyVersion string
}

// NewProvider creates a new Azure Key Vault provider
func NewProvider(cfg *kms.Config) (kms.Provider, error) {
	if cfg.Azure == nil {
		return nil, fmt.Errorf("azure configuration is required")
	}

	var cred *azidentity.DefaultAzureCredential
	var err error

	// Use default credential chain (env vars, managed identity, CLI, etc.)
	cred, err = azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create azure credential: %w", err)
	}

	client, err := azkeys.NewClient(cfg.Azure.VaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create azure keyvault client: %w", err)
	}

	return &Provider{
		client:     client,
		keyName:    cfg.Azure.KeyName,
		keyVersion: cfg.Azure.KeyVersion,
	}, nil
}

// Name returns the provider name
func (p *Provider) Name() string {
	return "azure-keyvault"
}

// WrapKey encrypts a key using Azure Key Vault
func (p *Provider) WrapKey(ctx context.Context, plaintext []byte) (*kms.WrapResult, error) {
	algorithm := azkeys.EncryptionAlgorithmRSAOAEP256

	params := azkeys.KeyOperationParameters{
		Algorithm: &algorithm,
		Value:     plaintext,
	}

	resp, err := p.client.WrapKey(ctx, p.keyName, p.keyVersion, params, nil)
	if err != nil {
		return nil, fmt.Errorf("azure keyvault wrap key failed: %w", err)
	}

	return &kms.WrapResult{
		Ciphertext: resp.Result,
		KeyID:      p.keyName,
		KeyVersion: 0,
		Algorithm:  string(algorithm),
		Provider:   "azure-keyvault",
		Extra: map[string]string{
			"key_version": p.keyVersion,
		},
	}, nil
}

// UnwrapKey decrypts a key using Azure Key Vault
func (p *Provider) UnwrapKey(ctx context.Context, wrapped *kms.WrappedKey) ([]byte, error) {
	algorithm := azkeys.EncryptionAlgorithmRSAOAEP256

	// Use key version from wrapped key if available
	keyVersion := p.keyVersion
	if v, ok := wrapped.Extra["key_version"]; ok && v != "" {
		keyVersion = v
	}

	params := azkeys.KeyOperationParameters{
		Algorithm: &algorithm,
		Value:     wrapped.Ciphertext,
	}

	resp, err := p.client.UnwrapKey(ctx, p.keyName, keyVersion, params, nil)
	if err != nil {
		return nil, fmt.Errorf("azure keyvault unwrap key failed: %w", err)
	}

	return resp.Result, nil
}

// GenerateDataKey generates a new data key and wraps it
func (p *Provider) GenerateDataKey(ctx context.Context, keySize int) (*kms.DataKey, error) {
	// Azure Key Vault doesn't have native GenerateDataKey
	// Generate locally and wrap
	plaintext := make([]byte, keySize)
	if _, err := rand.Read(plaintext); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	wrapped, err := p.WrapKey(ctx, plaintext)
	if err != nil {
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
