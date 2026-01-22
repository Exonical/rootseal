// Package kms provides a unified interface for key management services
package kms

import (
	"context"
	"fmt"
)

// Provider defines the interface for key management services
type Provider interface {
	// Name returns the provider name (e.g., "vault", "aws-kms", "azure-keyvault")
	Name() string

	// WrapKey encrypts a data encryption key (DEK) using the key encryption key (KEK)
	// Returns the wrapped key and metadata needed for unwrapping
	WrapKey(ctx context.Context, plaintext []byte) (*WrapResult, error)

	// UnwrapKey decrypts a wrapped data encryption key
	UnwrapKey(ctx context.Context, wrapped *WrappedKey) ([]byte, error)

	// GenerateDataKey generates a new data encryption key and returns both
	// the plaintext and wrapped versions (envelope encryption pattern)
	// keySize is in bytes (e.g., 32 for AES-256)
	GenerateDataKey(ctx context.Context, keySize int) (*DataKey, error)

	// Close releases any resources held by the provider
	Close() error
}

// WrapResult contains the result of a key wrap operation
type WrapResult struct {
	// Ciphertext is the wrapped key material
	Ciphertext []byte

	// KeyID identifies the KEK used for wrapping (provider-specific)
	KeyID string

	// KeyVersion is the version of the KEK used (if supported)
	KeyVersion int

	// Algorithm used for wrapping (e.g., "AES-256-GCM", "RSA-OAEP")
	Algorithm string

	// Provider name for deserialization
	Provider string

	// Extra contains provider-specific metadata
	Extra map[string]string
}

// WrappedKey represents a wrapped data encryption key with metadata
type WrappedKey struct {
	// Ciphertext is the wrapped key material
	Ciphertext []byte

	// KeyID identifies the KEK used for wrapping
	KeyID string

	// KeyVersion is the version of the KEK used
	KeyVersion int

	// Provider name
	Provider string

	// Extra contains provider-specific metadata needed for unwrapping
	Extra map[string]string
}

// DataKey contains both plaintext and wrapped versions of a data key
type DataKey struct {
	// Plaintext is the unencrypted data key (should be zeroed after use)
	Plaintext []byte

	// Wrapped contains the encrypted data key and metadata
	Wrapped *WrapResult
}

// Config holds common configuration for KMS providers
type Config struct {
	// Provider type: "vault", "aws-kms", "azure-keyvault", "fortanix-sdkms"
	Provider string `yaml:"provider" json:"provider"`

	// KeyID is the identifier for the key encryption key
	KeyID string `yaml:"key_id" json:"key_id"`

	// Region for cloud providers
	Region string `yaml:"region,omitempty" json:"region,omitempty"`

	// Endpoint override for testing or on-prem deployments
	Endpoint string `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`

	// Provider-specific configuration
	Vault    *VaultConfig    `yaml:"vault,omitempty" json:"vault,omitempty"`
	AWS      *AWSConfig      `yaml:"aws,omitempty" json:"aws,omitempty"`
	Azure    *AzureConfig    `yaml:"azure,omitempty" json:"azure,omitempty"`
	Fortanix *FortanixConfig `yaml:"fortanix,omitempty" json:"fortanix,omitempty"`
}

// VaultConfig holds HashiCorp Vault-specific configuration
type VaultConfig struct {
	Address     string `yaml:"address" json:"address"`
	Token       string `yaml:"token,omitempty" json:"token,omitempty"`
	TransitPath string `yaml:"transit_path" json:"transit_path"`
	KeyName     string `yaml:"key_name" json:"key_name"`
	Namespace   string `yaml:"namespace,omitempty" json:"namespace,omitempty"`
}

// AWSConfig holds AWS KMS-specific configuration
type AWSConfig struct {
	Region          string `yaml:"region" json:"region"`
	KeyID           string `yaml:"key_id" json:"key_id"`
	AccessKeyID     string `yaml:"access_key_id,omitempty" json:"access_key_id,omitempty"`
	SecretAccessKey string `yaml:"secret_access_key,omitempty" json:"secret_access_key,omitempty"`
	SessionToken    string `yaml:"session_token,omitempty" json:"session_token,omitempty"`
	RoleARN         string `yaml:"role_arn,omitempty" json:"role_arn,omitempty"`
	Endpoint        string `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
}

// AzureConfig holds Azure Key Vault-specific configuration
type AzureConfig struct {
	VaultURL     string `yaml:"vault_url" json:"vault_url"`
	KeyName      string `yaml:"key_name" json:"key_name"`
	KeyVersion   string `yaml:"key_version,omitempty" json:"key_version,omitempty"`
	TenantID     string `yaml:"tenant_id,omitempty" json:"tenant_id,omitempty"`
	ClientID     string `yaml:"client_id,omitempty" json:"client_id,omitempty"`
	ClientSecret string `yaml:"client_secret,omitempty" json:"client_secret,omitempty"`
}

// FortanixConfig holds Fortanix SDKMS-specific configuration
type FortanixConfig struct {
	Endpoint string `yaml:"endpoint" json:"endpoint"`
	APIKey   string `yaml:"api_key,omitempty" json:"api_key,omitempty"`
	KeyID    string `yaml:"key_id" json:"key_id"`
	GroupID  string `yaml:"group_id,omitempty" json:"group_id,omitempty"`
}

// ErrProviderNotFound is returned when a requested provider is not registered
var ErrProviderNotFound = fmt.Errorf("kms provider not found")

// ErrKeyNotFound is returned when a key cannot be found
var ErrKeyNotFound = fmt.Errorf("key not found")

// ErrUnwrapFailed is returned when key unwrapping fails
var ErrUnwrapFailed = fmt.Errorf("key unwrap failed")

// ProviderFactory is a function that creates a KMS provider from config
type ProviderFactory func(cfg *Config) (Provider, error)

// providerFactories holds registered provider factories
var providerFactories = make(map[string]ProviderFactory)

// RegisterProvider registers a provider factory
func RegisterProvider(name string, factory ProviderFactory) {
	providerFactories[name] = factory
}

// NewProvider creates a KMS provider based on configuration
func NewProvider(cfg *Config) (Provider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("kms config is nil")
	}

	factory, ok := providerFactories[cfg.Provider]
	if !ok {
		return nil, fmt.Errorf("%w: %s (available: vault, aws-kms, azure-keyvault, fortanix-sdkms)", ErrProviderNotFound, cfg.Provider)
	}

	return factory(cfg)
}
