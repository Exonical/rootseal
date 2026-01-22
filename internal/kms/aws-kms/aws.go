// Package awskms provides an AWS KMS provider
package awskms

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	rootsealkms "rootseal/internal/kms"
)

// Provider implements kms.Provider using AWS KMS
type Provider struct {
	client *kms.Client
	keyID  string
}

// NewProvider creates a new AWS KMS provider
func NewProvider(cfg *rootsealkms.Config) (rootsealkms.Provider, error) {
	if cfg.AWS == nil {
		return nil, fmt.Errorf("aws configuration is required")
	}

	var opts []func(*config.LoadOptions) error

	// Set region
	if cfg.AWS.Region != "" {
		opts = append(opts, config.WithRegion(cfg.AWS.Region))
	}

	// Set explicit credentials if provided
	if cfg.AWS.AccessKeyID != "" && cfg.AWS.SecretAccessKey != "" {
		creds := credentials.NewStaticCredentialsProvider(
			cfg.AWS.AccessKeyID,
			cfg.AWS.SecretAccessKey,
			cfg.AWS.SessionToken,
		)
		opts = append(opts, config.WithCredentialsProvider(creds))
	}

	awsCfg, err := config.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create KMS client with optional endpoint override
	var kmsOpts []func(*kms.Options)
	if cfg.AWS.Endpoint != "" {
		kmsOpts = append(kmsOpts, func(o *kms.Options) {
			o.BaseEndpoint = aws.String(cfg.AWS.Endpoint)
		})
	}

	client := kms.NewFromConfig(awsCfg, kmsOpts...)

	return &Provider{
		client: client,
		keyID:  cfg.AWS.KeyID,
	}, nil
}

// Name returns the provider name
func (p *Provider) Name() string {
	return "aws-kms"
}

// WrapKey encrypts a key using AWS KMS
func (p *Provider) WrapKey(ctx context.Context, plaintext []byte) (*rootsealkms.WrapResult, error) {
	input := &kms.EncryptInput{
		KeyId:               aws.String(p.keyID),
		Plaintext:           plaintext,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
	}

	resp, err := p.client.Encrypt(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("aws kms encrypt failed: %w", err)
	}

	return &rootsealkms.WrapResult{
		Ciphertext: resp.CiphertextBlob,
		KeyID:      aws.ToString(resp.KeyId),
		KeyVersion: 0, // AWS KMS doesn't expose version in encrypt response
		Algorithm:  string(resp.EncryptionAlgorithm),
		Provider:   "aws-kms",
		Extra:      map[string]string{},
	}, nil
}

// UnwrapKey decrypts a key using AWS KMS
func (p *Provider) UnwrapKey(ctx context.Context, wrapped *rootsealkms.WrappedKey) ([]byte, error) {
	input := &kms.DecryptInput{
		CiphertextBlob:      wrapped.Ciphertext,
		KeyId:               aws.String(p.keyID),
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
	}

	resp, err := p.client.Decrypt(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("aws kms decrypt failed: %w", err)
	}

	return resp.Plaintext, nil
}

// GenerateDataKey generates a new data key using AWS KMS
func (p *Provider) GenerateDataKey(ctx context.Context, keySize int) (*rootsealkms.DataKey, error) {
	var keySpec types.DataKeySpec
	switch keySize {
	case 16:
		keySpec = types.DataKeySpecAes128
	case 32:
		keySpec = types.DataKeySpecAes256
	default:
		return nil, fmt.Errorf("unsupported key size: %d (use 16 or 32)", keySize)
	}

	input := &kms.GenerateDataKeyInput{
		KeyId:   aws.String(p.keyID),
		KeySpec: keySpec,
	}

	resp, err := p.client.GenerateDataKey(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("aws kms generate data key failed: %w", err)
	}

	return &rootsealkms.DataKey{
		Plaintext: resp.Plaintext,
		Wrapped: &rootsealkms.WrapResult{
			Ciphertext: resp.CiphertextBlob,
			KeyID:      aws.ToString(resp.KeyId),
			KeyVersion: 0,
			Algorithm:  "AES_256",
			Provider:   "aws-kms",
			Extra:      map[string]string{},
		},
	}, nil
}

// Close releases resources
func (p *Provider) Close() error {
	return nil
}
