// Package fortanix provides a Fortanix SDKMS provider
package fortanix

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"rootseal/internal/kms"
)

func init() {
	kms.RegisterProvider("fortanix-sdkms", func(cfg *kms.Config) (kms.Provider, error) {
		return NewProvider(cfg)
	})
}

// Provider implements kms.Provider using Fortanix SDKMS
type Provider struct {
	endpoint string
	apiKey   string
	keyID    string
	client   *http.Client
}

// NewProvider creates a new Fortanix SDKMS provider
func NewProvider(cfg *kms.Config) (kms.Provider, error) {
	if cfg.Fortanix == nil {
		return nil, fmt.Errorf("fortanix configuration is required")
	}

	return &Provider{
		endpoint: cfg.Fortanix.Endpoint,
		apiKey:   cfg.Fortanix.APIKey,
		keyID:    cfg.Fortanix.KeyID,
		client:   &http.Client{},
	}, nil
}

// Name returns the provider name
func (p *Provider) Name() string {
	return "fortanix-sdkms"
}

// encryptRequest is the request body for Fortanix encrypt
type encryptRequest struct {
	Key   string `json:"key"`
	Alg   string `json:"alg"`
	Plain []byte `json:"plain"`
	Mode  string `json:"mode,omitempty"`
}

// encryptResponse is the response from Fortanix encrypt
type encryptResponse struct {
	Kid        string `json:"kid"`
	Cipher     []byte `json:"cipher"`
	Iv         []byte `json:"iv,omitempty"`
	Tag        []byte `json:"tag,omitempty"`
	KeyVersion int    `json:"key_version,omitempty"`
}

// decryptRequest is the request body for Fortanix decrypt
type decryptRequest struct {
	Key    string `json:"key"`
	Alg    string `json:"alg"`
	Cipher []byte `json:"cipher"`
	Iv     []byte `json:"iv,omitempty"`
	Tag    []byte `json:"tag,omitempty"`
	Mode   string `json:"mode,omitempty"`
}

// decryptResponse is the response from Fortanix decrypt
type decryptResponse struct {
	Plain []byte `json:"plain"`
}

// WrapKey encrypts a key using Fortanix SDKMS
func (p *Provider) WrapKey(ctx context.Context, plaintext []byte) (*kms.WrapResult, error) {
	reqBody := encryptRequest{
		Key:   p.keyID,
		Alg:   "AES",
		Plain: plaintext,
		Mode:  "GCM",
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", p.endpoint+"/crypto/v1/encrypt", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fortanix encrypt request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("fortanix encrypt failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var encResp encryptResponse
	if err := json.NewDecoder(resp.Body).Decode(&encResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Combine cipher, iv, and tag for storage
	combined := append(encResp.Iv, encResp.Cipher...)
	combined = append(combined, encResp.Tag...)

	return &kms.WrapResult{
		Ciphertext: combined,
		KeyID:      encResp.Kid,
		KeyVersion: encResp.KeyVersion,
		Algorithm:  "AES-GCM",
		Provider:   "fortanix-sdkms",
		Extra: map[string]string{
			"iv_len":  fmt.Sprintf("%d", len(encResp.Iv)),
			"tag_len": fmt.Sprintf("%d", len(encResp.Tag)),
		},
	}, nil
}

// UnwrapKey decrypts a key using Fortanix SDKMS
func (p *Provider) UnwrapKey(ctx context.Context, wrapped *kms.WrappedKey) ([]byte, error) {
	// Parse iv_len and tag_len from extra
	ivLen := 12  // default GCM IV length
	tagLen := 16 // default GCM tag length

	if v, ok := wrapped.Extra["iv_len"]; ok {
		fmt.Sscanf(v, "%d", &ivLen)
	}
	if v, ok := wrapped.Extra["tag_len"]; ok {
		fmt.Sscanf(v, "%d", &tagLen)
	}

	// Split combined ciphertext
	data := wrapped.Ciphertext
	if len(data) < ivLen+tagLen {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := data[:ivLen]
	cipher := data[ivLen : len(data)-tagLen]
	tag := data[len(data)-tagLen:]

	reqBody := decryptRequest{
		Key:    p.keyID,
		Alg:    "AES",
		Cipher: cipher,
		Iv:     iv,
		Tag:    tag,
		Mode:   "GCM",
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", p.endpoint+"/crypto/v1/decrypt", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fortanix decrypt request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("fortanix decrypt failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var decResp decryptResponse
	if err := json.NewDecoder(resp.Body).Decode(&decResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return decResp.Plain, nil
}

// GenerateDataKey generates a new data key and wraps it
func (p *Provider) GenerateDataKey(ctx context.Context, keySize int) (*kms.DataKey, error) {
	// Fortanix doesn't have native GenerateDataKey for symmetric keys
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
