package kms

import (
	"context"
	"errors"
	"testing"
)

// stubProvider is a minimal Provider for testing the registry.
type stubProvider struct{ name string }

func (s *stubProvider) Name() string                                          { return s.name }
func (s *stubProvider) WrapKey(_ context.Context, _ []byte) (*WrapResult, error) { return nil, nil }
func (s *stubProvider) UnwrapKey(_ context.Context, _ *WrappedKey) ([]byte, error) { return nil, nil }
func (s *stubProvider) GenerateDataKey(_ context.Context, _ int) (*DataKey, error) { return nil, nil }
func (s *stubProvider) Close() error                                          { return nil }

func TestNewProvider_NilConfig(t *testing.T) {
	_, err := NewProvider(nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestNewProvider_Unknown(t *testing.T) {
	_, err := NewProvider(&Config{Provider: "does-not-exist"})
	if !errors.Is(err, ErrProviderNotFound) {
		t.Errorf("expected ErrProviderNotFound, got %v", err)
	}
}

func TestRegisterAndRoute(t *testing.T) {
	const name = "test-stub"
	called := false

	RegisterProvider(name, func(cfg *Config) (Provider, error) {
		called = true
		return &stubProvider{name: name}, nil
	})

	p, err := NewProvider(&Config{Provider: name})
	if err != nil {
		t.Fatalf("NewProvider error: %v", err)
	}
	if !called {
		t.Error("factory was not called")
	}
	if p.Name() != name {
		t.Errorf("provider name: got %q want %q", p.Name(), name)
	}
}

func TestRegisterAndRoute_FactoryError(t *testing.T) {
	const name = "test-error"
	RegisterProvider(name, func(_ *Config) (Provider, error) {
		return nil, errors.New("init failed")
	})

	_, err := NewProvider(&Config{Provider: name})
	if err == nil {
		t.Fatal("expected error from factory")
	}
}
