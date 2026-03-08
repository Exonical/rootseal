package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	vaultclient "github.com/hashicorp/vault-client-go"

	"rootseal/internal/kms"
)

// newTestProvider creates a Provider backed by a fake httptest.Server.
// The handler func is called for every request to the fake Vault.
func newTestProvider(t *testing.T, handler http.HandlerFunc) (*Provider, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	client, err := vaultclient.New(vaultclient.WithAddress(srv.URL))
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	p := NewProviderWithClient(client, "transit", "recovery-key")
	return p, srv
}

// vaultResponse builds a minimal Vault API v2 envelope.
func vaultResponse(data map[string]interface{}) []byte {
	b, _ := json.Marshal(map[string]interface{}{"data": data})
	return b
}

// --- Name / Close ---

func TestVaultProvider_Name(t *testing.T) {
	p := NewProviderWithClient(nil, "transit", "key")
	if p.Name() != "vault" {
		t.Errorf("Name: got %q want %q", p.Name(), "vault")
	}
}

func TestVaultProvider_Close(t *testing.T) {
	p := NewProviderWithClient(nil, "transit", "key")
	if err := p.Close(); err != nil {
		t.Errorf("Close: unexpected error: %v", err)
	}
}

// --- WrapKey ---

func TestVaultProvider_WrapKey_Success(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(vaultResponse(map[string]interface{}{
			"ciphertext":  "vault:v1:abc123",
			"key_version": float64(1),
		}))
	}
	p, srv := newTestProvider(t, handler)
	defer srv.Close()

	result, err := p.WrapKey(context.Background(), []byte("my-secret-key"))
	if err != nil {
		t.Fatalf("WrapKey error: %v", err)
	}
	if string(result.Ciphertext) != "vault:v1:abc123" {
		t.Errorf("Ciphertext: got %q want %q", result.Ciphertext, "vault:v1:abc123")
	}
	if result.KeyVersion != 1 {
		t.Errorf("KeyVersion: got %d want 1", result.KeyVersion)
	}
	if result.Provider != "vault" {
		t.Errorf("Provider: got %q want vault", result.Provider)
	}
}

func TestVaultProvider_WrapKey_ServerError(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"errors":["internal error"]}`))
	}
	p, srv := newTestProvider(t, handler)
	defer srv.Close()

	_, err := p.WrapKey(context.Background(), []byte("key"))
	if err == nil {
		t.Fatal("expected error on server 500")
	}
}

func TestVaultProvider_WrapKey_MissingCiphertext(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Response with no ciphertext field
		_, _ = w.Write(vaultResponse(map[string]interface{}{
			"key_version": float64(1),
		}))
	}
	p, srv := newTestProvider(t, handler)
	defer srv.Close()

	_, err := p.WrapKey(context.Background(), []byte("key"))
	if err == nil {
		t.Fatal("expected error when ciphertext absent")
	}
}

// --- UnwrapKey ---

func TestVaultProvider_UnwrapKey_Success(t *testing.T) {
	original := []byte("my-recovered-key")
	encoded := base64.StdEncoding.EncodeToString(original)

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(vaultResponse(map[string]interface{}{
			"plaintext": encoded,
		}))
	}
	p, srv := newTestProvider(t, handler)
	defer srv.Close()

	got, err := p.UnwrapKey(context.Background(), &kms.WrappedKey{
		Ciphertext: []byte("vault:v1:abc123"),
	})
	if err != nil {
		t.Fatalf("UnwrapKey error: %v", err)
	}
	if string(got) != string(original) {
		t.Errorf("plaintext: got %q want %q", got, original)
	}
}

func TestVaultProvider_UnwrapKey_ServerError(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
	}
	p, srv := newTestProvider(t, handler)
	defer srv.Close()

	_, err := p.UnwrapKey(context.Background(), &kms.WrappedKey{
		Ciphertext: []byte("vault:v1:abc"),
	})
	if err == nil {
		t.Fatal("expected error on server 403")
	}
}

func TestVaultProvider_UnwrapKey_MissingPlaintext(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(vaultResponse(map[string]interface{}{}))
	}
	p, srv := newTestProvider(t, handler)
	defer srv.Close()

	_, err := p.UnwrapKey(context.Background(), &kms.WrappedKey{
		Ciphertext: []byte("vault:v1:abc"),
	})
	if err == nil {
		t.Fatal("expected error when plaintext absent")
	}
}

// --- NewProvider config validation ---

func TestNewProvider_MissingVaultConfig(t *testing.T) {
	_, err := NewProvider(&kms.Config{Provider: "vault"})
	if err == nil {
		t.Fatal("expected error when vault config is nil")
	}
}
