package controlplane

import (
	"context"
	"encoding/json"
	"net"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"rootseal/pkg/api"
)

const bufSize = 1024 * 1024

// mockDB implements DBStore with configurable function fields.
type mockDB struct {
	getVolumeByUUID       func(ctx context.Context, volumeUUID string) (*Volume, error)
	getKeyVersion         func(ctx context.Context, volumeID uuid.UUID, version int) (*KeyVersion, error)
	createNonce           func(ctx context.Context, volumeID uuid.UUID, nonce []byte) error
	validateConsumeNonce  func(ctx context.Context, volumeID uuid.UUID, nonce []byte) error
	getTPMEnrollment      func(ctx context.Context, volumeID uuid.UUID) (*TPMEnrollment, error)
	upsertAgent           func(ctx context.Context, hostname, serial string, labels json.RawMessage) (*Agent, error)
	getVolumeByDevicePath func(ctx context.Context, agentID uuid.UUID, devicePath string) (*Volume, error)
	getLatestKeyVersion   func(ctx context.Context, volumeID uuid.UUID) (*KeyVersion, error)
	upsertVolume          func(ctx context.Context, agentID uuid.UUID, devicePath, volumeUUID string) (*Volume, error)
	createKeyVersion      func(ctx context.Context, volumeID uuid.UUID, version int, vaultKeyID, wrappedKey string) (*KeyVersion, error)
	createTPMEnrollment   func(ctx context.Context, volumeID uuid.UUID, ekPublic, ekCert, akPublic, akName []byte) (*TPMEnrollment, error)
}

func (m *mockDB) GetVolumeByUUID(ctx context.Context, v string) (*Volume, error) {
	return m.getVolumeByUUID(ctx, v)
}
func (m *mockDB) GetKeyVersion(ctx context.Context, id uuid.UUID, version int) (*KeyVersion, error) {
	return m.getKeyVersion(ctx, id, version)
}
func (m *mockDB) CreateNonce(ctx context.Context, id uuid.UUID, nonce []byte) error {
	return m.createNonce(ctx, id, nonce)
}
func (m *mockDB) ValidateAndConsumeNonce(ctx context.Context, id uuid.UUID, nonce []byte) error {
	return m.validateConsumeNonce(ctx, id, nonce)
}
func (m *mockDB) GetTPMEnrollment(ctx context.Context, id uuid.UUID) (*TPMEnrollment, error) {
	return m.getTPMEnrollment(ctx, id)
}
func (m *mockDB) UpsertAgent(ctx context.Context, hostname, serial string, labels json.RawMessage) (*Agent, error) {
	return m.upsertAgent(ctx, hostname, serial, labels)
}
func (m *mockDB) GetVolumeByDevicePath(ctx context.Context, agentID uuid.UUID, devicePath string) (*Volume, error) {
	return m.getVolumeByDevicePath(ctx, agentID, devicePath)
}
func (m *mockDB) GetLatestKeyVersion(ctx context.Context, id uuid.UUID) (*KeyVersion, error) {
	return m.getLatestKeyVersion(ctx, id)
}
func (m *mockDB) UpsertVolume(ctx context.Context, agentID uuid.UUID, devicePath, volumeUUID string) (*Volume, error) {
	return m.upsertVolume(ctx, agentID, devicePath, volumeUUID)
}
func (m *mockDB) CreateKeyVersion(ctx context.Context, id uuid.UUID, version int, vaultKeyID, wrappedKey string) (*KeyVersion, error) {
	return m.createKeyVersion(ctx, id, version, vaultKeyID, wrappedKey)
}
func (m *mockDB) CreateTPMEnrollment(ctx context.Context, id uuid.UUID, ekPublic, ekCert, akPublic, akName []byte) (*TPMEnrollment, error) {
	return m.createTPMEnrollment(ctx, id, ekPublic, ekCert, akPublic, akName)
}

// mockKeyStore implements KeyStore with configurable function fields.
type mockKeyStore struct {
	wrapKey          func(ctx context.Context, plaintext []byte) (*EncryptResponse, error)
	unwrapKey        func(ctx context.Context, ciphertext string) ([]byte, error)
	storeKeyMetadata func(ctx context.Context, path string, metadata map[string]interface{}) error
}

func (m *mockKeyStore) WrapKey(ctx context.Context, plaintext []byte) (*EncryptResponse, error) {
	return m.wrapKey(ctx, plaintext)
}
func (m *mockKeyStore) UnwrapKey(ctx context.Context, ciphertext string) ([]byte, error) {
	return m.unwrapKey(ctx, ciphertext)
}
func (m *mockKeyStore) StoreKeyMetadata(ctx context.Context, path string, metadata map[string]interface{}) error {
	return m.storeKeyMetadata(ctx, path, metadata)
}

// mockQuoteVerifier implements QuoteVerifier.
type mockQuoteVerifier struct {
	verifyQuote func(akPublic, nonce []byte, quote *api.TPMQuote) error
}

func (m *mockQuoteVerifier) VerifyQuote(akPublic, nonce []byte, quote *api.TPMQuote) error {
	return m.verifyQuote(akPublic, nonce, quote)
}

// newTestServer creates an in-process gRPC server and returns a client.
func newTestServer(t *testing.T, db DBStore, ks KeyStore) (api.AgentServiceClient, api.LuksManagerClient, func()) {
	return newTestServerWithVerifier(t, db, ks, nil)
}

func newTestServerWithVerifier(t *testing.T, db DBStore, ks KeyStore, qv QuoteVerifier) (api.AgentServiceClient, api.LuksManagerClient, func()) {
	t.Helper()

	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()

	s := &server{db: db, vaultService: ks, quoteVerifier: qv}
	api.RegisterAgentServiceServer(srv, s)
	api.RegisterLuksManagerServer(srv, s)

	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}

	cleanup := func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
	}
	return api.NewAgentServiceClient(conn), api.NewLuksManagerClient(conn), cleanup
}

// --- GetKey tests ---

func TestGetKey_Success(t *testing.T) {
	volID := uuid.New()
	vol := &Volume{ID: volID, UUID: "test-vol-uuid"}
	kv := &KeyVersion{Version: 1, VaultKeyID: "k1", WrappedKey: "vault:v1:abc"}
	plaintext := []byte("recovered-key")

	db := &mockDB{
		getVolumeByUUID: func(_ context.Context, u string) (*Volume, error) { return vol, nil },
		getKeyVersion:   func(_ context.Context, _ uuid.UUID, _ int) (*KeyVersion, error) { return kv, nil },
	}
	ks := &mockKeyStore{
		unwrapKey: func(_ context.Context, _ string) ([]byte, error) { return plaintext, nil },
	}

	_, lm, cleanup := newTestServer(t, db, ks)
	defer cleanup()

	resp, err := lm.GetKey(context.Background(), &api.KeyRequest{VolumeUuid: "test-vol-uuid"})
	if err != nil {
		t.Fatalf("GetKey error: %v", err)
	}
	if string(resp.GetWrappedKey()) != string(plaintext) {
		t.Errorf("key: got %q want %q", resp.GetWrappedKey(), plaintext)
	}
	if resp.GetKeyVersion() != 1 {
		t.Errorf("key_version: got %d want 1", resp.GetKeyVersion())
	}
}

func TestGetKey_MissingVolumeUUID(t *testing.T) {
	_, lm, cleanup := newTestServer(t, &mockDB{}, &mockKeyStore{})
	defer cleanup()

	_, err := lm.GetKey(context.Background(), &api.KeyRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("code: got %v want InvalidArgument", status.Code(err))
	}
}

func TestGetKey_VolumeNotFound(t *testing.T) {
	db := &mockDB{
		getVolumeByUUID: func(_ context.Context, _ string) (*Volume, error) {
			return nil, status.Error(codes.NotFound, "not found")
		},
	}
	_, lm, cleanup := newTestServer(t, db, &mockKeyStore{})
	defer cleanup()

	_, err := lm.GetKey(context.Background(), &api.KeyRequest{VolumeUuid: "missing"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("code: got %v want NotFound", status.Code(err))
	}
}

func TestGetKey_KeyVersionNotFound(t *testing.T) {
	vol := &Volume{ID: uuid.New(), UUID: "u"}
	db := &mockDB{
		getVolumeByUUID: func(_ context.Context, _ string) (*Volume, error) { return vol, nil },
		getKeyVersion: func(_ context.Context, _ uuid.UUID, _ int) (*KeyVersion, error) {
			return nil, status.Error(codes.NotFound, "no key")
		},
	}
	_, lm, cleanup := newTestServer(t, db, &mockKeyStore{})
	defer cleanup()

	_, err := lm.GetKey(context.Background(), &api.KeyRequest{VolumeUuid: "u"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("code: got %v want NotFound", status.Code(err))
	}
}

// --- PostImaging tests ---

func TestPostImaging_NewVolume(t *testing.T) {
	agentID := uuid.New()
	volID := uuid.New()
	agent := &Agent{ID: agentID, Hostname: "host1"}
	vol := &Volume{ID: volID, UUID: "new-vol-uuid"}
	kv := &KeyVersion{Version: 1, VaultKeyID: "v1", WrappedKey: "cipher"}

	db := &mockDB{
		upsertAgent:           func(_ context.Context, _, _ string, _ json.RawMessage) (*Agent, error) { return agent, nil },
		getVolumeByDevicePath: func(_ context.Context, _ uuid.UUID, _ string) (*Volume, error) { return nil, nil },
		upsertVolume:          func(_ context.Context, _ uuid.UUID, _, _ string) (*Volume, error) { return vol, nil },
		createKeyVersion:      func(_ context.Context, _ uuid.UUID, _ int, _, _ string) (*KeyVersion, error) { return kv, nil },
	}
	ks := &mockKeyStore{
		wrapKey: func(_ context.Context, _ []byte) (*EncryptResponse, error) {
			return &EncryptResponse{Ciphertext: "cipher", KeyVersion: 1}, nil
		},
		storeKeyMetadata: func(_ context.Context, _ string, _ map[string]interface{}) error { return nil },
	}

	agentSvc, _, cleanup := newTestServer(t, db, ks)
	defer cleanup()

	resp, err := agentSvc.PostImaging(context.Background(), &api.PostImagingRequest{
		Hostname:       "host1",
		DevicePath:     "/dev/vda2",
		NewRecoveryKey: []byte("new-key"),
	})
	if err != nil {
		t.Fatalf("PostImaging error: %v", err)
	}
	if resp.GetVolume().GetUuid() != "new-vol-uuid" {
		t.Errorf("volume uuid: got %q want %q", resp.GetVolume().GetUuid(), "new-vol-uuid")
	}
	if resp.GetVersion().GetValue() != 1 {
		t.Errorf("version: got %d want 1", resp.GetVersion().GetValue())
	}
}

func TestPostImaging_ExistingVolume_IncrementsVersion(t *testing.T) {
	agentID := uuid.New()
	volID := uuid.New()
	agent := &Agent{ID: agentID, Hostname: "host2"}
	existingVol := &Volume{ID: volID, UUID: "existing-uuid"}
	latestKV := &KeyVersion{Version: 3}
	newKV := &KeyVersion{Version: 4, VaultKeyID: "v4", WrappedKey: "c"}

	db := &mockDB{
		upsertAgent:           func(_ context.Context, _, _ string, _ json.RawMessage) (*Agent, error) { return agent, nil },
		getVolumeByDevicePath: func(_ context.Context, _ uuid.UUID, _ string) (*Volume, error) { return existingVol, nil },
		getLatestKeyVersion:   func(_ context.Context, _ uuid.UUID) (*KeyVersion, error) { return latestKV, nil },
		createKeyVersion:      func(_ context.Context, _ uuid.UUID, _ int, _, _ string) (*KeyVersion, error) { return newKV, nil },
	}
	ks := &mockKeyStore{
		wrapKey: func(_ context.Context, _ []byte) (*EncryptResponse, error) {
			return &EncryptResponse{Ciphertext: "c", KeyVersion: 1}, nil
		},
		storeKeyMetadata: func(_ context.Context, _ string, _ map[string]interface{}) error { return nil },
	}

	agentSvc, _, cleanup := newTestServer(t, db, ks)
	defer cleanup()

	resp, err := agentSvc.PostImaging(context.Background(), &api.PostImagingRequest{
		Hostname:       "host2",
		DevicePath:     "/dev/vda2",
		NewRecoveryKey: []byte("k"),
	})
	if err != nil {
		t.Fatalf("PostImaging error: %v", err)
	}
	if resp.GetVersion().GetValue() != 4 {
		t.Errorf("version: got %d want 4", resp.GetVersion().GetValue())
	}
}

func TestPostImaging_MissingHostname(t *testing.T) {
	agentSvc, _, cleanup := newTestServer(t, &mockDB{}, &mockKeyStore{})
	defer cleanup()

	_, err := agentSvc.PostImaging(context.Background(), &api.PostImagingRequest{
		DevicePath:     "/dev/vda2",
		NewRecoveryKey: []byte("k"),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("code: got %v want InvalidArgument", status.Code(err))
	}
}

func TestPostImaging_MissingDevicePath(t *testing.T) {
	agentSvc, _, cleanup := newTestServer(t, &mockDB{}, &mockKeyStore{})
	defer cleanup()

	_, err := agentSvc.PostImaging(context.Background(), &api.PostImagingRequest{
		Hostname:       "h",
		NewRecoveryKey: []byte("k"),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("code: got %v want InvalidArgument", status.Code(err))
	}
}

func TestPostImaging_MissingRecoveryKey(t *testing.T) {
	agentSvc, _, cleanup := newTestServer(t, &mockDB{}, &mockKeyStore{})
	defer cleanup()

	_, err := agentSvc.PostImaging(context.Background(), &api.PostImagingRequest{
		Hostname:   "h",
		DevicePath: "/dev/vda2",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("code: got %v want InvalidArgument", status.Code(err))
	}
}

// --- GetNonce tests ---

func TestGetNonce_Success(t *testing.T) {
	volID := uuid.New()
	vol := &Volume{ID: volID, UUID: "u"}

	db := &mockDB{
		getVolumeByUUID: func(_ context.Context, _ string) (*Volume, error) { return vol, nil },
		createNonce:     func(_ context.Context, _ uuid.UUID, _ []byte) error { return nil },
	}
	_, lm, cleanup := newTestServer(t, db, &mockKeyStore{})
	defer cleanup()

	resp, err := lm.GetNonce(context.Background(), &api.NonceRequest{VolumeUuid: "u"})
	if err != nil {
		t.Fatalf("GetNonce error: %v", err)
	}
	if len(resp.GetNonce()) != 32 {
		t.Errorf("nonce length: got %d want 32", len(resp.GetNonce()))
	}
}

func TestGetNonce_MissingVolumeUUID(t *testing.T) {
	_, lm, cleanup := newTestServer(t, &mockDB{}, &mockKeyStore{})
	defer cleanup()

	_, err := lm.GetNonce(context.Background(), &api.NonceRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("code: got %v want InvalidArgument", status.Code(err))
	}
}

func TestGetNonce_VolumeNotFound(t *testing.T) {
	db := &mockDB{
		getVolumeByUUID: func(_ context.Context, _ string) (*Volume, error) {
			return nil, status.Error(codes.NotFound, "not found")
		},
	}
	_, lm, cleanup := newTestServer(t, db, &mockKeyStore{})
	defer cleanup()

	_, err := lm.GetNonce(context.Background(), &api.NonceRequest{VolumeUuid: "missing"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("code: got %v want NotFound", status.Code(err))
	}
}

// --- GetKeyWithAttestation tests ---

func TestGetKeyWithAttestation_MissingVolumeUUID(t *testing.T) {
	qv := &mockQuoteVerifier{verifyQuote: func(_, _ []byte, _ *api.TPMQuote) error { return nil }}
	_, lm, cleanup := newTestServerWithVerifier(t, &mockDB{}, &mockKeyStore{}, qv)
	defer cleanup()

	_, err := lm.GetKeyWithAttestation(context.Background(), &api.AttestationKeyRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("code: got %v want InvalidArgument", status.Code(err))
	}
}

func TestGetKeyWithAttestation_VolumeNotFound(t *testing.T) {
	db := &mockDB{
		getVolumeByUUID: func(_ context.Context, _ string) (*Volume, error) {
			return nil, status.Error(codes.NotFound, "not found")
		},
	}
	qv := &mockQuoteVerifier{verifyQuote: func(_, _ []byte, _ *api.TPMQuote) error { return nil }}
	_, lm, cleanup := newTestServerWithVerifier(t, db, &mockKeyStore{}, qv)
	defer cleanup()

	_, err := lm.GetKeyWithAttestation(context.Background(), &api.AttestationKeyRequest{VolumeUuid: "missing"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("code: got %v want NotFound", status.Code(err))
	}
}

func TestGetKeyWithAttestation_NoEnrollment(t *testing.T) {
	volID := uuid.New()
	vol := &Volume{ID: volID, UUID: "u"}
	db := &mockDB{
		getVolumeByUUID:  func(_ context.Context, _ string) (*Volume, error) { return vol, nil },
		getTPMEnrollment: func(_ context.Context, _ uuid.UUID) (*TPMEnrollment, error) { return nil, nil },
	}
	qv := &mockQuoteVerifier{verifyQuote: func(_, _ []byte, _ *api.TPMQuote) error { return nil }}
	_, lm, cleanup := newTestServerWithVerifier(t, db, &mockKeyStore{}, qv)
	defer cleanup()

	_, err := lm.GetKeyWithAttestation(context.Background(), &api.AttestationKeyRequest{VolumeUuid: "u"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("code: got %v want FailedPrecondition", status.Code(err))
	}
}

func TestGetKeyWithAttestation_NonceInvalid(t *testing.T) {
	volID := uuid.New()
	vol := &Volume{ID: volID, UUID: "u"}
	enrollment := &TPMEnrollment{AKPublic: []byte{0x01}}
	db := &mockDB{
		getVolumeByUUID:  func(_ context.Context, _ string) (*Volume, error) { return vol, nil },
		getTPMEnrollment: func(_ context.Context, _ uuid.UUID) (*TPMEnrollment, error) { return enrollment, nil },
		validateConsumeNonce: func(_ context.Context, _ uuid.UUID, _ []byte) error {
			return status.Error(codes.Unauthenticated, "nonce expired")
		},
	}
	qv := &mockQuoteVerifier{verifyQuote: func(_, _ []byte, _ *api.TPMQuote) error { return nil }}
	_, lm, cleanup := newTestServerWithVerifier(t, db, &mockKeyStore{}, qv)
	defer cleanup()

	_, err := lm.GetKeyWithAttestation(context.Background(), &api.AttestationKeyRequest{VolumeUuid: "u"})
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("code: got %v want Unauthenticated", status.Code(err))
	}
}

func TestGetKeyWithAttestation_QuoteFails(t *testing.T) {
	volID := uuid.New()
	vol := &Volume{ID: volID, UUID: "u"}
	enrollment := &TPMEnrollment{AKPublic: []byte{0x01}}
	db := &mockDB{
		getVolumeByUUID:      func(_ context.Context, _ string) (*Volume, error) { return vol, nil },
		getTPMEnrollment:     func(_ context.Context, _ uuid.UUID) (*TPMEnrollment, error) { return enrollment, nil },
		validateConsumeNonce: func(_ context.Context, _ uuid.UUID, _ []byte) error { return nil },
	}
	qv := &mockQuoteVerifier{verifyQuote: func(_, _ []byte, _ *api.TPMQuote) error {
		return status.Error(codes.Unauthenticated, "signature invalid")
	}}
	_, lm, cleanup := newTestServerWithVerifier(t, db, &mockKeyStore{}, qv)
	defer cleanup()

	_, err := lm.GetKeyWithAttestation(context.Background(), &api.AttestationKeyRequest{VolumeUuid: "u"})
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("code: got %v want Unauthenticated", status.Code(err))
	}
}

func TestGetKeyWithAttestation_Success(t *testing.T) {
	volID := uuid.New()
	vol := &Volume{ID: volID, UUID: "u"}
	enrollment := &TPMEnrollment{AKPublic: []byte{0x01}}
	kv := &KeyVersion{Version: 1, VaultKeyID: "k1", WrappedKey: "vault:v1:abc"}
	plaintext := []byte("recovered-key")

	db := &mockDB{
		getVolumeByUUID:      func(_ context.Context, _ string) (*Volume, error) { return vol, nil },
		getTPMEnrollment:     func(_ context.Context, _ uuid.UUID) (*TPMEnrollment, error) { return enrollment, nil },
		validateConsumeNonce: func(_ context.Context, _ uuid.UUID, _ []byte) error { return nil },
		getKeyVersion:        func(_ context.Context, _ uuid.UUID, _ int) (*KeyVersion, error) { return kv, nil },
	}
	ks := &mockKeyStore{
		unwrapKey: func(_ context.Context, _ string) ([]byte, error) { return plaintext, nil },
	}
	qv := &mockQuoteVerifier{verifyQuote: func(_, _ []byte, _ *api.TPMQuote) error { return nil }}

	_, lm, cleanup := newTestServerWithVerifier(t, db, ks, qv)
	defer cleanup()

	resp, err := lm.GetKeyWithAttestation(context.Background(), &api.AttestationKeyRequest{VolumeUuid: "u"})
	if err != nil {
		t.Fatalf("GetKeyWithAttestation error: %v", err)
	}
	if string(resp.GetWrappedKey()) != string(plaintext) {
		t.Errorf("key: got %q want %q", resp.GetWrappedKey(), plaintext)
	}
}
