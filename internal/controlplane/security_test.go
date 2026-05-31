package controlplane

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"rootseal/pkg/api"
)

// ctxWithCN returns a context carrying a verified mTLS client CN, mirroring
// what MTLSInterceptor installs in production.
func ctxWithCN(cn string) context.Context {
	return context.WithValue(context.Background(), peerCNKey{}, cn)
}

// --- F1: unattested GetKey path disabled by default ---

func TestGetKey_UnattestedPathDisabled(t *testing.T) {
	s := &server{allowUnattestedGetKey: false}
	_, err := s.GetKey(context.Background(), &api.KeyRequest{VolumeUuid: "v1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code: got %v want FailedPrecondition", status.Code(err))
	}
}

// --- F2/F8: per-host authorization bound to mTLS identity ---

func newAuthzServer(agent *Agent, getAgentErr error) *server {
	return &server{
		requireAuth: true,
		db: &mockDB{
			getAgent: func(_ context.Context, _ uuid.UUID) (*Agent, error) {
				if getAgentErr != nil {
					return nil, getAgentErr
				}
				return agent, nil
			},
		},
	}
}

func TestAuthorizeVolume_AllowedForBoundIdentity(t *testing.T) {
	vol := &Volume{ID: uuid.New(), AgentID: uuid.New(), UUID: "v1"}
	s := newAuthzServer(&Agent{ID: vol.AgentID, AuthorizedCN: "host-a", Revoked: false}, nil)
	if err := s.authorizeVolume(ctxWithCN("host-a"), "unlock", vol); err != nil {
		t.Fatalf("expected authorization to succeed, got %v", err)
	}
}

func TestAuthorizeVolume_CrossHostDenied(t *testing.T) {
	vol := &Volume{ID: uuid.New(), AgentID: uuid.New(), UUID: "v1"}
	s := newAuthzServer(&Agent{ID: vol.AgentID, AuthorizedCN: "host-a"}, nil)
	// host-b presents a valid cert but is not the bound identity for this volume.
	err := s.authorizeVolume(ctxWithCN("host-b"), "unlock", vol)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code: got %v want PermissionDenied", status.Code(err))
	}
}

func TestAuthorizeVolume_NoIdentityDenied(t *testing.T) {
	vol := &Volume{ID: uuid.New(), AgentID: uuid.New(), UUID: "v1"}
	s := newAuthzServer(&Agent{ID: vol.AgentID, AuthorizedCN: "host-a"}, nil)
	err := s.authorizeVolume(context.Background(), "unlock", vol) // no CN
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code: got %v want PermissionDenied", status.Code(err))
	}
}

func TestAuthorizeVolume_RevokedHostDenied(t *testing.T) {
	vol := &Volume{ID: uuid.New(), AgentID: uuid.New(), UUID: "v1"}
	s := newAuthzServer(&Agent{ID: vol.AgentID, AuthorizedCN: "host-a", Revoked: true}, nil)
	err := s.authorizeVolume(ctxWithCN("host-a"), "unlock", vol)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code: got %v want PermissionDenied", status.Code(err))
	}
}

func TestAuthorizeVolume_UnboundVolumeDenied(t *testing.T) {
	vol := &Volume{ID: uuid.New(), AgentID: uuid.New(), UUID: "v1"}
	s := newAuthzServer(&Agent{ID: vol.AgentID, AuthorizedCN: ""}, nil)
	err := s.authorizeVolume(ctxWithCN("host-a"), "unlock", vol)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code: got %v want PermissionDenied", status.Code(err))
	}
}

func TestAuthorizeVolume_SkippedWhenAuthDisabled(t *testing.T) {
	// Explicit insecure dev mode (requireAuth=false) skips the check.
	vol := &Volume{ID: uuid.New(), AgentID: uuid.New(), UUID: "v1"}
	s := &server{requireAuth: false}
	if err := s.authorizeVolume(context.Background(), "unlock", vol); err != nil {
		t.Fatalf("expected nil when requireAuth=false, got %v", err)
	}
}

// --- F7: enrollment token enforcement ---

func TestPostImaging_EnrollmentTokenMissing(t *testing.T) {
	s := &server{requireEnrollmentToken: true}
	_, err := s.PostImaging(context.Background(), &api.PostImagingRequest{
		Hostname:       "h1",
		DevicePath:     "/dev/sda2",
		NewRecoveryKey: []byte("k"),
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code: got %v want Unauthenticated", status.Code(err))
	}
}

func TestPostImaging_EnrollmentTokenReused(t *testing.T) {
	// ConsumeEnrollmentToken fails closed when the token was already used.
	s := &server{
		requireEnrollmentToken: true,
		db: &mockDB{
			consumeEnrollmentTok: func(_ context.Context, _ []byte, _ string) error {
				return status.Error(codes.PermissionDenied, "already used")
			},
		},
	}
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(enrollmentTokenMDKey, "reused-token"))
	_, err := s.PostImaging(ctx, &api.PostImagingRequest{
		Hostname:       "h1",
		DevicePath:     "/dev/sda2",
		NewRecoveryKey: []byte("k"),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code: got %v want PermissionDenied", status.Code(err))
	}
}

func TestEnrollmentTokenFromContext(t *testing.T) {
	if got := enrollmentTokenFromContext(context.Background()); got != "" {
		t.Fatalf("expected empty token, got %q", got)
	}
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(enrollmentTokenMDKey, "abc123"))
	if got := enrollmentTokenFromContext(ctx); got != "abc123" {
		t.Fatalf("token: got %q want abc123", got)
	}
}

// --- F6: PCR pinning serialization + comparison ---

func TestPCRPinningRoundTrip(t *testing.T) {
	pcrs := []*api.PCRValue{
		{Index: 0, Digest: []byte{0x01, 0x02}},
		{Index: 7, Digest: []byte{0xaa, 0xbb}},
	}
	pinned, err := pcrsToPinned(pcrs)
	if err != nil {
		t.Fatalf("pcrsToPinned: %v", err)
	}

	match, err := pcrsMatchPinned(pinned, pcrs)
	if err != nil {
		t.Fatalf("pcrsMatchPinned: %v", err)
	}
	if !match {
		t.Fatal("expected identical PCRs to match pinned values")
	}
}

func TestPCRPinningMismatch(t *testing.T) {
	orig := []*api.PCRValue{
		{Index: 0, Digest: []byte{0x01, 0x02}},
		{Index: 7, Digest: []byte{0xaa, 0xbb}},
	}
	pinned, err := pcrsToPinned(orig)
	if err != nil {
		t.Fatalf("pcrsToPinned: %v", err)
	}

	tampered := []*api.PCRValue{
		{Index: 0, Digest: []byte{0x01, 0x02}},
		{Index: 7, Digest: []byte{0xde, 0xad}}, // changed
	}
	match, err := pcrsMatchPinned(pinned, tampered)
	if err != nil {
		t.Fatalf("pcrsMatchPinned: %v", err)
	}
	if match {
		t.Fatal("expected tampered PCRs not to match pinned values")
	}
}

// --- F13: secure-by-default config validation ---

func TestConfigValidate_ProductionRequiresMTLS(t *testing.T) {
	cfg := ServerConfig{Production: true, RequiredPCRs: "0,7", EnforcePCRValues: true, VaultRoleID: "r"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected production without mTLS to be rejected")
	}
}

func TestConfigValidate_ProductionRequiresPCRPolicy(t *testing.T) {
	cfg := ServerConfig{
		Production:       true,
		TLS:              &TLSConfig{ClientAuth: true, CAFile: "ca.crt"},
		EnforcePCRValues: true,
		VaultRoleID:      "r",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected production without PCR policy to be rejected")
	}
}

func TestConfigValidate_ProductionForbidsUnattestedGetKey(t *testing.T) {
	cfg := ServerConfig{
		Production:            true,
		TLS:                   &TLSConfig{ClientAuth: true, CAFile: "ca.crt"},
		RequiredPCRs:          "0,7",
		EnforcePCRValues:      true,
		VaultRoleID:           "r",
		AllowUnattestedGetKey: true,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected production with unattested GetKey to be rejected")
	}
}

func TestConfigValidate_ProductionHappyPath(t *testing.T) {
	cfg := ServerConfig{
		Production:       true,
		TLS:              &TLSConfig{ClientAuth: true, CAFile: "ca.crt"},
		RequiredPCRs:     "0,2,4,7",
		EnforcePCRValues: true,
		VaultRoleID:      "r",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid production config, got %v", err)
	}
}

func TestConfigValidate_NonProdRefusesNoTLSUnlessOptIn(t *testing.T) {
	if err := (ServerConfig{Production: false}).Validate(); err == nil {
		t.Fatal("expected non-production without TLS to be rejected unless AllowInsecure")
	}
	if err := (ServerConfig{Production: false, AllowInsecure: true}).Validate(); err != nil {
		t.Fatalf("expected AllowInsecure to permit no-TLS dev mode, got %v", err)
	}
}
