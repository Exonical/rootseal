package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"rootseal/internal/tpm2"
	"rootseal/pkg/api"

	"github.com/google/uuid"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

// server is used to implement api.LuksManagerServer.
type server struct {
	api.UnimplementedLuksManagerServer
	api.UnimplementedAgentServiceServer
	vaultClient  *vault.Client
	vaultService *VaultService
	db           *DB
	pcrPolicy    *tpm2.PCRPolicy
}

// Attest implements api.LuksManagerServer
func (s *server) Attest(ctx context.Context, in *api.AttestationRequest) (*api.AttestationResponse, error) {
	slog.Info("received attestation request", "role_id", in.GetRoleId())

	resp, err := s.vaultClient.Auth.AppRoleLogin(ctx, schema.AppRoleLoginRequest{
		RoleId:   in.GetRoleId(),
		SecretId: in.GetSecretId(),
	})
	if err != nil {
		return nil, err
	}

	return &api.AttestationResponse{Token: resp.Auth.ClientToken}, nil
}

// GetKey implements api.LuksManagerServer - retrieves wrapped key for NBDE unlock
func (s *server) GetKey(ctx context.Context, in *api.KeyRequest) (*api.KeyResponse, error) {
	slog.Info("received key request", "volume_uuid", in.GetVolumeUuid(), "hostname", in.GetHostname(), "version", in.GetVersion())

	volumeUUID := in.GetVolumeUuid()
	if volumeUUID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "volume_uuid is required")
	}

	// Look up the volume in the database
	volume, err := s.db.GetVolumeByUUID(ctx, volumeUUID)
	if err != nil {
		slog.Error("failed to find volume", "volume_uuid", volumeUUID, "error", err)
		return nil, status.Errorf(codes.NotFound, "volume not found: %v", err)
	}

	// Get the requested key version (0 = latest)
	requestedVersion := int(in.GetVersion())
	keyVersion, err := s.db.GetKeyVersion(ctx, volume.ID, requestedVersion)
	if err != nil {
		slog.Error("failed to get key version", "volume_id", volume.ID, "version", requestedVersion, "error", err)
		return nil, status.Errorf(codes.NotFound, "key version not found: %v", err)
	}

	// Unwrap the key using Vault Transit
	plaintext, err := s.vaultService.UnwrapKey(ctx, keyVersion.WrappedKey)
	if err != nil {
		slog.Error("failed to unwrap key", "volume_uuid", volumeUUID, "error", err)
		return nil, status.Errorf(codes.Internal, "failed to unwrap key: %v", err)
	}

	slog.Info("returning unwrapped key", "volume_uuid", volumeUUID, "version", keyVersion.Version, "vault_key_id", keyVersion.VaultKeyID)

	return &api.KeyResponse{
		WrappedKey:  plaintext,
		KeyVersion:  int32(keyVersion.Version),
		VaultKvPath: keyVersion.VaultKeyID,
	}, nil
}

// GetNonce generates a nonce for TPM attestation challenge
func (s *server) GetNonce(ctx context.Context, in *api.NonceRequest) (*api.NonceResponse, error) {
	volumeUUID := in.GetVolumeUuid()
	if volumeUUID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "volume_uuid is required")
	}

	// Look up the volume to get its ID
	volume, err := s.db.GetVolumeByUUID(ctx, volumeUUID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "volume not found: %v", err)
	}

	// Generate 32-byte random nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate nonce: %v", err)
	}

	// Store nonce for later validation
	if err := s.db.CreateNonce(ctx, volume.ID, nonce); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to store nonce: %v", err)
	}

	slog.Info("generated attestation nonce", "volume_uuid", volumeUUID)

	// Nonce expires in 5 minutes
	expiresAt := time.Now().Add(5 * time.Minute)

	return &api.NonceResponse{
		Nonce:     nonce,
		ExpiresAt: expiresAt.Unix(),
	}, nil
}

// GetKeyWithAttestation returns the decryption key after verifying TPM attestation
func (s *server) GetKeyWithAttestation(ctx context.Context, in *api.AttestationKeyRequest) (*api.KeyResponse, error) {
	volumeUUID := in.GetVolumeUuid()
	if volumeUUID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "volume_uuid is required")
	}

	slog.Info("received attested key request", "volume_uuid", volumeUUID)

	// Look up the volume
	volume, err := s.db.GetVolumeByUUID(ctx, volumeUUID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "volume not found: %v", err)
	}

	// Get TPM enrollment for this volume
	enrollment, err := s.db.GetTPMEnrollment(ctx, volume.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get TPM enrollment: %v", err)
	}
	if enrollment == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "no TPM enrollment found for volume")
	}

	// Validate and consume the nonce (prevents replay attacks)
	if err := s.db.ValidateAndConsumeNonce(ctx, volume.ID, in.GetNonce()); err != nil {
		slog.Warn("nonce validation failed", "volume_uuid", volumeUUID, "error", err)
		return nil, status.Errorf(codes.Unauthenticated, "nonce validation failed: %v", err)
	}

	// Verify the TPM quote
	verifier := tpm2.NewVerifier()
	if err := verifier.VerifyQuote(enrollment.AKPublic, in.GetNonce(), in.GetQuote()); err != nil {
		slog.Warn("TPM quote verification failed", "volume_uuid", volumeUUID, "error", err)
		return nil, status.Errorf(codes.Unauthenticated, "TPM attestation failed: %v", err)
	}

	// Verify PCR policy if configured
	if s.pcrPolicy != nil {
		if err := s.pcrPolicy.Verify(in.GetQuote().GetPcrs()); err != nil {
			slog.Warn("PCR policy verification failed", "volume_uuid", volumeUUID, "error", err)
			return nil, status.Errorf(codes.Unauthenticated, "PCR policy check failed: %v", err)
		}
		slog.Info("PCR policy verified", "volume_uuid", volumeUUID)
	}

	slog.Info("TPM attestation verified", "volume_uuid", volumeUUID)

	// Get the key version
	keyVersion, err := s.db.GetKeyVersion(ctx, volume.ID, 0) // Latest
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "key version not found: %v", err)
	}

	// Unwrap the key
	plaintext, err := s.vaultService.UnwrapKey(ctx, keyVersion.WrappedKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unwrap key: %v", err)
	}

	slog.Info("returning key after TPM attestation", "volume_uuid", volumeUUID, "version", keyVersion.Version)

	return &api.KeyResponse{
		WrappedKey:  plaintext,
		KeyVersion:  int32(keyVersion.Version),
		VaultKvPath: keyVersion.VaultKeyID,
	}, nil
}

// ServerConfig holds configuration for the control plane server
type ServerConfig struct {
	DatabaseURL      string
	VaultAddr        string
	VaultToken       string
	RequiredPCRs     string // Comma-separated list of PCR indices (e.g., "0,2,7,11")
	EnforcePCRValues bool   // If true, reject quotes with unexpected PCR values
}

// NewServer creates and starts a new gRPC server with graceful shutdown (uses defaults).
func NewServer(dbConnStr, vaultAddr, vaultToken string) error {
	return NewServerWithConfig(ServerConfig{
		DatabaseURL: dbConnStr,
		VaultAddr:   vaultAddr,
		VaultToken:  vaultToken,
	})
}

// NewServerWithConfig creates and starts a new gRPC server with the given configuration.
func NewServerWithConfig(cfg ServerConfig) error {
	// Initialize structured logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Initialize database
	db, err := NewDB(cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}

	// Initialize Vault client
	vaultClient, err := vault.New(
		vault.WithAddress(cfg.VaultAddr),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		return fmt.Errorf("failed to initialize vault client: %w", err)
	}

	// Set Vault token
	if err := vaultClient.SetToken(cfg.VaultToken); err != nil {
		return fmt.Errorf("failed to set vault token: %w", err)
	}

	// Initialize Vault service
	// Uses 'recovery-key' and 'kv' to match deploy/compose/vault-init.sh
	vaultService := NewVaultService(vaultClient, "transit", "recovery-key", "kv")

	// Parse PCR policy from config
	requiredPCRs, err := tpm2.ParsePCRList(cfg.RequiredPCRs)
	if err != nil {
		return fmt.Errorf("failed to parse TPM_REQUIRED_PCRS: %w", err)
	}
	pcrPolicy := tpm2.NewPCRPolicy(requiredPCRs, !cfg.EnforcePCRValues)
	slog.Info("TPM PCR policy configured", "required_pcrs", requiredPCRs, "enforce_values", cfg.EnforcePCRValues)

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	s := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			RecoveryInterceptor(),
			LoggingInterceptor(),
		),
	)
	srv := &server{
		vaultClient:  vaultClient,
		vaultService: vaultService,
		db:           db,
		pcrPolicy:    pcrPolicy,
	}
	api.RegisterLuksManagerServer(s, srv)
	api.RegisterAgentServiceServer(s, srv)

	// Register health service
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(s, healthServer)
	healthServer.SetServingStatus("api.LuksManager", healthpb.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("api.AgentService", healthpb.HealthCheckResponse_SERVING)

	// Register reflection service for grpcurl debugging
	reflection.Register(s)

	// Graceful shutdown handler
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		slog.Info("received shutdown signal", "signal", sig)
		healthServer.SetServingStatus("api.LuksManager", healthpb.HealthCheckResponse_NOT_SERVING)
		healthServer.SetServingStatus("api.AgentService", healthpb.HealthCheckResponse_NOT_SERVING)
		s.GracefulStop()
		if err := db.Close(); err != nil {
			slog.Error("failed to close database", "error", err)
		}
	}()

	slog.Info("server listening", "address", lis.Addr())
	return s.Serve(lis)
}

// PostImaging implements api.AgentServiceServer
func (s *server) PostImaging(ctx context.Context, in *api.PostImagingRequest) (*api.PostImagingResponse, error) {
	slog.Info("received post-imaging request", "device", in.GetDevicePath(), "hostname", in.GetHostname())

	// Validate required fields
	if in.GetHostname() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "hostname is required")
	}
	if in.GetDevicePath() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "device_path is required")
	}
	if len(in.GetNewRecoveryKey()) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "new_recovery_key is required")
	}

	// Parse labels if provided
	var labels json.RawMessage
	if len(in.GetLabels()) > 0 {
		labelsBytes, err := json.Marshal(in.GetLabels())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "failed to marshal labels: %v", err)
		}
		labels = json.RawMessage(labelsBytes)
	} else {
		labels = json.RawMessage("{}")
	}

	// Upsert agent record
	agent, err := s.db.UpsertAgent(ctx, in.GetHostname(), in.GetSerial(), labels)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to upsert agent: %v", err)
	}
	slog.Info("agent record upserted", "hostname", agent.Hostname, "agent_id", agent.ID)

	// Check if volume already exists for idempotency
	existingVolume, err := s.db.GetVolumeByDevicePath(ctx, agent.ID, in.GetDevicePath())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check existing volume: %v", err)
	}

	var volume *Volume
	var nextVersion int = 1

	if existingVolume != nil {
		// Volume exists, check latest key version for idempotency
		volume = existingVolume
		latestKey, err := s.db.GetLatestKeyVersion(ctx, volume.ID)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to get latest key version: %v", err)
		}
		if latestKey != nil {
			nextVersion = latestKey.Version + 1
		}
		slog.Info("existing volume found", "volume_uuid", volume.UUID, "next_version", nextVersion)
	} else {
		// Create new volume record
		volumeUUID := uuid.New().String()
		volume, err = s.db.UpsertVolume(ctx, agent.ID, in.GetDevicePath(), volumeUUID)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to create volume: %v", err)
		}
		slog.Info("created new volume", "volume_uuid", volume.UUID)
	}

	// Wrap the recovery key using Vault Transit
	encryptResp, err := s.vaultService.WrapKey(ctx, in.GetNewRecoveryKey())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to wrap recovery key: %v", err)
	}
	slog.Debug("recovery key wrapped with vault transit")

	// Generate Vault KV path for metadata
	kvPath := fmt.Sprintf("volumes/%s/v%d", volume.UUID, nextVersion)

	// Store key metadata in Vault KV
	metadata := map[string]interface{}{
		"volume_id":   volume.ID.String(),
		"volume_uuid": volume.UUID,
		"device_path": in.GetDevicePath(),
		"hostname":    in.GetHostname(),
		"serial":      in.GetSerial(),
		"version":     nextVersion,
		"luks_uuid":   "", // LUKS UUID not available in PostImagingRequest
		"created_at":  time.Now().UTC().Format(time.RFC3339),
		"key_version": encryptResp.KeyVersion,
	}

	err = s.vaultService.StoreKeyMetadata(ctx, kvPath, metadata)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to store key metadata: %v", err)
	}
	slog.Debug("key metadata stored", "kv_path", kvPath)

	// Store key version in database
	vaultKeyID := fmt.Sprintf("%s/v%d", volume.UUID, nextVersion)
	keyVersion, err := s.db.CreateKeyVersion(ctx, volume.ID, nextVersion, vaultKeyID, encryptResp.Ciphertext)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create key version: %v", err)
	}
	slog.Info("key version created", "version", keyVersion.Version, "volume_uuid", volume.UUID)

	// Store TPM enrollment if provided
	if tpmEnroll := in.GetTpmEnrollment(); tpmEnroll != nil {
		_, err := s.db.CreateTPMEnrollment(ctx, volume.ID,
			tpmEnroll.GetEkPublic(),
			tpmEnroll.GetEkCert(),
			tpmEnroll.GetAkPublic(),
			tpmEnroll.GetAkName(),
		)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to store TPM enrollment: %v", err)
		}
		slog.Info("TPM enrollment stored", "volume_uuid", volume.UUID)
	}

	// Convert wrapped key to bytes for response
	ciphertextBytes := []byte(encryptResp.Ciphertext)

	return &api.PostImagingResponse{
		Wrapped: &api.WrappedKey{
			Ciphertext:  ciphertextBytes,
			KeyVersion:  int32(encryptResp.KeyVersion),
			VaultKvPath: kvPath,
		},
		Version: &api.Version{
			Value: int32(nextVersion),
		},
		Volume: &api.Volume{
			Uuid:     volume.UUID,
			LuksUuid: "", // LUKS UUID not available in PostImagingRequest
		},
	}, nil
}
