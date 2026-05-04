package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"rootseal/internal/kms"
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

// DBStore is the subset of *DB methods used by server handlers.
type DBStore interface {
	GetVolumeByUUID(ctx context.Context, volumeUUID string) (*Volume, error)
	GetKeyVersion(ctx context.Context, volumeID uuid.UUID, version int) (*KeyVersion, error)
	CreateNonce(ctx context.Context, volumeID uuid.UUID, nonce []byte) error
	ValidateAndConsumeNonce(ctx context.Context, volumeID uuid.UUID, nonce []byte) error
	GetTPMEnrollment(ctx context.Context, volumeID uuid.UUID) (*TPMEnrollment, error)
	UpsertAgent(ctx context.Context, hostname, serial string, labels json.RawMessage) (*Agent, error)
	GetVolumeByDevicePath(ctx context.Context, agentID uuid.UUID, devicePath string) (*Volume, error)
	GetLatestKeyVersion(ctx context.Context, volumeID uuid.UUID) (*KeyVersion, error)
	UpsertVolume(ctx context.Context, agentID uuid.UUID, devicePath, volumeUUID string) (*Volume, error)
	CreateKeyVersion(ctx context.Context, volumeID uuid.UUID, version int, vaultKeyID, wrappedKey string) (*KeyVersion, error)
	CreateTPMEnrollment(ctx context.Context, volumeID uuid.UUID, ekPublic, ekCert, akPublic, akName []byte) (*TPMEnrollment, error)
}

// KeyStore wraps key encryption/decryption operations.
type KeyStore interface {
	WrapKey(ctx context.Context, plaintext []byte) (*EncryptResponse, error)
	UnwrapKey(ctx context.Context, ciphertext string) ([]byte, error)
	StoreKeyMetadata(ctx context.Context, path string, metadata map[string]interface{}) error
}

// QuoteVerifier verifies TPM quotes during attestation.
type QuoteVerifier interface {
	VerifyQuote(akPublicBytes []byte, nonce []byte, quote *api.TPMQuote) error
}

// server is used to implement api.LuksManagerServer.
type server struct {
	api.UnimplementedLuksManagerServer
	api.UnimplementedAgentServiceServer
	vaultClient    *vault.Client
	vaultService   KeyStore
	kmsProvider    kms.Provider
	db             DBStore
	pcrPolicy      *tpm2.PCRPolicy
	quoteVerifier  QuoteVerifier
	ekTrustStore   *x509.CertPool // Trusted TPM manufacturer CA certs for EK verification
	ekVerifyStrict bool           // If true, reject enrollments without a valid EK cert
}

// Attest implements api.LuksManagerServer.
// The server validates the AppRole credentials against Vault but does NOT
// return the raw Vault token to the caller. Instead it returns a short-lived,
// opaque server-side session identifier that the agent can present in
// subsequent RPCs if needed.  Keeping the Vault token server-side prevents
// agents from having direct Vault access.
func (s *server) Attest(ctx context.Context, in *api.AttestationRequest) (*api.AttestationResponse, error) {
	slog.Info("received attestation request")

	_, err := s.vaultClient.Auth.AppRoleLogin(ctx, schema.AppRoleLoginRequest{
		RoleId:   in.GetRoleId(),
		SecretId: in.GetSecretId(),
	})
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "vault AppRole login failed")
	}

	// Generate a random opaque token instead of returning the Vault token.
	sessionToken := make([]byte, 32)
	if _, err := rand.Read(sessionToken); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate session token")
	}

	return &api.AttestationResponse{Token: fmt.Sprintf("rs-%x", sessionToken)}, nil
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

	slog.Info("key retrieved", "volume_uuid", volumeUUID, "version", keyVersion.Version)

	return &api.KeyResponse{
		WrappedKey:  plaintext,
		KeyVersion:  int32(keyVersion.Version), // #nosec G115 -- key version is a small DB-incremented integer
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

	// Verify the request's AK public matches the enrolled AK
	if reqAK := in.GetAkPublic(); len(reqAK) > 0 {
		if !bytes.Equal(reqAK, enrollment.AKPublic) {
			slog.Warn("AK public key mismatch", "volume_uuid", volumeUUID)
			return nil, status.Errorf(codes.Unauthenticated, "AK public key does not match enrollment")
		}
	}

	// Validate and consume the nonce (prevents replay attacks)
	if err := s.db.ValidateAndConsumeNonce(ctx, volume.ID, in.GetNonce()); err != nil {
		slog.Warn("nonce validation failed", "volume_uuid", volumeUUID, "error", err)
		return nil, status.Errorf(codes.Unauthenticated, "nonce validation failed: %v", err)
	}

	// Verify the TPM quote using the ENROLLED AK (not the one from the request)
	if err := s.quoteVerifier.VerifyQuote(enrollment.AKPublic, in.GetNonce(), in.GetQuote()); err != nil {
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
		KeyVersion:  int32(keyVersion.Version), // #nosec G115 -- key version is a small DB-incremented integer
		VaultKvPath: keyVersion.VaultKeyID,
	}, nil
}

// ServerConfig holds configuration for the control plane server
type ServerConfig struct {
	DatabaseURL      string
	VaultAddr        string
	VaultToken       string // Static token (dev only; prefer AppRole)
	VaultRoleID      string // AppRole role_id (preferred over static token)
	VaultSecretID    string // AppRole secret_id
	RequiredPCRs     string // Comma-separated list of PCR indices (e.g., "0,2,7,11")
	EnforcePCRValues bool   // If true, reject quotes with unexpected PCR values

	// TLS configuration
	TLS *TLSConfig // When nil the server runs without TLS (insecure, dev-only)

	// Debug mode (enables gRPC reflection)
	Debug bool

	// TPM EK verification
	EKCertCAFile   string // Path to PEM file with trusted TPM manufacturer CAs
	EKVerifyStrict bool   // If true, reject enrollments without a valid EK certificate

	// KMS configuration
	KMSProvider string // "vault", "aws-kms", "azure-keyvault", "fortanix-sdkms"
	KMSConfig   *kms.Config
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

	// Authenticate to Vault: prefer AppRole, fall back to static token
	if cfg.VaultRoleID != "" {
		resp, err := vaultClient.Auth.AppRoleLogin(context.Background(), schema.AppRoleLoginRequest{
			RoleId:   cfg.VaultRoleID,
			SecretId: cfg.VaultSecretID,
		})
		if err != nil {
			return fmt.Errorf("vault AppRole login failed: %w", err)
		}
		if err := vaultClient.SetToken(resp.Auth.ClientToken); err != nil {
			return fmt.Errorf("failed to set vault token from AppRole: %w", err)
		}
		slog.Info("vault authenticated via AppRole")

		// Renew the token periodically in the background
		go renewVaultToken(vaultClient, resp.Auth.LeaseDuration)
	} else if cfg.VaultToken != "" {
		if err := vaultClient.SetToken(cfg.VaultToken); err != nil {
			return fmt.Errorf("failed to set vault token: %w", err)
		}
		slog.Warn("vault authenticated via static token (prefer VAULT_ROLE_ID/VAULT_SECRET_ID)")
	} else {
		return fmt.Errorf("vault auth required: set VAULT_ROLE_ID+VAULT_SECRET_ID or VAULT_TOKEN")
	}

	// Initialize Vault service for metadata storage
	// Uses 'recovery-key' and 'kv' to match deploy/compose/vault-init.sh
	vaultService := NewVaultService(vaultClient, "transit", "recovery-key", "kv")

	// Initialize KMS provider
	var kmsProvider kms.Provider
	if cfg.KMSConfig != nil {
		var err error
		kmsProvider, err = kms.NewProvider(cfg.KMSConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize KMS provider: %w", err)
		}
		slog.Info("KMS provider initialized", "provider", cfg.KMSConfig.Provider)
	} else {
		// Default to Vault KMS using the existing config
		kmsProvider, err = kms.NewProvider(&kms.Config{
			Provider: "vault",
			Vault: &kms.VaultConfig{
				Address:     cfg.VaultAddr,
				Token:       cfg.VaultToken,
				TransitPath: "transit",
				KeyName:     "recovery-key",
			},
		})
		if err != nil {
			return fmt.Errorf("failed to initialize default Vault KMS: %w", err)
		}
		slog.Info("KMS provider initialized", "provider", "vault (default)")
	}

	// Parse PCR policy from config
	requiredPCRs, err := tpm2.ParsePCRList(cfg.RequiredPCRs)
	if err != nil {
		return fmt.Errorf("failed to parse TPM_REQUIRED_PCRS: %w", err)
	}
	pcrPolicy := tpm2.NewPCRPolicy(requiredPCRs, !cfg.EnforcePCRValues)
	slog.Info("TPM PCR policy configured", "required_pcrs", requiredPCRs, "enforce_values", cfg.EnforcePCRValues)

	// Load EK certificate trust store if configured
	var ekTrustStore *x509.CertPool
	if cfg.EKCertCAFile != "" {
		caPEM, err := os.ReadFile(cfg.EKCertCAFile) // #nosec G304 -- path from operator-controlled config
		if err != nil {
			return fmt.Errorf("failed to read EK CA file: %w", err)
		}
		ekTrustStore = x509.NewCertPool()
		if !ekTrustStore.AppendCertsFromPEM(caPEM) {
			return fmt.Errorf("failed to parse any certificates from EK CA file")
		}
		slog.Info("EK certificate trust store loaded", "file", cfg.EKCertCAFile, "strict", cfg.EKVerifyStrict)
	} else if cfg.EKVerifyStrict {
		return fmt.Errorf("EK_VERIFY_STRICT is set but EK_CERT_CA_FILE is not configured")
	}

	lis, err := net.Listen("tcp", ":50051") // #nosec G102 -- server intentionally binds to all interfaces
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	// Build gRPC server options
	interceptors := []grpc.UnaryServerInterceptor{
		RecoveryInterceptor(),
		LoggingInterceptor(),
	}

	var grpcOpts []grpc.ServerOption
	if cfg.TLS != nil {
		creds, err := NewServerTransportCredentials(*cfg.TLS)
		if err != nil {
			return fmt.Errorf("failed to load TLS credentials: %w", err)
		}
		grpcOpts = append(grpcOpts, grpc.Creds(creds))
		interceptors = append(interceptors, MTLSInterceptor())
		slog.Info("TLS enabled", "cert", cfg.TLS.CertFile, "client_auth", cfg.TLS.ClientAuth)
	} else {
		slog.Warn("TLS is DISABLED — running in insecure mode (dev only)")
	}

	grpcOpts = append(grpcOpts, grpc.ChainUnaryInterceptor(interceptors...))
	s := grpc.NewServer(grpcOpts...)

	srv := &server{
		vaultClient:    vaultClient,
		vaultService:   vaultService,
		kmsProvider:    kmsProvider,
		db:             db,
		pcrPolicy:      pcrPolicy,
		quoteVerifier:  tpm2.NewVerifier(),
		ekTrustStore:   ekTrustStore,
		ekVerifyStrict: cfg.EKVerifyStrict,
	}
	api.RegisterLuksManagerServer(s, srv)
	api.RegisterAgentServiceServer(s, srv)

	// Register health service
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(s, healthServer)
	healthServer.SetServingStatus("api.LuksManager", healthpb.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("api.AgentService", healthpb.HealthCheckResponse_SERVING)

	// Only register reflection when debug mode is explicitly enabled
	if cfg.Debug {
		reflection.Register(s)
		slog.Warn("gRPC reflection enabled (debug mode)")
	}

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

	// Start background nonce cleanup (every 5 minutes)
	go startNonceCleanup(db, 5*time.Minute)

	slog.Info("server listening", "address", lis.Addr())
	return s.Serve(lis)
}

// renewVaultToken periodically renews the Vault token before it expires.
func renewVaultToken(client *vault.Client, leaseDurationSec int) {
	// Renew at half the lease duration to avoid last-minute races
	renewInterval := time.Duration(leaseDurationSec) * time.Second / 2
	if renewInterval < 30*time.Second {
		renewInterval = 30 * time.Second
	}

	ticker := time.NewTicker(renewInterval)
	defer ticker.Stop()

	for range ticker.C {
		resp, err := client.Auth.TokenRenewSelf(context.Background(), schema.TokenRenewSelfRequest{})
		if err != nil {
			slog.Error("failed to renew vault token", "error", err)
			continue
		}
		slog.Info("vault token renewed", "lease_duration", resp.Auth.LeaseDuration)
	}
}

// startNonceCleanup runs CleanupExpiredNonces periodically.
func startNonceCleanup(db *DB, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		deleted, err := db.CleanupExpiredNonces(ctx)
		cancel()
		if err != nil {
			slog.Error("nonce cleanup failed", "error", err)
		} else if deleted > 0 {
			slog.Info("expired nonces cleaned up", "count", deleted)
		}
	}
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
	nextVersion := 1

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
		// Verify EK certificate if a trust store is configured
		verifier := tpm2.NewVerifier()
		if ekCert := tpmEnroll.GetEkCert(); len(ekCert) > 0 {
			if err := verifier.VerifyEKCertificate(ekCert, s.ekTrustStore); err != nil {
				slog.Warn("EK certificate verification failed", "volume_uuid", volume.UUID, "error", err)
				if s.ekVerifyStrict {
					return nil, status.Errorf(codes.Unauthenticated, "EK certificate verification failed: %v", err)
				}
				slog.Warn("EK verification non-strict: accepting enrollment despite invalid EK cert")
			} else {
				slog.Info("EK certificate verified", "volume_uuid", volume.UUID)
			}
		} else if s.ekVerifyStrict {
			return nil, status.Errorf(codes.InvalidArgument, "EK certificate required but not provided")
		}

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
			KeyVersion:  int32(encryptResp.KeyVersion), // #nosec G115 -- key version from Vault, bounded to small integer
			VaultKvPath: kvPath,
		},
		Version: &api.Version{
			Value: int32(nextVersion), // #nosec G115 -- nextVersion is a DB-incremented counter, bounded well below int32 max
		},
		Volume: &api.Volume{
			Uuid:     volume.UUID,
			LuksUuid: "", // LUKS UUID not available in PostImagingRequest
		},
	}, nil
}
