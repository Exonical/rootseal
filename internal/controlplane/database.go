package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// HashEnrollmentToken returns the SHA-256 hash of an enrollment token. Only the
// hash is ever persisted or compared, so the plaintext token never touches the
// database or logs.
func HashEnrollmentToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// DB represents database operations
type DB struct {
	conn *gorm.DB
}

// Agent represents an agent record.
//
// AuthorizedCN binds the agent (and therefore its volumes) to a single mTLS
// client identity (certificate Common Name) established at enrollment time.
// Key release is authorized against this value, so one host cannot request
// another host's key even with a valid certificate. Revoked marks a host as
// decommissioned; revoked hosts are refused all key access.
type Agent struct {
	ID           uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Hostname     string          `gorm:"uniqueIndex:idx_agent_hostname_serial;not null" json:"hostname"`
	Serial       string          `gorm:"uniqueIndex:idx_agent_hostname_serial" json:"serial"`
	AuthorizedCN string          `gorm:"index" json:"authorized_cn"`
	Revoked      bool            `gorm:"not null;default:false" json:"revoked"`
	Labels       json.RawMessage `gorm:"type:jsonb;default:'{}'" json:"labels"`
	LastSeen     time.Time       `gorm:"not null;default:now()" json:"last_seen"`
	CreatedAt    time.Time       `gorm:"autoCreateTime" json:"created_at"`
}

// Volume represents a volume record
type Volume struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	AgentID    uuid.UUID `gorm:"type:uuid;uniqueIndex:idx_volume_agent_device;not null" json:"agent_id"`
	DevicePath string    `gorm:"uniqueIndex:idx_volume_agent_device;not null" json:"device_path"`
	UUID       string    `gorm:"uniqueIndex;not null" json:"uuid"`
	CreatedAt  time.Time `gorm:"autoCreateTime" json:"created_at"`
	Agent      *Agent    `gorm:"foreignKey:AgentID" json:"-"`
}

// KeyVersion represents a key version record
type KeyVersion struct {
	ID         uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	VolumeID   uuid.UUID `gorm:"type:uuid;uniqueIndex:idx_keyversion_volume_version;not null" json:"volume_id"`
	Version    int       `gorm:"uniqueIndex:idx_keyversion_volume_version;not null" json:"version"`
	VaultKeyID string    `gorm:"not null" json:"vault_key_id"`
	WrappedKey string    `gorm:"not null" json:"wrapped_key"`
	CreatedAt  time.Time `gorm:"autoCreateTime" json:"created_at"`
	Volume     *Volume   `gorm:"foreignKey:VolumeID" json:"-"`
}

// TPMEnrollment represents a TPM enrollment record.
//
// PinnedPCRs holds the expected PCR digests for this volume (JSON map of PCR
// index -> hex digest). It is populated on first successful attestation when
// PCR value enforcement is enabled, and subsequent unlocks must match it.
type TPMEnrollment struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	VolumeID   uuid.UUID `gorm:"type:uuid;uniqueIndex;not null" json:"volume_id"`
	EKPublic   []byte    `json:"ek_public"`
	EKCert     []byte    `json:"ek_cert"`
	AKPublic   []byte    `gorm:"not null" json:"ak_public"`
	AKName     []byte    `gorm:"not null" json:"ak_name"`
	PinnedPCRs []byte    `json:"pinned_pcrs"`
	CreatedAt  time.Time `gorm:"autoCreateTime" json:"created_at"`
	Volume     *Volume   `gorm:"foreignKey:VolumeID" json:"-"`
}

// EnrollmentToken is a single-use, high-entropy credential required to enroll
// a host via PostImaging. Only the SHA-256 hash of the token is stored; the
// plaintext is shown once at creation time and never logged. BoundCN, when
// set, restricts the token to a specific mTLS client identity.
type EnrollmentToken struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	TokenHash []byte     `gorm:"uniqueIndex;not null" json:"-"`
	BoundCN   string     `json:"bound_cn"`
	ExpiresAt time.Time  `gorm:"not null" json:"expires_at"`
	UsedAt    *time.Time `json:"used_at"`
	CreatedAt time.Time  `gorm:"autoCreateTime" json:"created_at"`
}

// AttestationNonce represents a nonce for replay protection
type AttestationNonce struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	VolumeID  uuid.UUID  `gorm:"type:uuid;not null" json:"volume_id"`
	Nonce     []byte     `gorm:"uniqueIndex;not null" json:"nonce"`
	CreatedAt time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UsedAt    *time.Time `json:"used_at"`
	Volume    *Volume    `gorm:"foreignKey:VolumeID" json:"-"`
}

// NewDB creates a new database connection with GORM
func NewDB(dsn string) (*DB, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)
	sqlDB.SetConnMaxIdleTime(1 * time.Minute)

	// Auto-migrate schema
	if err := db.AutoMigrate(&Agent{}, &Volume{}, &KeyVersion{}, &TPMEnrollment{}, &AttestationNonce{}, &EnrollmentToken{}); err != nil {
		return nil, fmt.Errorf("failed to auto-migrate: %w", err)
	}

	return &DB{conn: db}, nil
}

// Close closes the database connection
func (db *DB) Close() error {
	sqlDB, err := db.conn.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// UpsertAgent creates or updates an agent record. authorizedCN is the mTLS
// client identity that is permitted to retrieve this agent's keys. On update
// the binding is only (re)set when authorizedCN is non-empty so that an
// unauthenticated/dev caller cannot clear an existing binding.
func (db *DB) UpsertAgent(ctx context.Context, hostname, serial, authorizedCN string, labels json.RawMessage) (*Agent, error) {
	agent := Agent{
		Hostname:     hostname,
		Serial:       serial,
		AuthorizedCN: authorizedCN,
		Labels:       labels,
		LastSeen:     time.Now(),
	}

	// Try to find existing agent
	var existing Agent
	err := db.conn.WithContext(ctx).Where("hostname = ? AND serial = ?", hostname, serial).First(&existing).Error
	if err == nil {
		// Update existing
		existing.Labels = labels
		existing.LastSeen = time.Now()
		if authorizedCN != "" {
			existing.AuthorizedCN = authorizedCN
		}
		if err := db.conn.WithContext(ctx).Save(&existing).Error; err != nil {
			return nil, fmt.Errorf("failed to update agent: %w", err)
		}
		return &existing, nil
	} else if errors.Is(err, gorm.ErrRecordNotFound) {
		// Create new
		if err := db.conn.WithContext(ctx).Create(&agent).Error; err != nil {
			return nil, fmt.Errorf("failed to create agent: %w", err)
		}
		return &agent, nil
	}
	return nil, fmt.Errorf("failed to upsert agent: %w", err)
}

// GetAgent retrieves an agent by ID.
func (db *DB) GetAgent(ctx context.Context, agentID uuid.UUID) (*Agent, error) {
	var agent Agent
	err := db.conn.WithContext(ctx).Where("id = ?", agentID).First(&agent).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("agent not found")
		}
		return nil, fmt.Errorf("failed to get agent: %w", err)
	}
	return &agent, nil
}

// SetAgentRevoked marks an agent (by hostname+serial) as revoked or active.
// Revoked agents are refused all key access. Used for host decommissioning.
func (db *DB) SetAgentRevoked(ctx context.Context, hostname, serial string, revoked bool) error {
	result := db.conn.WithContext(ctx).
		Model(&Agent{}).
		Where("hostname = ? AND serial = ?", hostname, serial).
		Update("revoked", revoked)
	if result.Error != nil {
		return fmt.Errorf("failed to update agent revocation: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("agent not found")
	}
	return nil
}

// UpsertVolume creates or updates a volume record
func (db *DB) UpsertVolume(ctx context.Context, agentID uuid.UUID, devicePath, volumeUUID string) (*Volume, error) {
	volume := Volume{
		AgentID:    agentID,
		DevicePath: devicePath,
		UUID:       volumeUUID,
	}

	// Try to find existing volume
	var existing Volume
	err := db.conn.WithContext(ctx).Where("agent_id = ? AND device_path = ?", agentID, devicePath).First(&existing).Error
	if err == nil {
		// Update existing
		existing.UUID = volumeUUID
		if err := db.conn.WithContext(ctx).Save(&existing).Error; err != nil {
			return nil, fmt.Errorf("failed to update volume: %w", err)
		}
		return &existing, nil
	} else if errors.Is(err, gorm.ErrRecordNotFound) {
		// Create new
		if err := db.conn.WithContext(ctx).Create(&volume).Error; err != nil {
			return nil, fmt.Errorf("failed to create volume: %w", err)
		}
		return &volume, nil
	}
	return nil, fmt.Errorf("failed to upsert volume: %w", err)
}

// CreateKeyVersion creates a new key version record
func (db *DB) CreateKeyVersion(ctx context.Context, volumeID uuid.UUID, version int, vaultKeyID, wrappedKey string) (*KeyVersion, error) {
	keyVersion := KeyVersion{
		VolumeID:   volumeID,
		Version:    version,
		VaultKeyID: vaultKeyID,
		WrappedKey: wrappedKey,
	}

	if err := db.conn.WithContext(ctx).Create(&keyVersion).Error; err != nil {
		return nil, fmt.Errorf("failed to create key version: %w", err)
	}

	return &keyVersion, nil
}

// GetLatestKeyVersion gets the latest key version for a volume
func (db *DB) GetLatestKeyVersion(ctx context.Context, volumeID uuid.UUID) (*KeyVersion, error) {
	var keyVersion KeyVersion
	err := db.conn.WithContext(ctx).
		Where("volume_id = ?", volumeID).
		Order("version DESC").
		First(&keyVersion).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get latest key version: %w", err)
	}
	return &keyVersion, nil
}

// GetVolumeByDevicePath gets a volume by agent ID and device path
func (db *DB) GetVolumeByDevicePath(ctx context.Context, agentID uuid.UUID, devicePath string) (*Volume, error) {
	var volume Volume
	err := db.conn.WithContext(ctx).
		Where("agent_id = ? AND device_path = ?", agentID, devicePath).
		First(&volume).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get volume: %w", err)
	}
	return &volume, nil
}

// GetVolumeByUUID gets a volume by its UUID
func (db *DB) GetVolumeByUUID(ctx context.Context, volumeUUID string) (*Volume, error) {
	var volume Volume
	err := db.conn.WithContext(ctx).
		Where("uuid = ?", volumeUUID).
		First(&volume).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("volume not found")
		}
		return nil, fmt.Errorf("failed to get volume: %w", err)
	}
	return &volume, nil
}

// GetKeyVersion gets a specific key version for a volume (0 = latest)
func (db *DB) GetKeyVersion(ctx context.Context, volumeID uuid.UUID, version int) (*KeyVersion, error) {
	var keyVersion KeyVersion
	query := db.conn.WithContext(ctx).Where("volume_id = ?", volumeID)

	if version == 0 {
		query = query.Order("version DESC")
	} else {
		query = query.Where("version = ?", version)
	}

	err := query.First(&keyVersion).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("key version not found")
		}
		return nil, fmt.Errorf("failed to get key version: %w", err)
	}
	return &keyVersion, nil
}

// ErrAKRebind is returned when an enrollment attempts to replace an existing
// Attestation Key with a different one. Rebinding the AK would let an attacker
// re-root the volume's trust, so it is refused.
var ErrAKRebind = errors.New("TPM AK rebind not allowed: volume already enrolled with a different AK")

// CreateTPMEnrollment stores TPM enrollment data for a volume.
//
// The Attestation Key is immutable once set: if an enrollment already exists
// with a different AKPublic, the call fails with ErrAKRebind. Re-enrolling with
// the identical AK is permitted (idempotent) and refreshes the EK material.
func (db *DB) CreateTPMEnrollment(ctx context.Context, volumeID uuid.UUID, ekPublic, ekCert, akPublic, akName []byte) (*TPMEnrollment, error) {
	enrollment := TPMEnrollment{
		VolumeID: volumeID,
		EKPublic: ekPublic,
		EKCert:   ekCert,
		AKPublic: akPublic,
		AKName:   akName,
	}

	var existing TPMEnrollment
	err := db.conn.WithContext(ctx).Where("volume_id = ?", volumeID).First(&existing).Error
	if err == nil {
		// An enrollment already exists. Refuse to rebind to a different AK.
		if !bytes.Equal(existing.AKPublic, akPublic) {
			return nil, ErrAKRebind
		}
		existing.EKPublic = ekPublic
		existing.EKCert = ekCert
		existing.AKName = akName
		if err := db.conn.WithContext(ctx).Save(&existing).Error; err != nil {
			return nil, fmt.Errorf("failed to update TPM enrollment: %w", err)
		}
		return &existing, nil
	} else if errors.Is(err, gorm.ErrRecordNotFound) {
		if err := db.conn.WithContext(ctx).Create(&enrollment).Error; err != nil {
			return nil, fmt.Errorf("failed to create TPM enrollment: %w", err)
		}
		return &enrollment, nil
	}
	return nil, fmt.Errorf("failed to create TPM enrollment: %w", err)
}

// PinTPMEnrollmentPCRs stores the expected PCR digests for a volume (used for
// trust-on-first-use PCR value enforcement).
func (db *DB) PinTPMEnrollmentPCRs(ctx context.Context, volumeID uuid.UUID, pinnedPCRs []byte) error {
	result := db.conn.WithContext(ctx).
		Model(&TPMEnrollment{}).
		Where("volume_id = ?", volumeID).
		Update("pinned_pcrs", pinnedPCRs)
	if result.Error != nil {
		return fmt.Errorf("failed to pin PCRs: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("no TPM enrollment found for volume")
	}
	return nil
}

// GetTPMEnrollment retrieves TPM enrollment for a volume
func (db *DB) GetTPMEnrollment(ctx context.Context, volumeID uuid.UUID) (*TPMEnrollment, error) {
	var enrollment TPMEnrollment
	err := db.conn.WithContext(ctx).
		Where("volume_id = ?", volumeID).
		First(&enrollment).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get TPM enrollment: %w", err)
	}
	return &enrollment, nil
}

// CreateNonce creates a new attestation nonce
func (db *DB) CreateNonce(ctx context.Context, volumeID uuid.UUID, nonce []byte) error {
	attestNonce := AttestationNonce{
		VolumeID: volumeID,
		Nonce:    nonce,
	}
	if err := db.conn.WithContext(ctx).Create(&attestNonce).Error; err != nil {
		return fmt.Errorf("failed to create nonce: %w", err)
	}
	return nil
}

// ValidateAndConsumeNonce checks if a nonce is valid and marks it as used
func (db *DB) ValidateAndConsumeNonce(ctx context.Context, volumeID uuid.UUID, nonce []byte) error {
	now := time.Now()
	fiveMinutesAgo := now.Add(-5 * time.Minute)

	result := db.conn.WithContext(ctx).
		Model(&AttestationNonce{}).
		Where("volume_id = ? AND nonce = ? AND used_at IS NULL AND created_at > ?", volumeID, nonce, fiveMinutesAgo).
		Update("used_at", now)

	if result.Error != nil {
		return fmt.Errorf("failed to validate nonce: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("nonce invalid, expired, or already used")
	}
	return nil
}

// CreateEnrollmentToken stores the hash of a new single-use enrollment token.
// boundCN may be empty to allow any client identity. ttl sets the validity
// window.
func (db *DB) CreateEnrollmentToken(ctx context.Context, tokenHash []byte, boundCN string, ttl time.Duration) error {
	tok := EnrollmentToken{
		TokenHash: tokenHash,
		BoundCN:   boundCN,
		ExpiresAt: time.Now().Add(ttl),
	}
	if err := db.conn.WithContext(ctx).Create(&tok).Error; err != nil {
		return fmt.Errorf("failed to create enrollment token: %w", err)
	}
	return nil
}

// ConsumeEnrollmentToken atomically validates and marks an enrollment token as
// used. It fails closed if the token is unknown, expired, already used, or
// bound to a different client identity. The single UPDATE guarantees a token
// can be consumed at most once even under concurrent requests.
func (db *DB) ConsumeEnrollmentToken(ctx context.Context, tokenHash []byte, cn string) error {
	now := time.Now()
	result := db.conn.WithContext(ctx).
		Model(&EnrollmentToken{}).
		Where("token_hash = ? AND used_at IS NULL AND expires_at > ? AND (bound_cn = '' OR bound_cn = ?)", tokenHash, now, cn).
		Update("used_at", now)
	if result.Error != nil {
		return fmt.Errorf("failed to consume enrollment token: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("enrollment token invalid, expired, already used, or not authorized")
	}
	return nil
}

// CleanupExpiredNonces removes old nonces (older than 10 minutes)
func (db *DB) CleanupExpiredNonces(ctx context.Context) (int64, error) {
	tenMinutesAgo := time.Now().Add(-10 * time.Minute)
	result := db.conn.WithContext(ctx).
		Where("created_at < ?", tenMinutesAgo).
		Delete(&AttestationNonce{})
	if result.Error != nil {
		return 0, fmt.Errorf("failed to cleanup nonces: %w", result.Error)
	}
	return result.RowsAffected, nil
}
