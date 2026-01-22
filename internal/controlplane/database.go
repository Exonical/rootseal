package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DB represents database operations
type DB struct {
	conn *gorm.DB
}

// Agent represents an agent record
type Agent struct {
	ID        uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Hostname  string          `gorm:"uniqueIndex:idx_agent_hostname_serial;not null" json:"hostname"`
	Serial    string          `gorm:"uniqueIndex:idx_agent_hostname_serial" json:"serial"`
	Labels    json.RawMessage `gorm:"type:jsonb;default:'{}'" json:"labels"`
	LastSeen  time.Time       `gorm:"not null;default:now()" json:"last_seen"`
	CreatedAt time.Time       `gorm:"autoCreateTime" json:"created_at"`
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

// TPMEnrollment represents a TPM enrollment record
type TPMEnrollment struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	VolumeID  uuid.UUID `gorm:"type:uuid;uniqueIndex;not null" json:"volume_id"`
	EKPublic  []byte    `json:"ek_public"`
	EKCert    []byte    `json:"ek_cert"`
	AKPublic  []byte    `gorm:"not null" json:"ak_public"`
	AKName    []byte    `gorm:"not null" json:"ak_name"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	Volume    *Volume   `gorm:"foreignKey:VolumeID" json:"-"`
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
	if err := db.AutoMigrate(&Agent{}, &Volume{}, &KeyVersion{}, &TPMEnrollment{}, &AttestationNonce{}); err != nil {
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

// UpsertAgent creates or updates an agent record
func (db *DB) UpsertAgent(ctx context.Context, hostname, serial string, labels json.RawMessage) (*Agent, error) {
	agent := Agent{
		Hostname: hostname,
		Serial:   serial,
		Labels:   labels,
		LastSeen: time.Now(),
	}

	// Try to find existing agent
	var existing Agent
	err := db.conn.WithContext(ctx).Where("hostname = ? AND serial = ?", hostname, serial).First(&existing).Error
	if err == nil {
		// Update existing
		existing.Labels = labels
		existing.LastSeen = time.Now()
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

// CreateTPMEnrollment stores TPM enrollment data for a volume
func (db *DB) CreateTPMEnrollment(ctx context.Context, volumeID uuid.UUID, ekPublic, ekCert, akPublic, akName []byte) (*TPMEnrollment, error) {
	enrollment := TPMEnrollment{
		VolumeID: volumeID,
		EKPublic: ekPublic,
		EKCert:   ekCert,
		AKPublic: akPublic,
		AKName:   akName,
	}

	// Upsert: update if exists, create if not
	var existing TPMEnrollment
	err := db.conn.WithContext(ctx).Where("volume_id = ?", volumeID).First(&existing).Error
	if err == nil {
		// Update existing
		existing.EKPublic = ekPublic
		existing.EKCert = ekCert
		existing.AKPublic = akPublic
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
