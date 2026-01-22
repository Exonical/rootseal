package agent

import (
	"context"
	"fmt"

	"github.com/siderolabs/go-blockdevice/v2/encryption"
	"go.uber.org/zap"
)

// LUKSOperator provides Add/Remove operations used in add+remove flow.
type LUKSOperator interface {
	AddKey(ctx context.Context, devname string, key, newKey *encryption.Key) error
	RemoveKey(ctx context.Context, devname string, slot int, key *encryption.Key) error
}

// LUKSChanger provides SetKey used in replace-in-place flow.
type LUKSChanger interface {
	SetKey(ctx context.Context, devname string, oldKey, newKey *encryption.Key) error
}

// ReplaceKeyInPlace replaces the old passphrase with the new one (luksChangeKey equivalent).
func ReplaceKeyInPlace(ctx context.Context, l LUKSChanger, device string, oldKey, newKey *encryption.Key) error {
	if err := l.SetKey(ctx, device, oldKey, newKey); err != nil {
		return fmt.Errorf("replace in place failed: %w", err)
	}
	return nil
}

// AddNewAndRemoveOld adds the new key then removes the old key from slot 0.
// If logger is nil, no debug logging is performed.
func AddNewAndRemoveOld(ctx context.Context, l LUKSOperator, device string, newKey, authKey *encryption.Key, logger *zap.Logger) error {
	if logger != nil {
		logger.Info("AddNewAndRemoveOld called",
			zap.String("device", device),
			zap.Int("newKey.Slot", newKey.Slot),
			zap.Int("newKey.Value.len", len(newKey.Value)),
			zap.Int("authKey.Slot", authKey.Slot),
			zap.Int("authKey.Value.len", len(authKey.Value)),
		)
		logger.Info("calling library AddKey", zap.String("device", device))
	}

	if err := l.AddKey(ctx, device, authKey, newKey); err != nil {
		if logger != nil {
			logger.Error("library AddKey failed", zap.Error(err))
		}
		return fmt.Errorf("add key failed: %w", err)
	}

	if logger != nil {
		logger.Info("library AddKey succeeded")
		logger.Info("calling library RemoveKey", zap.Int("slot", 0))
	}

	// Remove old key from slot 0 using the NEW key to authorize
	if err := l.RemoveKey(ctx, device, 0, newKey); err != nil {
		if logger != nil {
			logger.Error("library RemoveKey failed", zap.Error(err))
		}
		return fmt.Errorf("remove old key failed: %w", err)
	}

	if logger != nil {
		logger.Info("library RemoveKey succeeded")
	}

	return nil
}
