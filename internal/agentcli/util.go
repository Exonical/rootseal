package agentcli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"

	"github.com/siderolabs/go-blockdevice/v2/block"
)

// SystemInfo holds system identification data for enrollment
type SystemInfo struct {
	Hostname string
	Username string
	Serial   string
	Labels   map[string]string
}

// GatherSystemInfo collects hostname, username, and device serial/model
func GatherSystemInfo(devicePath string) (*SystemInfo, error) {
	info := &SystemInfo{
		Labels: make(map[string]string),
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %w", err)
	}
	info.Hostname = hostname

	currentUser, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("failed to get current user: %w", err)
	}
	info.Username = currentUser.Username

	// Get device properties (serial, model, wwid) from go-blockdevice
	dev, err := block.NewFromPath(devicePath)
	if err != nil {
		// Non-fatal: fall back to empty serial
		log.Printf("Warning: failed to open block device %s: %v", devicePath, err)
		info.Serial = ""
	} else {
		defer dev.Close()

		// Try to get the whole disk for partition devices (e.g., /dev/sda1 -> /dev/sda)
		wholeDisk, err := dev.GetWholeDisk()
		if err == nil && wholeDisk != nil {
			defer wholeDisk.Close()
			dev = wholeDisk
		}

		props, err := dev.GetProperties()
		if err != nil {
			log.Printf("Warning: failed to get device properties: %v", err)
			info.Serial = ""
		} else {
			// Prefer serial, fall back to WWID, then model
			if props.Serial != "" {
				info.Serial = props.Serial
			} else if props.WWID != "" {
				info.Serial = props.WWID
			} else if props.Model != "" {
				info.Serial = props.Model
			}

			// Add additional device info to labels
			if props.Model != "" {
				info.Labels["device_model"] = props.Model
			}
			if props.Transport != "" {
				info.Labels["device_transport"] = props.Transport
			}
		}
	}

	return info, nil
}

// SecureZero wipes a byte slice
func SecureZero(s []byte) {
	for i := range s {
		s[i] = 0
	}
}

// WriteJSON0600 writes JSON to a file with 0600 permissions
func WriteJSON0600(dir, filename string, v any) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return err
	}
	return nil
}
