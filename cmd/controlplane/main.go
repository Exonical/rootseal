package main

import (
	"log"
	"os"

	"rootseal/internal/controlplane"
)

func main() {
	// Get configuration from environment variables
	dbConnStr := os.Getenv("DATABASE_URL")
	if dbConnStr == "" {
		dbConnStr = "postgres://rootseal:rootseal@localhost:5432/rootseal?sslmode=disable"
	}

	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "http://127.0.0.1:8200"
	}

	vaultToken := os.Getenv("VAULT_TOKEN")
	if vaultToken == "" {
		vaultToken = "dev-root-token"
	}

	// TPM PCR policy configuration
	// TPM_REQUIRED_PCRS: comma-separated list of PCR indices (default: "0,2,7,11")
	// TPM_ENFORCE_PCR_VALUES: if "true", reject quotes with unexpected PCR values
	requiredPCRs := os.Getenv("TPM_REQUIRED_PCRS")
	enforcePCRValues := os.Getenv("TPM_ENFORCE_PCR_VALUES") == "true"

	cfg := controlplane.ServerConfig{
		DatabaseURL:      dbConnStr,
		VaultAddr:        vaultAddr,
		VaultToken:       vaultToken,
		RequiredPCRs:     requiredPCRs,
		EnforcePCRValues: enforcePCRValues,
	}

	if err := controlplane.NewServerWithConfig(cfg); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
