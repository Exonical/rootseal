package main

import (
	"log"
	"os"

	"rootseal/internal/controlplane"
	"rootseal/internal/kms"

	// Import KMS providers to register them via init()
	_ "rootseal/internal/kms/aws-kms"
	_ "rootseal/internal/kms/azure-key-vault"
	_ "rootseal/internal/kms/fortanix-sdkms"
	_ "rootseal/internal/kms/vault"
)

func main() {
	// Get configuration from environment variables
	dbConnStr := os.Getenv("DATABASE_URL")
	if dbConnStr == "" {
		dbConnStr = "postgres://rootseal:rootseal@localhost:5432/rootseal?sslmode=verify-full" // #nosec G101 -- dev default, not a production credential
	}

	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "https://127.0.0.1:8200"
	}

	vaultToken := os.Getenv("VAULT_TOKEN")
	if vaultToken == "" {
		log.Fatal("VAULT_TOKEN environment variable is required")
	}

	// TPM PCR policy configuration
	requiredPCRs := os.Getenv("TPM_REQUIRED_PCRS")
	enforcePCRValues := os.Getenv("TPM_ENFORCE_PCR_VALUES") == "true"

	// KMS provider configuration
	// KMS_PROVIDER: "vault" (default), "aws-kms", "azure-keyvault", "fortanix-sdkms"
	kmsProvider := os.Getenv("KMS_PROVIDER")
	if kmsProvider == "" {
		kmsProvider = "vault"
	}

	var kmsCfg *kms.Config
	switch kmsProvider {
	case "vault":
		kmsCfg = &kms.Config{
			Provider: "vault",
			Vault: &kms.VaultConfig{
				Address:     vaultAddr,
				Token:       vaultToken,
				TransitPath: getEnvOrDefault("KMS_VAULT_TRANSIT_PATH", "transit"),
				KeyName:     getEnvOrDefault("KMS_VAULT_KEY_NAME", "recovery-key"),
				Namespace:   os.Getenv("KMS_VAULT_NAMESPACE"),
			},
		}
	case "aws-kms":
		kmsCfg = &kms.Config{
			Provider: "aws-kms",
			AWS: &kms.AWSConfig{
				Region:          getEnvOrDefault("AWS_REGION", "us-east-1"),
				KeyID:           os.Getenv("KMS_AWS_KEY_ID"),
				AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
				SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
				SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
				Endpoint:        os.Getenv("KMS_AWS_ENDPOINT"),
			},
		}
	case "azure-keyvault":
		kmsCfg = &kms.Config{
			Provider: "azure-keyvault",
			Azure: &kms.AzureConfig{
				VaultURL:   os.Getenv("KMS_AZURE_VAULT_URL"),
				KeyName:    os.Getenv("KMS_AZURE_KEY_NAME"),
				KeyVersion: os.Getenv("KMS_AZURE_KEY_VERSION"),
				TenantID:   os.Getenv("AZURE_TENANT_ID"),
				ClientID:   os.Getenv("AZURE_CLIENT_ID"),
			},
		}
	case "fortanix-sdkms":
		kmsCfg = &kms.Config{
			Provider: "fortanix-sdkms",
			Fortanix: &kms.FortanixConfig{
				Endpoint: os.Getenv("KMS_FORTANIX_ENDPOINT"),
				APIKey:   os.Getenv("KMS_FORTANIX_API_KEY"),
				KeyID:    os.Getenv("KMS_FORTANIX_KEY_ID"),
				GroupID:  os.Getenv("KMS_FORTANIX_GROUP_ID"),
			},
		}
	default:
		log.Fatalf("unknown KMS provider: %q", kmsProvider) // #nosec G706 -- %q escapes control characters
	}

	// TLS configuration
	var tlsCfg *controlplane.TLSConfig
	tlsCert := os.Getenv("TLS_CERT_FILE")
	tlsKey := os.Getenv("TLS_KEY_FILE")
	tlsCA := os.Getenv("TLS_CA_FILE")
	if tlsCert != "" && tlsKey != "" {
		tlsCfg = &controlplane.TLSConfig{
			CertFile:   tlsCert,
			KeyFile:    tlsKey,
			CAFile:     tlsCA,
			ClientAuth: os.Getenv("TLS_CLIENT_AUTH") != "false", // default: require mTLS
		}
	} else {
		log.Println("WARNING: TLS_CERT_FILE / TLS_KEY_FILE not set — running WITHOUT TLS (insecure)")
	}

	cfg := controlplane.ServerConfig{
		DatabaseURL:      dbConnStr,
		VaultAddr:        vaultAddr,
		VaultToken:       vaultToken,
		RequiredPCRs:     requiredPCRs,
		EnforcePCRValues: enforcePCRValues,
		KMSProvider:      kmsProvider,
		KMSConfig:        kmsCfg,
		TLS:              tlsCfg,
		Debug:            os.Getenv("ROOTSEAL_DEBUG") == "true",
	}

	if err := controlplane.NewServerWithConfig(cfg); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}
