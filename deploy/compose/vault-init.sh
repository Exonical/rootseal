#!/bin/sh
# Initialize Vault for development

export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=dev-root-token

# Wait for Vault to be ready
sleep 2

# Enable Transit secrets engine
vault secrets enable transit

# Create a key for wrapping recovery keys
vault write -f transit/keys/recovery-key

# Enable KV v2 secrets engine for metadata
vault secrets enable -path=kv kv-v2

# Create a policy for the rootseal server
vault policy write rootseal-server - <<EOF
# Transit engine permissions
path "transit/encrypt/recovery-key" {
  capabilities = ["create", "update"]
}

path "transit/decrypt/recovery-key" {
  capabilities = ["create", "update"]
}

path "transit/keys/recovery-key" {
  capabilities = ["read"]
}

# KV v2 permissions for metadata
path "kv/data/volumes/*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "kv/metadata/volumes/*" {
  capabilities = ["list", "read", "delete"]
}
EOF

# Create a token for the server
vault token create -policy=rootseal-server -ttl=24h -display-name=rootseal-server

echo "Vault initialized for development"
