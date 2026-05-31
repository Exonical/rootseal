#!/bin/sh
# Initialize Vault for development.
#
# This configures the Transit engine used to wrap recovery keys, a KV v2 mount
# for per-volume metadata, a least-privilege policy, and an AppRole the rootseal
# server uses to obtain SHORT-LIVED tokens instead of a long-lived static token.
#
# SECURITY NOTE (documented residual risk): all recovery keys are currently
# wrapped with a single Transit key ("recovery-key"). A fully compromised
# rootseal server could therefore unwrap every volume's key. The policy below is
# written so that migrating to per-volume Transit keys (named "volume-<uuid>")
# requires no policy change. Until that migration lands this remains an accepted,
# documented risk for lab/pilot use only.

set -e

export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=dev-root-token

# Wait for Vault to be ready
sleep 2

# Enable Transit secrets engine
vault secrets enable transit || true

# Create the fleet wrapping key (non-exportable, non-deletable by the server).
vault write -f transit/keys/recovery-key

# Enable KV v2 secrets engine for metadata
vault secrets enable -path=kv kv-v2 || true

# Least-privilege policy for the rootseal server. It can encrypt/decrypt with
# the wrapping key(s) but cannot read key material, rotate, export, or delete
# keys, and is scoped to the volumes/* metadata subtree only.
vault policy write rootseal-server - <<'EOF'
# Wrap/unwrap recovery keys. The glob keeps this forward-compatible with a
# future per-volume key naming scheme (recovery-key, volume-<uuid>, ...).
path "transit/encrypt/recovery-key" {
  capabilities = ["update"]
}
path "transit/decrypt/recovery-key" {
  capabilities = ["update"]
}
path "transit/encrypt/volume-*" {
  capabilities = ["update"]
}
path "transit/decrypt/volume-*" {
  capabilities = ["update"]
}

# Per-volume metadata only. No list at the data plane; no recursive delete.
path "kv/data/volumes/*" {
  capabilities = ["create", "read", "update"]
}
path "kv/metadata/volumes/*" {
  capabilities = ["read"]
}
EOF

# Enable AppRole auth and bind a role to the policy with short-lived tokens.
vault auth enable approle || true
vault write auth/approle/role/rootseal-server \
  token_policies="rootseal-server" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=24h \
  token_num_uses=0

ROLE_ID=$(vault read -field=role_id auth/approle/role/rootseal-server/role-id)
SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/rootseal-server/secret-id)

echo "Vault initialized for development"
echo "AppRole role_id:   $ROLE_ID"
echo "AppRole secret_id: $SECRET_ID"
echo
echo "Start the server with these (preferred over a static token):"
echo "  VAULT_ROLE_ID=$ROLE_ID VAULT_SECRET_ID=$SECRET_ID"
