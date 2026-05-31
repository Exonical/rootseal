---
title: Vault integration
description: How Rootseal wraps disk keys with Vault Transit using a least-privilege AppRole.
---

By default Rootseal uses HashiCorp Vault as its key management service
(`KMS_PROVIDER=vault`). Recovery keys are **wrapped** with the Vault Transit
engine and stored wrapped in Postgres — never in plaintext at rest.

## Authentication

- The server authenticates with a **short-lived AppRole token** (`token_ttl=1h`,
  auto-renewed) rather than a long-lived static token.
- `VAULT_ROLE_ID` + `VAULT_SECRET_ID` are preferred. `VAULT_TOKEN` is supported
  for dev only. The server refuses to start without one of these.

## Least-privilege policy

The `rootseal-server` policy:

- can `encrypt`/`decrypt` with the wrapping key(s) only,
- can read its own `volumes/*` metadata,
- **cannot** read, export, rotate, or delete Transit keys,
- is forward-compatible with **per-volume** Transit keys (`volume-<uuid>`).

The dev stack's `deploy/compose/vault-init.sh` configures the Transit engine,
the AppRole, and this policy, and prints the generated `role_id`/`secret_id`.

## Fail-closed behavior

If Vault is unavailable or denies the request, the server **does not unlock** and
does not cache keys insecurely. Vault tokens are never logged or exposed.

## Other KMS providers

`KMS_PROVIDER` can also be `aws-kms`, `azure-keyvault`, or `fortanix-sdkms`;
each has its own settings (see [Configuration](../configuration/)). The provider
is selected at startup via registered `init()` hooks in `internal/kms`.

## Residual risk: single fleet key

All recovery keys are currently wrapped with a **single** Transit key
(`recovery-key`), so a fully compromised server could unwrap every volume's key.
The policy already allows per-volume `volume-*` keys; migrating to per-volume
keys is the recommended hardening step and is documented as a lab/pilot-only
acceptance in the [Security model](../../concepts/security-model/).
