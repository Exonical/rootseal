---
title: Configuration
description: Environment variables and reference config for the Rootseal control plane.
---

The control plane is configured through **environment variables** (read in
`cmd/controlplane/main.go`). `configs/server.dev.yaml` documents the available
knobs and is a convenient values source for docker-compose, but production
deployments should set the env vars directly and not ship that file.

## Operating mode

| Variable | Default | Meaning |
|---|---|---|
| `ROOTSEAL_PRODUCTION` | `true` | Secure-by-default mode. `false` = explicit, loudly warned dev mode. |
| `ROOTSEAL_ALLOW_INSECURE` | `false` | Permit running without TLS (dev only). |
| `ROOTSEAL_ALLOW_UNATTESTED_GETKEY` | `false` | Permit the legacy unattested key path (dev only; ignored in production). |
| `ROOTSEAL_REQUIRE_ENROLLMENT_TOKEN` | `true` | Require a single-use enrollment token for `PostImaging`. |
| `ROOTSEAL_DEBUG` | `false` | Enable gRPC reflection (forbidden in production). |

## TLS / mTLS

| Variable | Default | Meaning |
|---|---|---|
| `TLS_CERT_FILE` | — | Server certificate. |
| `TLS_KEY_FILE` | — | Server private key. |
| `TLS_CA_FILE` | — | CA bundle used to verify client certificates. |
| `TLS_CLIENT_AUTH` | `true` | Require client certificates (mTLS). |

## TPM / attestation

| Variable | Default | Meaning |
|---|---|---|
| `TPM_REQUIRED_PCRS` | — | Comma-separated PCR indices required in quotes (e.g. `0,2,4,7`). |
| `TPM_ENFORCE_PCR_VALUES` | `false` | Pin/enforce PCR values per volume (forced on in production). |
| `EK_CERT_CA_FILE` | — | TPM manufacturer CA bundle used to verify EK certificates. |
| `EK_VERIFY_STRICT` | `false` | Reject enrollments lacking a verifiable EK certificate. |

## State store (PostgreSQL)

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | `postgres://…sslmode=verify-full` | Postgres DSN. The default uses `sslmode=verify-full`; do not weaken in production. |

## Vault / KMS

| Variable | Default | Meaning |
|---|---|---|
| `VAULT_ADDR` | `https://127.0.0.1:8200` | Vault address. |
| `VAULT_ROLE_ID` / `VAULT_SECRET_ID` | — | AppRole auth (preferred). |
| `VAULT_TOKEN` | — | Static token (dev only). |
| `KMS_PROVIDER` | `vault` | One of `vault`, `aws-kms`, `azure-keyvault`, `fortanix-sdkms`. |
| `KMS_VAULT_TRANSIT_PATH` | `transit` | Transit mount path. |
| `KMS_VAULT_KEY_NAME` | `recovery-key` | Transit wrapping key name. |

The server requires Vault auth: it exits if neither `VAULT_ROLE_ID` nor
`VAULT_TOKEN` is set. See [Vault integration](../vault/) for the least-privilege
policy.

## Reference dev config

`configs/server.dev.yaml` mirrors these settings for the local Compose stack.
Note it sets `ROOTSEAL_PRODUCTION=false` and uses plaintext credentials — it is
for development only.
