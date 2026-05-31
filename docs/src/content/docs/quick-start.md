---
title: Quick start (local stack)
description: Bring up Postgres, Vault, and the Rootseal control plane locally with Docker Compose.
---

This brings up a **non-production** local stack — PostgreSQL, a dev Vault, and
the Rootseal control plane — using the Compose file in `deploy/compose/`. It is
useful for development and exploration only.

:::danger[Dev mode only]
This stack sets `ROOTSEAL_PRODUCTION=false`, uses a plaintext Postgres/Vault, a
dev root token, and enables gRPC reflection. Never use these settings in
production. See the [Security model](../concepts/security-model/).
:::

## Prerequisites

- Docker + Docker Compose
- OpenSSL (for the throwaway dev certificates)
- Go 1.26.3 if you want to build the binaries outside containers

## 1. Generate development certificates

Each host needs its own agent certificate with a **unique CN** — a shared CN
would let any host unlock any volume. The script writes certs to `certs/`:

```sh
./scripts/mkcerts.sh agent01.example.com
```

## 2. Bring up the stack

```sh
cd deploy/compose
docker compose up --build
```

This starts:

- **postgres** (`postgres:17-alpine`) — state store
- **vault** (`hashicorp/vault:1.20`, dev mode) — `vault-init.sh` configures the
  Transit engine, AppRole, and the least-privilege `rootseal-server` policy
- **rootseal-server** — the control plane, listening on `0.0.0.0:50051`

The server reads its configuration from environment variables (documented in
[Configuration](../operations/configuration/)); `configs/server.dev.yaml` is a
reference for the available knobs.

## 3. Exercise the agent

From an imaged host, the agent enrolls and then unlocks. In production you would
mint a single-use enrollment token first (see [Enrollment](../operations/enrollment/)),
but the dev stack sets `ROOTSEAL_REQUIRE_ENROLLMENT_TOKEN=false` for convenience:

```sh
# Enroll the host and escrow a wrapped recovery key
rootseal postimaging --server localhost:50051 ...

# Later, during early boot, fetch + apply the key
rootseal unlock --server localhost:50051 ...
```

See the [CLI reference](../reference/cli/) for the full set of agent and admin
commands, and the [Unlock flow](../concepts/unlock-flow/) for what happens on the
wire.
