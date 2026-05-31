---
title: Architecture
description: The components of Rootseal, their trust boundaries, and how they interact.
---

Rootseal has two binaries — a host-side **agent** and a central **control
plane** — backed by PostgreSQL for state and HashiCorp Vault for key wrapping.

## Components

```
        early boot / initramfs                         data center
 ┌───────────────────────────────┐        ┌──────────────────────────────────┐
 │  host                          │        │  control plane                   │
 │  ┌──────────┐   TPM 2.0        │  mTLS  │  rootseal-controlplane (gRPC)    │
 │  │  rootseal│◄──quote/PCRs     │◄──────►│  ┌────────────┐  ┌─────────────┐ │
 │  │  (agent) │                  │ gRPC   │  │ attestation│  │ authz (CN → │ │
 │  └────┬─────┘                  │        │  │  verify    │  │   volume)   │ │
 │       │ cryptsetup (stdin)     │        │  └─────┬──────┘  └──────┬──────┘ │
 │  ┌────▼─────┐                  │        │        │                │        │
 │  │ LUKS vol │                  │        │     ┌──▼────┐      ┌────▼─────┐  │
 │  └──────────┘                  │        │     │ Vault │      │ Postgres │  │
 └───────────────────────────────┘        │     │Transit│      │  state   │  │
                                           │     └───────┘      └──────────┘  │
                                           └──────────────────────────────────┘
```

| Component | Binary / image | Responsibility |
|---|---|---|
| Agent | `rootseal` | Runs at imaging time and during early boot. Enrolls the host, produces TPM quotes, requests keys, and feeds them to `cryptsetup` via stdin. |
| Control plane | `rootseal-controlplane` | gRPC server. Verifies attestation, enforces per-host authorization, and wraps/unwraps keys via the KMS. Hosts admin subcommands (`mint-enrollment-token`, `revoke-host`). |
| State store | PostgreSQL | Enrolled hosts, attestation keys (AK), authorized CNs, pinned PCR values, single-use enrollment tokens, wrapped keys, revocation state. |
| KMS | HashiCorp Vault (default) | Transit engine wraps/unwraps recovery keys; KV stores per-volume metadata. Pluggable: `aws-kms`, `azure-keyvault`, `fortanix-sdkms`. |

The agent ships as dracut/initramfs and systemd integration (`deploy/dracut`,
`deploy/initramfs`, `deploy/systemd`) so unlocking happens automatically before
the root filesystem is mounted.

## gRPC services

Defined in `pkg/api`:

- **`LuksManager`** — `GetNonce`, `Attest`, `GetKeyWithAttestation`, and the
  legacy `GetKey` (disabled by default; see [Security model](../security-model/)).
- **`AgentService`** — `PostImaging` for enrollment/escrow.

## Trust boundaries

1. **Host ↔ control plane** — crosses the network. Protected by mTLS; the
   client certificate's CN is the host's network identity and is bound to the
   volume at enrollment.
2. **TPM ↔ agent** — the TPM is the hardware root of trust. The agent cannot
   forge a quote; the AK is TPM-resident and its attributes are validated
   server-side.
3. **Control plane ↔ Vault** — the server authenticates with a short-lived,
   least-privilege AppRole and can only wrap/unwrap with the recovery key(s).
4. **Control plane ↔ Postgres** — authoritative store of identity and policy;
   all authorization decisions are made here, server-side.

See the [Unlock flow](../unlock-flow/) for the end-to-end sequence and the
[Security model](../security-model/) for the enforced guarantees.
