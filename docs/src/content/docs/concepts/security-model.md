---
title: Security model
description: The guarantees Rootseal enforces, its secure defaults, and documented residual risks.
---

Rootseal handles highly sensitive key material and may run in early
boot/initramfs. This page summarizes the enforced model; the authoritative
source is [`SECURITY.md`](https://github.com/Exonical/rootseal/blob/main/SECURITY.md)
in the repository.

## Secure by default

The server runs in **production mode by default** and **fails closed** on
insecure configuration. Set `ROOTSEAL_PRODUCTION=false` only for an explicit,
loudly warned dev/lab stack.

Production mode requires all of the following, or the server refuses to start:

- mTLS with client-certificate verification (`TLS_CLIENT_AUTH=true`, `TLS_CA_FILE` set)
- A non-empty PCR policy (`TPM_REQUIRED_PCRS`)
- PCR value enforcement (forced on; per-volume PCRs pinned trust-on-first-use)
- Vault authentication (`VAULT_ROLE_ID`/`VAULT_SECRET_ID` preferred, or `VAULT_TOKEN`)
- The unattested `GetKey` path disabled
- gRPC reflection disabled (`ROOTSEAL_DEBUG` unset)

## Identity and authorization

- Each host has its own mTLS client certificate with a **unique CN**. At
  enrollment the CN is bound to the host (`AuthorizedCN`); key release requires
  the requesting mTLS identity to match the bound CN (constant-time compare).
- One host **cannot** obtain another host's key.
- Authorization is enforced server-side on every unlock RPC and fails closed on
  missing identity, lookup failure, revoked host, unbound volume, or mismatch.
- Authorization is bound to **cryptographic TPM identity**, never to mutable
  metadata (hostname, UUID, MAC, serial).

## TPM attestation

- Every attestation uses a **fresh, single-use server nonce**; replayed or stale
  nonces are rejected.
- Quotes are verified against the nonce and selected PCRs, and the quote's
  `TPM_GENERATED_VALUE` magic is checked.
- AK object attributes are validated (FixedTPM, FixedParent, Restricted, Sign,
  not Decrypt) so software keys cannot masquerade as TPM-resident AKs.
- When `EK_CERT_CA_FILE` is set, the EK certificate chain is verified to a
  trusted manufacturer CA; `EK_VERIFY_STRICT=true` requires it.
- PCR values are pinned per volume on first successful attestation and enforced
  thereafter (trust-on-first-use).

## Key handling

- Disk keys are never logged, written to disk, placed in argv/env, or printed.
- `rootseal unseal --key-only` writes raw key bytes to stdout for piping into
  `cryptsetup` stdin; without `--key-only` the key is never rendered. Key memory
  is wiped after use.

## Vault least-privilege

- The server authenticates with a short-lived AppRole token (`token_ttl=1h`,
  auto-renewed), not a long-lived static token.
- The `rootseal-server` policy can only encrypt/decrypt with the wrapping key(s)
  and read its own `volumes/*` metadata — it cannot read, export, rotate, or
  delete Transit keys.

## Documented residual risks

- **Single fleet Transit key:** all recovery keys are currently wrapped with one
  Transit key, so a fully compromised server could unwrap every volume's key.
  Migrating to per-volume Transit keys (the policy already allows `volume-*`) is
  the recommended next step. Acceptable for lab/pilot only.
- **Full TPM credential activation** (`MakeCredential`/`ActivateCredential`) and
  live-TPM end-to-end validation require a real TPM/swtpm and are not exercised
  by the unit tests; the server-side verification logic is implemented and unit
  tested against synthetic quotes.
