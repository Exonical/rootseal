---
title: Unlock flow
description: The end-to-end enrollment and unlock sequence, from imaging to LUKS open.
---

Rootseal has two phases: a one-time **enrollment** at imaging time, and a
repeated **unlock** during early boot.

## Enrollment (`PostImaging`)

```
agent                                control plane
  │  PostImaging(token, AK, EK, …)       │
  │─────────────────────────────────────►│  verify single-use enrollment token
  │                                       │  verify EK cert chain (if configured)
  │                                       │  bind AK + authorized CN to host
  │                                       │  wrap recovery key via Vault Transit
  │  ◄─────────── wrapped key ────────────│  store wrapped key + pinned policy
```

- Requires a **single-use, high-entropy enrollment token** in production
  (passed in the `x-rootseal-enrollment-token` gRPC header).
- Binds the TPM **Attestation Key (AK)** and the mTLS **CN** to the host.
- Re-enrolling an already-enrolled host with a different AK is rejected
  (`ErrAKRebind`) so trust cannot be silently rebound.

## Unlock (`GetNonce` → `Attest` / `GetKeyWithAttestation`)

```
agent                                control plane
  │  GetNonce()                          │
  │  ◄──────── fresh single-use nonce ───│  store nonce (single use, expiring)
  │                                       │
  │  quote = TPM_Quote(nonce, PCRs)       │  (signed by the AK over selected PCRs)
  │                                       │
  │  GetKeyWithAttestation(quote, PCRs)   │  ─ verify mTLS CN is bound to volume
  │─────────────────────────────────────►│  ─ verify nonce is fresh + unused
  │                                       │  ─ verify quote signature with stored AK
  │                                       │  ─ check TPM_GENERATED magic + AK attrs
  │                                       │  ─ enforce pinned PCR values
  │                                       │  ─ check host not revoked
  │                                       │  ─ unwrap recovery key via Vault
  │  ◄────────── recovery key ────────────│
  │                                       │
  │  cryptsetup open (key via stdin)      │
  ▼                                       │
 LUKS volume opened; key memory wiped
```

Every check fails closed: a missing identity, lookup failure, revoked host,
unbound volume, stale/replayed nonce, bad quote, or PCR mismatch all result in
**no key release**.

## Where secrets live

- The recovery key exists in plaintext only transiently, in the control plane
  (during unwrap) and the agent (during `cryptsetup`); it is wiped from memory
  after use and never logged, persisted, or passed via argv/env.
- At rest, the key is stored **wrapped** (Vault Transit) in Postgres.

See [TPM attestation](../../operations/tpm-attestation/) and
[Vault integration](../../operations/vault/) for the details of each step.
