---
title: Enrollment
description: Securely enrolling hosts with single-use tokens, AK binding, and revocation.
---

Enrollment (`PostImaging`) is how a freshly imaged host establishes trust with
the control plane. It must prevent **rogue self-enrollment**.

## Single-use enrollment tokens

In production (`ROOTSEAL_REQUIRE_ENROLLMENT_TOKEN=true`, the default),
`PostImaging` requires a single-use, high-entropy enrollment token. Mint one
out-of-band and deliver it to the host being provisioned:

```sh
rootseal-controlplane mint-enrollment-token -cn host01.example.com -ttl 15m
```

- Only the **SHA-256 hash** is stored; the plaintext is printed once and never logged.
- Tokens are **single-use** (atomically consumed), expiring, and optionally
  bound to a CN.
- The agent passes the token via the gRPC metadata header
  `x-rootseal-enrollment-token`.

## AK binding and rebind protection

At enrollment the TPM **Attestation Key (AK)** and the mTLS **CN** are bound to
the host. Re-enrolling an already-enrolled host with a **different AK** is
rejected (`ErrAKRebind`), preventing an attacker from silently rebinding trust
to a key they control.

## Host revocation

A revoked host is refused at key release even with a valid certificate:

```sh
# Revoke
rootseal-controlplane revoke-host -hostname host01 -serial ABC123

# Un-revoke
rootseal-controlplane revoke-host -hostname host01 -serial ABC123 -unrevoke
```

## Certificates

Each host must have its own agent certificate with a **unique CN**. Use
`scripts/mkcerts.sh <host-cn>` to mint a per-host dev certificate; in production
issue per-host certificates from your own CA.

See the [Security model](../../concepts/security-model/) for why mutable metadata
(hostname, serial) is never trusted for authorization on its own.
