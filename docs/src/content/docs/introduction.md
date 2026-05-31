---
title: Introduction
description: What Rootseal is, the problem it solves, and how its components fit together.
---

Rootseal is a replacement for [Clevis](https://github.com/latchset/clevis) +
[Tang](https://github.com/latchset/tang). It provides **TPM-attested,
Vault-backed unlocking of LUKS/root volumes** so encrypted hosts can boot
unattended without storing the disk-unlock key on the host or trusting a host's
self-reported identity.

## The problem

Full-disk encryption protects data at rest, but a passphrase has to come from
somewhere at boot. Network-Bound Disk Encryption (NBDE) answers this by handing
the key to a network service — but only if the host can prove it is the machine
it claims to be, in the expected boot state. Rootseal binds key release to:

- a **TPM 2.0 attestation** (a signed quote over selected PCRs), and
- a **mutual-TLS client identity** that is bound to the specific volume, and
- a **Vault**-managed wrapping key that unwraps the recovery key server-side.

## Components

| Component | Binary | Role |
|---|---|---|
| Control plane | `rootseal-controlplane` | gRPC server that verifies attestation, enforces authorization, and unwraps keys via Vault. Also hosts admin subcommands. |
| Agent | `rootseal` | Host-side CLI used during imaging and early boot to enroll, bind, and unlock volumes. |
| State store | PostgreSQL | Stores enrolled hosts, attestation keys, authorized CNs, pinned PCRs, enrollment tokens, and wrapped keys. |
| Key service | HashiCorp Vault | Transit engine wraps/unwraps recovery keys; KV stores per-volume metadata. |

The agent integrates with **dracut/initramfs** and **systemd** so the unlock
happens automatically during early boot. See
[Architecture](../concepts/architecture/) for the full picture.

## Design principles

- **Hardware-rooted identity.** Authorization is tied to a TPM-resident
  Attestation Key, never to mutable metadata (hostname, UUID, MAC, serial).
- **Secure by default.** The server runs in production mode unless explicitly
  told otherwise, and fails closed on insecure configuration.
- **Least privilege.** The server's Vault policy can only wrap/unwrap with the
  recovery key(s) and read its own metadata — it cannot export or delete keys.
- **No secret leakage.** Disk keys are never logged, written to disk, placed in
  argv/env, or printed; key memory is wiped after use.

Continue to the [Quick start](../quick-start/) to bring up a local stack, or read
the [Security model](../concepts/security-model/) for the enforced guarantees.
