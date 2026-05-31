---
title: CLI reference
description: Commands and flags for the rootseal agent and the rootseal-controlplane admin tools.
---

Rootseal ships two binaries: the host **agent** (`rootseal`) and the **control
plane** (`rootseal-controlplane`, which also hosts admin subcommands).

## Agent: `rootseal`

```
rootseal <command> [args]
Commands: postimaging, bind, unlock, unseal
```

### `rootseal postimaging`

Enroll a host after imaging: add a Rootseal-managed key slot to a LUKS device,
optionally enroll the TPM, and escrow the wrapped recovery key.

| Flag | Default | Description |
|---|---|---|
| `-device` | — | Path to the LUKS device (required). |
| `-server` | — | Control plane address (`host:port`). |
| `-current-password` | — | Current LUKS password (`-` to prompt, or `ROOTSEAL_LUKS_PASSWORD`). |
| `-tpm` | `false` | Enroll TPM for attestation-based unlock. |
| `-seal-pcrs` | `0,2,4,7` | PCR indices to bind the sealed key to. |
| `-ak-blob` | `/etc/rootseal/ak.blob` | Where to save the AK blob. |
| `-enrollment-token` | — | Single-use enrollment token (required in production; prefer `ROOTSEAL_ENROLLMENT_TOKEN` to avoid argv exposure). |
| `-cert` / `-key` / `-ca` | `/etc/rootseal/certs/...` | Client mTLS cert / key / CA. |
| `-kill-old` | `false` | Remove the old key slot after adding the new one. |
| `-replace-in-place` | `false` | Use `luksChangeKey` instead of add+remove. |
| `-insecure` | `false` | Disable TLS (dev only). |

### `rootseal bind`

Bind an existing device to a volume UUID.

| Flag | Default | Description |
|---|---|---|
| `-device` | — | Path to the LUKS device (required). |
| `-server` | — | Control plane address. |
| `-volume-uuid` | — | Volume UUID (from postimaging or `/etc/rootseal/recovery.json`). |

### `rootseal unlock`

Fetch the key from the control plane (with attestation) and open the LUKS device.

| Flag | Default | Description |
|---|---|---|
| `-device` | — | Path to the LUKS device (required). |
| `-server` | — | Control plane address. |
| `-volume-uuid` | — | Volume UUID (reads from the LUKS token if omitted). |
| `-name` | `luks-<device>` | Name for the unlocked mapping. |
| `-tpm` | `false` | Use TPM attestation for authentication. |
| `-ak-blob` | `/etc/rootseal/ak.blob` | Stored AK blob path. |
| `-key-only` | `false` | Output only the key to stdout (for `--key-file=-`). |
| `-timeout` | `30` | Server connection timeout (seconds). |
| `-cert` / `-key` / `-ca` | `/etc/rootseal/certs/...` | Client mTLS cert / key / CA. |
| `-insecure` | `false` | Disable TLS (dev only). |

### `rootseal unseal`

Locally unseal a TPM-sealed key (no server round-trip).

| Flag | Default | Description |
|---|---|---|
| `-device` | — | LUKS device path. |
| `-key-only` | `false` | Output only the raw key, for piping to `cryptsetup` stdin. |

## Control plane: `rootseal-controlplane`

Run with no subcommand to start the gRPC server (configured via environment
variables — see [Configuration](../../operations/configuration/)). The following
admin subcommands operate out-of-band against the database.

### `mint-enrollment-token`

```sh
rootseal-controlplane mint-enrollment-token -cn host01.example.com -ttl 15m
```

| Flag | Default | Description |
|---|---|---|
| `-cn` | — | Optional mTLS CN the token is bound to (recommended). |
| `-ttl` | `1h` | Token validity window (e.g. `15m`, `1h`). |

The plaintext token is printed once and never logged; only its SHA-256 hash is
stored.

### `revoke-host`

```sh
rootseal-controlplane revoke-host -hostname host01 -serial ABC123
rootseal-controlplane revoke-host -hostname host01 -serial ABC123 -unrevoke
```

| Flag | Default | Description |
|---|---|---|
| `-hostname` | — | Hostname of the agent to revoke. |
| `-serial` | — | Hardware serial of the agent to revoke. |
| `-unrevoke` | `false` | Re-activate a previously revoked host. |
