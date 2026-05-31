# Rootseal Security Model & Operations

Rootseal performs TPM-attested, Vault-backed unlocking of LUKS/root volumes. It
handles highly sensitive key material and may run in early boot/initramfs. This
document describes the enforced security model, secure defaults, and operational
procedures.

## Operating modes

The server runs in **production mode by default** and fails closed on insecure
configuration. Set `ROOTSEAL_PRODUCTION=false` only for an explicit, loudly
warned dev/lab stack.

Production mode (default) requires all of the following or the server refuses to
start:

- mTLS with client-certificate verification (`TLS_CLIENT_AUTH=true`, `TLS_CA_FILE` set)
- A non-empty PCR policy (`TPM_REQUIRED_PCRS`)
- PCR value enforcement (forced on; per-volume PCRs are pinned trust-on-first-use)
- Vault authentication (`VAULT_ROLE_ID`/`VAULT_SECRET_ID` preferred, or `VAULT_TOKEN`)
- The unattested `GetKey` path disabled
- gRPC reflection disabled (`ROOTSEAL_DEBUG` unset)

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `ROOTSEAL_PRODUCTION` | `true` | Secure-by-default mode. `false` = explicit dev mode. |
| `ROOTSEAL_ALLOW_INSECURE` | `false` | Permit running without TLS (dev only). |
| `ROOTSEAL_ALLOW_UNATTESTED_GETKEY` | `false` | Permit the legacy unattested key path (dev only; ignored in production). |
| `ROOTSEAL_REQUIRE_ENROLLMENT_TOKEN` | `true` | Require a single-use enrollment token for `PostImaging`. |
| `ROOTSEAL_DEBUG` | `false` | Enable gRPC reflection (forbidden in production). |
| `TPM_REQUIRED_PCRS` | — | Comma-separated PCR indices required in quotes (e.g. `0,2,4,7`). |
| `TPM_ENFORCE_PCR_VALUES` | `false` | Pin/enforce PCR values per volume (forced on in production). |
| `EK_CERT_CA_FILE` | — | TPM manufacturer CA bundle used to verify EK certificates. |
| `EK_VERIFY_STRICT` | `false` | Reject enrollments lacking a verifiable EK certificate. |
| `TLS_CLIENT_AUTH` | `true` | Require client certificates (mTLS). |

## Identity and authorization

- Each host must have its own mTLS client certificate with a **unique CN**. A
  shared CN lets every host unlock every other host's volume. `scripts/mkcerts.sh`
  now mints a per-host agent cert (`mkcerts.sh <host-cn>`).
- At enrollment the client CN is bound to the agent (`AuthorizedCN`). Key release
  requires the requesting mTLS identity to match the bound CN (constant-time
  compare). One host cannot obtain another host's key.
- Authorization is enforced server-side on every unlock RPC and fails closed on
  missing identity, lookup failure, revoked host, unbound volume, or mismatch.

## Enrollment (preventing rogue self-enrollment)

`PostImaging` requires a **single-use, high-entropy enrollment token** in
production. Mint one out-of-band and deliver it to the host being provisioned:

```sh
rootseal-controlplane mint-enrollment-token -cn host01.example.com -ttl 15m
```

- Only the SHA-256 hash is stored; the plaintext is printed once and never logged.
- Tokens are single-use (atomically consumed), expiring, and optionally bound to a CN.
- The agent passes the token via gRPC metadata header `x-rootseal-enrollment-token`.
- Re-enrollment with a different AK for an already-enrolled host is rejected
  (`ErrAKRebind`), preventing trust rebinding.

## TPM attestation

- Every attestation uses a fresh, single-use server nonce; replayed/stale nonces
  are rejected.
- Quotes are verified against the nonce and the selected PCRs, and the quote's
  `TPM_GENERATED_VALUE` magic is checked.
- The AK object attributes are validated (FixedTPM, FixedParent, Restricted,
  Sign, not Decrypt) so software keys cannot masquerade as TPM-resident AKs.
- When `EK_CERT_CA_FILE` is set, the EK certificate chain is verified to a trusted
  manufacturer CA; `EK_VERIFY_STRICT=true` requires it.
- PCR values are pinned per volume on first successful attestation and enforced
  thereafter (trust-on-first-use).

## Host revocation

```sh
rootseal-controlplane revoke-host -hostname host01 -serial ABC123
rootseal-controlplane revoke-host -hostname host01 -serial ABC123 -unrevoke
```

A revoked host is refused at key release even with a valid certificate.

## Vault least-privilege

- The server authenticates with a short-lived AppRole token (`token_ttl=1h`,
  renewed automatically) rather than a long-lived static token.
- The `rootseal-server` policy can only encrypt/decrypt with the wrapping key(s)
  and read its own `volumes/*` metadata. It cannot read, export, rotate, or
  delete Transit keys.
- The policy is forward-compatible with per-volume Transit keys (`volume-<uuid>`).

## Key handling

- Disk keys are never logged, written to disk, placed in argv/env, or printed.
- `rootseal unseal --key-only` writes raw key bytes to stdout for piping into
  `cryptsetup` stdin; without `--key-only` the key is never rendered. Key memory
  is wiped after use.

## Documented residual risks

- **Single fleet Transit key:** all recovery keys are currently wrapped with one
  Transit key, so a fully compromised server could unwrap every volume's key.
  Migrating to per-volume Transit keys (policy already allows `volume-*`) is the
  recommended next step. Acceptable for lab/pilot only.
- **Full TPM credential activation** (`MakeCredential`/`ActivateCredential`) and
  live-TPM end-to-end validation require a real TPM/swtpm and are not exercised
  by the unit tests; the server-side verification logic is implemented and unit
  tested against synthetic quotes.
