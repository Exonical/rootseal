---
title: gRPC API
description: The LuksManager and AgentService gRPC services and their messages.
---

The control plane exposes two gRPC services, defined in `pkg/api` (proto3,
`package api`). All production traffic is over mTLS.

## Service: `LuksManager`

| RPC | Request → Response | Purpose |
|---|---|---|
| `GetNonce` | `NonceRequest` → `NonceResponse` | Obtain a fresh, single-use attestation nonce. |
| `GetKeyWithAttestation` | `AttestationKeyRequest` → `KeyResponse` | Primary unlock path: returns the wrapped key after verifying the TPM quote and authorization. |
| `Attest` | `AttestationRequest` → `AttestationResponse` | AppRole-style attestation token exchange. |
| `GetKey` | `KeyRequest` → `KeyResponse` | **Legacy unattested path. Disabled by default** and ignored in production (`ROOTSEAL_ALLOW_UNATTESTED_GETKEY`). |

## Service: `AgentService`

| RPC | Request → Response | Purpose |
|---|---|---|
| `PostImaging` | `PostImagingRequest` → `PostImagingResponse` | Enroll a host and escrow the wrapped recovery key. Requires a single-use enrollment token in production. |

## Key messages

### Attestation

```proto
message NonceRequest  { string volume_uuid = 1; }
message NonceResponse { bytes nonce = 1; int64 expires_at = 2; }

message AttestationKeyRequest {
  string volume_uuid = 1;
  bytes  nonce       = 2;
  TPMQuote quote     = 3;
  bytes  ak_public   = 4;
}

message TPMQuote {
  bytes quote     = 1;  // TPM2B_ATTEST
  bytes signature = 2;  // TPMT_SIGNATURE
  repeated PCRValue pcrs = 3;
}

message PCRValue { int32 index = 1; bytes digest = 2; }
```

### Enrollment

```proto
message PostImagingRequest {
  string device_path        = 1;
  string hostname           = 2;
  string username           = 3;
  string serial             = 4;
  bytes  current_password   = 5;
  bytes  new_recovery_key   = 6;
  map<string, string> labels = 7;
  TPMEnrollment tpm_enrollment = 8;
}

message TPMEnrollment {
  bytes ek_public = 1;  // Endorsement Key public
  bytes ek_cert   = 2;  // EK certificate (verified when EK_CERT_CA_FILE is set)
  bytes ak_public = 3;  // Attestation Key public
  bytes ak_name   = 4;  // AK name (for credential activation)
}
```

### Key response

```proto
message KeyResponse {
  bytes  wrapped_key  = 1;  // wrapped via the KMS; never plaintext at rest
  int32  key_version  = 2;
  string vault_kv_path = 3;
}
```

The enrollment token is **not** a proto field — the agent passes it in gRPC
metadata as the `x-rootseal-enrollment-token` header (see
[Enrollment](../../operations/enrollment/)).

:::note
`hostname`, `serial`, and similar fields are descriptive metadata. Authorization
is **never** based on them alone — it is bound to the TPM AK and the mTLS CN.
See the [Security model](../../concepts/security-model/).
:::
