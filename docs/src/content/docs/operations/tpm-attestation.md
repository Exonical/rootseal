---
title: TPM attestation
description: How Rootseal verifies TPM quotes, AK identity, EK certificates, and PCR policy.
---

TPM 2.0 attestation is what ties key release to a specific machine in a known
boot state. The verification logic lives in `internal/tpm2`.

## Nonce / challenge

- Every attestation begins with `GetNonce`, which returns a **fresh, single-use**
  server-generated nonce.
- The agent produces a TPM quote over the selected PCRs, signed by the AK, with
  the nonce as the qualifying data.
- The server rejects **replayed, stale, missing, or malformed** nonces — there
  is no way to reuse an old quote.

## Quote verification

The server checks all of the following:

- The quote signature verifies against the host's **stored AK**.
- The quote carries the `TPM_GENERATED_VALUE` magic (it was produced by a TPM,
  not synthesized).
- The PCR digest in the quote matches the presented PCR values.

## AK identity

The AK object attributes are validated so a software key cannot masquerade as a
TPM-resident AK:

- `FixedTPM`, `FixedParent` (the key cannot leave the TPM),
- `Restricted` + `Sign` (it can only sign TPM-generated data),
- **not** `Decrypt`.

## EK certificate (optional but recommended)

When `EK_CERT_CA_FILE` is set, the EK certificate chain is verified against a
trusted TPM **manufacturer CA** bundle, tying the AK to genuine TPM hardware.
Set `EK_VERIFY_STRICT=true` to reject any enrollment that lacks a verifiable EK
certificate.

## PCR policy

- `TPM_REQUIRED_PCRS` selects which PCRs must appear in the quote (e.g.
  `0,2,4,7` — firmware, option ROMs, bootloader, Secure Boot state).
- PCR **values** are pinned per volume on the first successful attestation and
  enforced thereafter (**trust-on-first-use**). In production this enforcement
  is forced on; an empty PCR policy is refused.

## Limitations

Full credential activation (`MakeCredential`/`ActivateCredential`) and live-TPM
end-to-end validation require a real TPM or swtpm and are not exercised by the
unit tests. The server-side verification logic is implemented and unit tested
against synthetic quotes. See the [Security model](../../concepts/security-model/).
