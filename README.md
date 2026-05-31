# Rootseal

**TPM-attested, Vault-backed unlocking of LUKS/root volumes — a modern
replacement for Clevis+Tang.**

Rootseal lets encrypted hosts boot unattended without storing the disk-unlock
key on the host. A small agent runs during early boot (initramfs) and asks a
central control plane for the key; the key is only released after the host
proves its identity with a **TPM 2.0 attestation**, presents a valid **mTLS**
client certificate bound to that volume, and the control plane unwraps the key
through **HashiCorp Vault**.

📖 **Documentation: https://exonical.github.io/rootseal**

## Why

Full-disk encryption protects data at rest, but the passphrase has to come from
somewhere at boot. Network-Bound Disk Encryption (NBDE) hands the key to a
network service — but only if the host can prove it is the machine it claims to
be, in the expected boot state. Rootseal binds key release to hardware-rooted
TPM identity rather than mutable metadata like hostname, UUID, MAC, or serial.

## Components

| Component | Binary | Role |
|---|---|---|
| Control plane | `rootseal-controlplane` | gRPC server that verifies attestation, enforces per-host authorization, and unwraps keys via Vault. Hosts admin subcommands. |
| Agent | `rootseal` | Host-side CLI used at imaging and early boot to enroll, bind, and unlock volumes. |
| State store | PostgreSQL | Enrolled hosts, attestation keys, authorized CNs, pinned PCRs, enrollment tokens, wrapped keys. |
| KMS | HashiCorp Vault (default) | Transit engine wraps/unwraps recovery keys; KV stores metadata. Also supports AWS KMS, Azure Key Vault, Fortanix SDKMS. |

## Security highlights

- **Secure by default.** The server runs in production mode by default and
  refuses to start without mTLS, attestation, a non-empty PCR policy, and Vault
  auth. Every unlock RPC fails closed.
- **Hardware-rooted identity.** Authorization is bound to a TPM-resident
  Attestation Key and the mTLS CN; one host cannot fetch another host's key.
- **Single-use enrollment tokens** + AK-rebind protection prevent rogue
  self-enrollment; hosts can be revoked.
- **Least-privilege Vault** via a short-lived AppRole that can only wrap/unwrap.
- **No secret leakage.** Disk keys are never logged, persisted, or passed via
  argv/env; key memory is wiped after use.

See [`SECURITY.md`](SECURITY.md) for the full model and documented residual risks.

## Quick start (local, non-production)

```sh
# Throwaway dev mTLS certs (each host needs a unique CN)
./scripts/mkcerts.sh agent01.example.com

# Bring up Postgres + Vault + control plane
cd deploy/compose && docker compose up --build
```

> The Compose stack sets `ROOTSEAL_PRODUCTION=false` and uses plaintext
> credentials — for development only. See the
> [Quick start](https://exonical.github.io/rootseal/quick-start/) docs.

## Build

Requires **Go 1.26.3+**.

```sh
go build ./...     # build all binaries
go test ./...      # run the test suite
```

RPM packages (including native Go FIPS 140-3 variants) are built from
`packaging/rootseal.spec`; see
[Installation](https://exonical.github.io/rootseal/operations/installation/).

## FIPS 140-3

FIPS packages use **native Go FIPS 140-3** (`GOFIPS140=latest`, no
cgo/BoringCrypto). Verify a binary with `go version -m <bin> | grep GOFIPS140`.
See the [FIPS docs](https://exonical.github.io/rootseal/operations/fips/).

## Documentation

The docs site is built with [Astro Starlight](https://starlight.astro.build/)
from `docs/` and published to GitHub Pages on every push to `main`.

```sh
cd docs
npm install
npm run dev      # local preview at http://localhost:4321/rootseal
npm run build    # static build into docs/dist
```

## License

Apache-2.0.
