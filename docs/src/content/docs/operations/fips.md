---
title: FIPS 140-3 builds
description: Native Go FIPS 140-3 builds with GOFIPS140, replacing BoringCrypto.
---

Rootseal's FIPS packages use **native Go FIPS 140-3**, built with
`GOFIPS140=latest`. This replaces the older `GOEXPERIMENT=boringcrypto`
approach: there is **no cgo/BoringCrypto dependency** and no gcc build
requirement. See the Go [FIPS 140-3 documentation](https://go.dev/doc/security/fips140).

## How it works

Building with `GOFIPS140=latest` links the frozen Go Cryptographic Module and
enables FIPS mode by default (`GODEBUG=fips140=on`). The resulting binary records
this in its build metadata.

```sh
GOFIPS140=latest CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -o rootseal-fips ./cmd/rootseal
```

## Verifying a binary

Inspect the build metadata — a FIPS binary records `GOFIPS140=latest`:

```sh
go version -m ./rootseal-fips | grep GOFIPS140
# build   GOFIPS140=latest
# build   GODEBUG=...fips140=on...
```

CI runs exactly this check and fails the build if `GOFIPS140=latest` is missing
from the FIPS binaries.

## FIPS packages

`rpmbuild --with fips_build` produces `rootseal-fips` and
`rootseal-controlplane-fips`. The `%build` step exports `GOFIPS140=latest` and
`CGO_ENABLED=0`; the FIPS subpackage descriptions reference Go FIPS 140-3 rather
than BoringCrypto. See [Installation](../installation/) for building the RPMs.
