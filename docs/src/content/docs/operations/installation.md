---
title: Installation (RPM)
description: Building and installing the Rootseal RPM packages, including FIPS variants.
---

Rootseal is packaged as RPMs from `packaging/rootseal.spec`. CI builds the
packages on Rocky Linux 10; you can also build them locally.

## Packages

| Package | Contents |
|---|---|
| `rootseal` | The host agent (`rootseal`) and initramfs/systemd integration. |
| `rootseal-controlplane` | The control plane server and admin CLI. |
| `rootseal-fips` | FIPS 140-3 build of the agent (see [FIPS builds](../fips/)). |
| `rootseal-controlplane-fips` | FIPS 140-3 build of the control plane. |

## Requirements

- **Go ≥ 1.26.3** (`BuildRequires: golang >= 1.26.3`). Rocky 10's packaged Go
  may be older, so CI installs Go 1.26.3 explicitly and builds with `--nodeps`.

## Build from source

```sh
# Vendor modules so the build is hermetic
go mod vendor

# Set up the rpmbuild tree and stage the source
rpmdev-setuptree
VERSION=0.1.0
tar --transform "s,^,rootseal-${VERSION}/," --exclude='.git' --exclude='bin' \
    -czf ~/rpmbuild/SOURCES/rootseal-${VERSION}.tar.gz .
cp packaging/rootseal.spec ~/rpmbuild/SPECS/rootseal.spec

# Build the default packages
rpmbuild -ba --define "_pkgver ${VERSION}" --define "_pkgrel 1" \
    ~/rpmbuild/SPECS/rootseal.spec
```

### Build the FIPS subpackages

Pass `--with fips_build`:

```sh
rpmbuild -ba --with fips_build \
    --define "_pkgver ${VERSION}" --define "_pkgrel 1" \
    ~/rpmbuild/SPECS/rootseal.spec
```

## Versioning and changelog

Version and release are **overridable from CI** so packages track git tags
automatically:

- `Version` / `Release` come from `--define "_pkgver"` / `--define "_pkgrel"`
  (defaulting to `0.1.0` / `1`).
- CI derives the version from the latest `v*` git tag and injects an
  auto-generated `%changelog` from git history via `packaging/gen-changelog.sh`.

```sh
# Generate a changelog block for a version/release from git history
sh packaging/gen-changelog.sh 1.2.0 1
```

## Install

```sh
sudo dnf install ./rootseal-*.rpm ./rootseal-controlplane-*.rpm
```

Then configure the service via environment variables — see
[Configuration](../configuration/).
