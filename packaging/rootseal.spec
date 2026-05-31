# Version and release are overridable from CI so packages track git tags
# automatically (see .github/workflows/build.yml and packaging/gen-changelog.sh).
%global pkgver %{?_pkgver}%{!?_pkgver:0.1.0}
%global pkgrel %{?_pkgrel}%{!?_pkgrel:1}

Name:           rootseal
Version:        %{pkgver}
Release:        %{pkgrel}%{?dist}
Summary:        Network-Bound Disk Encryption (NBDE) agent and control plane

License:        Apache-2.0
URL:            https://github.com/banglin/go-luks2
Source0:        %{name}-%{version}.tar.gz

%global debug_package %{nil}

# Pass --define "fips_build 1" to rpmbuild to produce the FIPS subpackage
%bcond_with fips_build

BuildRequires:  golang >= 1.26.3
BuildRequires:  systemd-rpm-macros

Requires:       cryptsetup
Requires:       dracut
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
rootseal provides NBDE (Network-Bound Disk Encryption) for LUKS2 volumes.
The agent binary handles post-imaging key registration, LUKS unlocking,
TPM attestation, and initramfs integration via a dracut module.

%package controlplane
Summary:        rootseal control plane server
Requires:       %{name} = %{version}-%{release}

%description controlplane
The rootseal control plane is a gRPC server that stores and serves
wrapped LUKS recovery keys, backed by HashiCorp Vault and PostgreSQL.

%if %{with fips_build}
%package fips
Summary:        rootseal agent built in native Go FIPS 140-3 mode
Provides:       %{name} = %{version}-%{release}
Obsoletes:      %{name} < %{version}-%{release}

%description fips
FIPS 140-3 build of the rootseal agent. Compiled with GOFIPS140=latest so the
binary links the Go Cryptographic Module and runs in FIPS 140-3 mode by default
(GODEBUG=fips140=on); no cgo/BoringCrypto dependency. See
https://go.dev/doc/security/fips140.

%package controlplane-fips
Summary:        rootseal control plane built in native Go FIPS 140-3 mode
Provides:       %{name}-controlplane = %{version}-%{release}
Obsoletes:      %{name}-controlplane < %{version}-%{release}

%description controlplane-fips
FIPS 140-3 build of the rootseal control plane server (GOFIPS140=latest,
native Go Cryptographic Module).
%endif

# ---------------------------------------------------------------------------
%prep
%autosetup -p1

# ---------------------------------------------------------------------------
%build
export GOFLAGS="-mod=vendor"
export GOPATH=%{_builddir}/gopath
export CGO_ENABLED=0

# Native Go FIPS 140-3: link the frozen Go Cryptographic Module and enable
# FIPS mode by default. No cgo/BoringCrypto required.
%if %{with fips_build}
export GOFIPS140=latest
%endif

go build -v \
    -ldflags "-s -w -X main.version=%{version}" \
    -o bin/rootseal \
    ./cmd/rootseal

go build -v \
    -ldflags "-s -w -X main.version=%{version}" \
    -o bin/rootseal-controlplane \
    ./cmd/controlplane

# ---------------------------------------------------------------------------
%install
%if %{with fips_build}
install -D -m 0755 bin/rootseal              %{buildroot}%{_bindir}/rootseal-fips
install -D -m 0755 bin/rootseal-controlplane %{buildroot}%{_bindir}/rootseal-controlplane-fips
%else
install -D -m 0755 bin/rootseal              %{buildroot}%{_bindir}/rootseal
install -D -m 0755 bin/rootseal-controlplane %{buildroot}%{_bindir}/rootseal-controlplane
%endif

# Systemd units
install -D -m 0644 deploy/systemd/rootseal-agent.service \
    %{buildroot}%{_unitdir}/rootseal-agent.service
install -D -m 0644 deploy/systemd/rootseal-postimaging.service \
    %{buildroot}%{_unitdir}/rootseal-postimaging.service
install -D -m 0644 deploy/systemd/rootseal-postimaging@.service \
    %{buildroot}%{_unitdir}/rootseal-postimaging@.service

# Dracut module
install -d -m 0755 %{buildroot}%{_prefix}/lib/dracut/modules.d/90rootseal
install -m 0755 deploy/dracut/90rootseal/module-setup.sh \
    %{buildroot}%{_prefix}/lib/dracut/modules.d/90rootseal/module-setup.sh
install -m 0755 deploy/dracut/90rootseal/rootseal-askpass \
    %{buildroot}%{_prefix}/lib/dracut/modules.d/90rootseal/rootseal-askpass
install -m 0644 deploy/dracut/90rootseal/rootseal-askpass.path \
    %{buildroot}%{_prefix}/lib/dracut/modules.d/90rootseal/rootseal-askpass.path
install -m 0644 deploy/dracut/90rootseal/rootseal-askpass.service \
    %{buildroot}%{_prefix}/lib/dracut/modules.d/90rootseal/rootseal-askpass.service
install -m 0755 deploy/dracut/90rootseal/rootseal-hook.sh \
    %{buildroot}%{_prefix}/lib/dracut/modules.d/90rootseal/rootseal-hook.sh

# Config directory
install -d -m 0750 %{buildroot}%{_sysconfdir}/rootseal

# ---------------------------------------------------------------------------
%post
%systemd_post rootseal-agent.service

%preun
%systemd_preun rootseal-agent.service

%postun
%systemd_postun_with_restart rootseal-agent.service

# ---------------------------------------------------------------------------
%if %{without fips_build}
%files
%license LICENSE
%{_bindir}/rootseal
%{_unitdir}/rootseal-agent.service
%{_unitdir}/rootseal-postimaging.service
%{_unitdir}/rootseal-postimaging@.service
%{_prefix}/lib/dracut/modules.d/90rootseal/
%dir %attr(0750,root,root) %{_sysconfdir}/rootseal

%files controlplane
%{_bindir}/rootseal-controlplane
%endif

%if %{with fips_build}
%files fips
%license LICENSE
%{_bindir}/rootseal-fips
%{_unitdir}/rootseal-agent.service
%{_unitdir}/rootseal-postimaging.service
%{_unitdir}/rootseal-postimaging@.service
%{_prefix}/lib/dracut/modules.d/90rootseal/
%dir %attr(0750,root,root) %{_sysconfdir}/rootseal

%files controlplane-fips
%{_bindir}/rootseal-controlplane-fips
%endif

# ---------------------------------------------------------------------------
%changelog
* Sat Mar 08 2025 rootseal maintainers <rootseal@example.com> - 0.1.0-1
- Initial package
