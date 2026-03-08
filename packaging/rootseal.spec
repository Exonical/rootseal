Name:           rootseal
Version:        0.1.0
Release:        1%{?dist}
Summary:        Network-Bound Disk Encryption (NBDE) agent and control plane

License:        Apache-2.0
URL:            https://github.com/banglin/go-luks2
Source0:        %{name}-%{version}.tar.gz

%global debug_package %{nil}

# Pass --define "fips_build 1" to rpmbuild to produce the FIPS subpackage
%bcond_with fips_build

BuildRequires:  golang >= 1.21
BuildRequires:  systemd-rpm-macros
%if %{with fips_build}
BuildRequires:  gcc
%endif

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
Summary:        rootseal agent built with FIPS 140 BoringCrypto
Provides:       %{name} = %{version}-%{release}
Obsoletes:      %{name} < %{version}-%{release}

%description fips
FIPS 140-2 compliant build of the rootseal agent. Compiled with
GOEXPERIMENT=boringcrypto so all TLS and cryptographic operations
use the Red Hat FIPS-validated BoringCrypto library.

%package controlplane-fips
Summary:        rootseal control plane built with FIPS 140 BoringCrypto
Provides:       %{name}-controlplane = %{version}-%{release}
Obsoletes:      %{name}-controlplane < %{version}-%{release}

%description controlplane-fips
FIPS 140-2 compliant build of the rootseal control plane server.
%endif

# ---------------------------------------------------------------------------
%prep
%autosetup -p1

# ---------------------------------------------------------------------------
%build
export GOFLAGS="-mod=vendor"
export GOPATH=%{_builddir}/gopath

%if %{with fips_build}
export GOEXPERIMENT=boringcrypto
export CGO_ENABLED=1
%else
export CGO_ENABLED=0
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
