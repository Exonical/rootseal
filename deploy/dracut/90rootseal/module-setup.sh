#!/bin/bash
# dracut module for rootseal NBDE

check() {
    # Check if rootseal is installed
    require_binaries rootseal || return 1
    return 0
}

depends() {
    echo "network systemd"
    return 0
}

install() {
    # Install the rootseal binary
    inst_binary /usr/local/bin/rootseal

    # Install the unlock hook
    inst_hook pre-mount 90 "$moddir/rootseal-hook.sh"

    # Install required libraries for DNS resolution
    inst_libdir_file "libnss_dns.so.*" "libnss_files.so.*" "libresolv.so.*"

    # Install resolv.conf if it exists
    [[ -e /etc/resolv.conf ]] && inst_simple /etc/resolv.conf

    # Install rootseal configuration if present
    [[ -e /etc/rootseal/agent.yaml ]] && inst_simple /etc/rootseal/agent.yaml

    # Install CA certificates for TLS
    inst_dir /etc/pki/tls/certs
    inst_multiple /etc/pki/tls/certs/ca-bundle.crt /etc/pki/tls/certs/ca-bundle.trust.crt 2>/dev/null

    # Install cryptsetup for LUKS operations
    inst_binary cryptsetup
}

installkernel() {
    # Include network drivers
    instmods '=drivers/net'
}
