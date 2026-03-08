#!/bin/bash
# dracut module for rootseal NBDE
# Uses systemd askpass approach like Clevis

check() {
    require_binaries rootseal || return 1
    return 0
}

depends() {
    local deps="crypt network"
    if dracut_module_included "systemd"; then
        if [ -d "$(dracut_module_path systemd-cryptsetup 2>/dev/null)" ]; then
            deps="$deps systemd-cryptsetup"
        else
            deps="$deps systemd"
        fi
    fi
    echo "$deps"
    return 255
}

install() {
    # Install rootseal binary
    inst_binary /usr/bin/rootseal

    if dracut_module_included "systemd"; then
        # Systemd approach: use askpass to respond to password prompts
        inst_simple "$moddir/rootseal-askpass.service" "$systemdsystemunitdir/rootseal-askpass.service"
        inst_simple "$moddir/rootseal-askpass.path" "$systemdsystemunitdir/rootseal-askpass.path"
        inst_simple "$moddir/rootseal-askpass" "/usr/libexec/rootseal-askpass"
        chmod +x "${initdir}/usr/libexec/rootseal-askpass"
        
        # Enable the path unit
        systemctl -q --root "$initdir" add-wants cryptsetup.target rootseal-askpass.path
        
        # Install systemd-reply-password
        inst_binary /usr/lib/systemd/systemd-reply-password
    else
        # Non-systemd: use initqueue hooks
        inst_hook initqueue/online 60 "$moddir/rootseal-hook.sh"
        inst_hook initqueue/settled 60 "$moddir/rootseal-hook.sh"
    fi

    # Install TPM AK blob for attestation
    [[ -e /etc/rootseal/ak.blob ]] && inst_simple /etc/rootseal/ak.blob

    # Install required libraries for DNS resolution
    inst_libdir_file "libnss_dns.so.*" "libnss_files.so.*" "libresolv.so.*"

    # Install resolv.conf if it exists
    [[ -e /etc/resolv.conf ]] && inst_simple /etc/resolv.conf

    # Install cryptsetup and network tools
    inst_binary cryptsetup
    inst_binary ip
    inst_binary grep
    inst_binary sleep

    dracut_need_initqueue
}

installkernel() {
    instmods '=drivers/net'
}
