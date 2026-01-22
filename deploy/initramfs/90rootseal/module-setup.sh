#!/bin/bash
# Dracut module for rootseal network unlock

check() {
    require_binaries rootseal-init || return 1
    return 0
}

depends() {
    echo network
    return 0
}

install() {
    inst_multiple rootseal-init
    inst_hook cmdline 30 "$moddir/parse-rootseal.sh"
    inst_hook pre-mount 30 "$moddir/rootseal-unlock.sh"
    
    # Install config and certs
    inst_dir /etc/rootseal
    inst_multiple -o /etc/rootseal/init.yaml
    inst_multiple -o /etc/rootseal/certs/*
    
    # Install systemd service for initramfs
    inst "$moddir/rootseal-unlock.service" "$systemdsystemunitdir/rootseal-unlock.service"
    $SYSTEMCTL -q --root "$initdir" enable rootseal-unlock.service
}

installkernel() {
    return 0
}
