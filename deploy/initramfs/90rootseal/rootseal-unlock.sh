#!/bin/bash
# Cryptor network unlock script for initramfs

[ -f /tmp/rootseal.env ] && . /tmp/rootseal.env

if [ -n "$CRYPTOR_SERVER" ]; then
    info "Starting rootseal network unlock..."
    
    # Wait for network
    wait_for_if_up
    
    # Attempt unlock with timeout
    timeout ${CRYPTOR_TIMEOUT:-300} rootseal-init unlock \
        --server="$CRYPTOR_SERVER" \
        --device="$CRYPTOR_DEVICE" \
        --config=/etc/rootseal/init.yaml
    
    if [ $? -eq 0 ]; then
        info "Cryptor network unlock successful"
    else
        warn "Cryptor network unlock failed, falling back to manual unlock"
    fi
fi
