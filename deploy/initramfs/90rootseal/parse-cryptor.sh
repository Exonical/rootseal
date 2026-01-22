#!/bin/bash
# Parse rootseal kernel command line parameters

# Check for rootseal.server parameter
if getargbool 0 rd.rootseal || getarg rootseal.server >/dev/null; then
    CRYPTOR_SERVER=$(getarg rootseal.server)
    CRYPTOR_DEVICE=$(getarg rootseal.device)
    CRYPTOR_TIMEOUT=$(getarg rootseal.timeout)
    
    # Set defaults
    [ -z "$CRYPTOR_SERVER" ] && CRYPTOR_SERVER="rootseal.example.com:443"
    [ -z "$CRYPTOR_TIMEOUT" ] && CRYPTOR_TIMEOUT="300"
    
    # Export for use in unlock script
    echo "CRYPTOR_SERVER=$CRYPTOR_SERVER" >> /tmp/rootseal.env
    echo "CRYPTOR_DEVICE=$CRYPTOR_DEVICE" >> /tmp/rootseal.env
    echo "CRYPTOR_TIMEOUT=$CRYPTOR_TIMEOUT" >> /tmp/rootseal.env
    
    info "Cryptor network unlock enabled for server: $CRYPTOR_SERVER"
fi
