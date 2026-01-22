#!/bin/bash
# rootseal NBDE unlock hook for dracut
# This runs during initramfs before root is mounted

type getarg >/dev/null 2>&1 || . /lib/dracut-lib.sh

CRYPTOR_SERVER="${CRYPTOR_SERVER:-}"
CRYPTOR_TIMEOUT="${CRYPTOR_TIMEOUT:-30}"

# Get server from kernel command line if not set
[ -z "$CRYPTOR_SERVER" ] && CRYPTOR_SERVER=$(getarg rd.rootseal.server=)

# Find LUKS devices that have rootseal tokens
find_rootseal_devices() {
    local dev
    for dev in /dev/disk/by-uuid/*; do
        [ -b "$dev" ] || continue
        if cryptsetup isLuks "$dev" 2>/dev/null; then
            # Check if device has a rootseal token
            if cryptsetup luksDump "$dev" 2>/dev/null | grep -q '"type": "rootseal"'; then
                echo "$dev"
            fi
        fi
    done
}

# Extract rootseal token data from LUKS header
get_token_data() {
    local dev="$1"
    cryptsetup luksDump "$dev" --dump-json-metadata 2>/dev/null | \
        jq -r '.tokens | to_entries[] | select(.value.type == "rootseal") | .value'
}

# Unlock a single LUKS device using rootseal
unlock_device() {
    local dev="$1"
    local name="$2"
    local token_data
    local volume_uuid
    local server

    token_data=$(get_token_data "$dev")
    if [ -z "$token_data" ]; then
        warn "rootseal: No rootseal token found for $dev"
        return 1
    fi

    volume_uuid=$(echo "$token_data" | jq -r '.volume_uuid')
    server=$(echo "$token_data" | jq -r '.server // empty')
    
    # Use token server or fall back to kernel cmdline/env
    [ -z "$server" ] && server="$CRYPTOR_SERVER"
    
    if [ -z "$server" ]; then
        warn "rootseal: No server configured for $dev"
        return 1
    fi

    info "rootseal: Unlocking $dev (volume $volume_uuid) via $server"

    # Call rootseal to get the key and unlock
    if rootseal unlock \
        --device="$dev" \
        --server="$server" \
        --volume-uuid="$volume_uuid" \
        --name="$name" \
        --timeout="$CRYPTOR_TIMEOUT"; then
        info "rootseal: Successfully unlocked $dev as $name"
        return 0
    else
        warn "rootseal: Failed to unlock $dev, falling back to passphrase"
        return 1
    fi
}

# Main entry point
main() {
    local dev name

    # Wait for network to be available
    if ! getargbool 0 rd.neednet; then
        # Network not requested, skip
        return 0
    fi

    # Process devices from crypttab or auto-discover
    if [ -f /etc/crypttab ]; then
        while read -r name dev _ options; do
            [ -z "$name" ] || [ "${name:0:1}" = "#" ] && continue
            
            # Resolve UUID= or PARTUUID= references
            case "$dev" in
                UUID=*) dev="/dev/disk/by-uuid/${dev#UUID=}" ;;
                PARTUUID=*) dev="/dev/disk/by-partuuid/${dev#PARTUUID=}" ;;
            esac

            # Check if this device should use rootseal
            if echo "$options" | grep -q '_netdev\|rootseal'; then
                if ! unlock_device "$dev" "$name"; then
                    # Fallback handled by systemd-cryptsetup
                    continue
                fi
            fi
        done < /etc/crypttab
    else
        # Auto-discover rootseal-enabled devices
        for dev in $(find_rootseal_devices); do
            name="luks-$(cryptsetup luksUUID "$dev" 2>/dev/null)"
            unlock_device "$dev" "$name" || true
        done
    fi
}

main "$@"
