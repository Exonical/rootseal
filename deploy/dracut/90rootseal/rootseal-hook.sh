#!/bin/bash
# rootseal NBDE unlock hook for dracut
# This runs in initqueue/online when network is available

type getarg >/dev/null 2>&1 || . /lib/dracut-lib.sh

info "rootseal: initqueue/online hook triggered"

# Find the LUKS device from kernel cmdline
LUKS_UUID=$(getarg rd.luks.uuid=)
LUKS_UUID="${LUKS_UUID#luks-}"

if [ -z "$LUKS_UUID" ]; then
    warn "rootseal: No rd.luks.uuid found"
    exit 0
fi

DEV="/dev/disk/by-uuid/$LUKS_UUID"
if [ ! -b "$DEV" ]; then
    warn "rootseal: Device $DEV not found"
    exit 0
fi

# Check if already unlocked
DM_NAME="luks-$LUKS_UUID"
if [ -b "/dev/mapper/$DM_NAME" ]; then
    info "rootseal: $DM_NAME already unlocked"
    exit 0
fi

# Try to unlock with rootseal
info "rootseal: Attempting to unlock $DEV via NBDE"

TPM_ARGS=""
if [ -f /etc/rootseal/ak.blob ]; then
    TPM_ARGS="--tpm"
    info "rootseal: Using TPM attestation"
fi

if /usr/local/bin/rootseal unlock --device="$DEV" --name="$DM_NAME" $TPM_ARGS 2>&1; then
    info "rootseal: Successfully unlocked $DEV as $DM_NAME"
    # Signal success
    echo "$DM_NAME" > /tmp/rootseal.unlocked
else
    warn "rootseal: Failed to unlock via NBDE"
fi
