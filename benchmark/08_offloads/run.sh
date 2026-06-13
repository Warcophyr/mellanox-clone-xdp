#!/usr/bin/env bash
# 08_offloads/run.sh
#
# For each hardware offload: disable it, measure throughput + CPU, re-enable.
# Usage:
#   sudo PEER=192.168.1.2 bash 08_offloads/run.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

IFACE="${IFACE:-eth0}"
PEER="${PEER:-}"
DURATION="${DURATION:-20}"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/results}"
META="${OUTPUT_DIR}/meta.json"

require_root
require_tool ethtool mpstat python3
[[ -n "$PEER" ]] || die "PEER is not set."
mkdir -p "$OUTPUT_DIR"

# Resolve DUT addressing for TRex
DUT_MAC=$(ip link show "$IFACE" | awk '/ether/{print $2}')
DUT_IP=$(ip -4 addr show "$IFACE" | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
export DUT_MAC DUT_IP TREX_IP="$PEER"


# Save a full offload snapshot so we can restore exactly
ORIG_OFFLOADS="${OUTPUT_DIR}/offloads_orig.txt"
ethtool -k "$IFACE" > "$ORIG_OFFLOADS" 2>/dev/null

restore_all_offloads() {
    info "Restoring original offload state..."
    # Read the saved state and restore togglable features
    while IFS= read -r line; do
        local feat state
        feat=$(echo "$line" | cut -d: -f1 | xargs)
        state=$(echo "$line" | awk -F: '{print $2}' | awk '{print $1}')
        [[ "$state" == "on" || "$state" == "off" ]] || continue
        # Skip fixed features
        echo "$line" | grep -q '\[fixed\]' && continue
        ethtool -K "$IFACE" "$feat" "$state" 2>/dev/null || true
    done < "$ORIG_OFFLOADS"
    ok "Offloads restored"
}
trap restore_all_offloads EXIT

# ── Offload list: (short_name, ethtool-K key) ─────────────────────────────────
declare -A OFFLOADS=(
    ["tso"]="tso"
    ["gro"]="gro"
    ["lro"]="lro"
    ["rx_csum"]="rx"
    ["tx_csum"]="tx"
    ["rxvlan"]="rxvlan"
    ["txvlan"]="txvlan"
    ["sg"]="sg"
)

# Check if an offload is fixed (can't be changed)
is_fixed() {
    local key="$1"
    grep -E "^(${key}|.*${key}.*):" "$ORIG_OFFLOADS" 2>/dev/null \
        | grep -q '\[fixed\]' && return 0 || return 1
}

# Measure throughput + CPU for current offload state
measure() {
    local label="$1"
    local iperf_out="${OUTPUT_DIR}/offload_${label}.json"
    local mpstat_out="${OUTPUT_DIR}/offload_${label}_cpu.txt"

    mpstat -P ALL 1 "$DURATION" > "$mpstat_out" 2>&1 &
    local mpstat_pid=$!

    iperf3 --client "$PEER" --time "$DURATION" --parallel 4 \
           --json --logfile "$iperf_out" \
        || warn "iperf3 non-zero for $label"

    wait "$mpstat_pid" 2>/dev/null || true
}

# ── Baseline measurement (all offloads in original state) ─────────────────────
info "=== Measuring baseline (all offloads default) ==="
measure "baseline"

# ── Per-offload toggle ────────────────────────────────────────────────────────
for name in "${!OFFLOADS[@]}"; do
    key="${OFFLOADS[$name]}"

    if is_fixed "$key"; then
        warn "  $name ($key) is [fixed] — skipping"
        continue
    fi

    info "=== Offload: $name ($key) — disabling ==="
    ethtool -K "$IFACE" "$key" off 2>/dev/null \
        || { warn "  Cannot disable $key — skipping"; continue; }
    sleep 1

    measure "${name}_off"

    # Re-enable
    ethtool -K "$IFACE" "$key" on 2>/dev/null || true
    sleep 1
done

# ── Combination: all checksum offloads off ────────────────────────────────────
info "=== Combination: all checksum offloads off ==="
ethtool -K "$IFACE" rx off tx off 2>/dev/null || true
sleep 1
measure "combo_no_csum"
ethtool -K "$IFACE" rx on tx on 2>/dev/null || true

RESULT="${OUTPUT_DIR}/result.json"
python3 "${SCRIPT_DIR}/analyse.py" \
    --results-dir "$OUTPUT_DIR" --iface "$IFACE" --output "$RESULT"

python3 "${SCRIPT_DIR}/report.py" \
    --result "$RESULT" --baseline "${SCRIPT_DIR}/baseline.json" \
    --env "${OUTPUT_DIR}/env.json" --output "${SCRIPT_DIR}/REPORT.md" --meta "$META"

log "=== 08_offloads complete ==="
