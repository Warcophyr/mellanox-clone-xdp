#!/usr/bin/env bash
# 07_queue_scaling/run.sh
#
# Sub-tests:
#   A) Queue count scaling  — ethtool -L combined N, iperf3 -P N
#   B) Ring buffer depth    — ethtool -G, pktgen 64B flood
#   C) RSS distribution     — per-queue packet counts from ethtool -S
#
# Usage:
#   sudo PEER=192.168.1.2 bash 07_queue_scaling/run.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

IFACE="${IFACE:-eth0}"
PEER="${PEER:-}"
DURATION="${DURATION:-20}"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/results}"
META="${OUTPUT_DIR}/meta.json"

require_root
require_tool ethtool python3 ip
[[ -n "$PEER" ]] || die "PEER is not set."
mkdir -p "$OUTPUT_DIR"

# Resolve DUT addressing for TRex
DUT_MAC=$(ip link show "$IFACE" | awk '/ether/{print $2}')
DUT_IP=$(ip -4 addr show "$IFACE" | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
export DUT_MAC DUT_IP TREX_IP="$PEER"


# Save original queue and ring settings
ORIG_QUEUES=$(ethtool -l "$IFACE" 2>/dev/null | awk '/Combined:/{print $2; exit}' || echo 1)
ORIG_RX_RING=$(ethtool -g "$IFACE" 2>/dev/null | awk '/RX:/{print $2; exit}' || echo 256)
ORIG_TX_RING=$(ethtool -g "$IFACE" 2>/dev/null | awk '/TX:/{print $2; exit}' || echo 256)
MAX_QUEUES=$(ethtool -l "$IFACE" 2>/dev/null | awk 'NR==4 && /Combined:/{print $2}' || echo 8)

info "Original: queues=$ORIG_QUEUES  rx_ring=$ORIG_RX_RING  tx_ring=$ORIG_TX_RING  max_queues=$MAX_QUEUES"

restore_settings() {
    ethtool -L "$IFACE" combined "$ORIG_QUEUES"   2>/dev/null || true
    ethtool -G "$IFACE" rx "$ORIG_RX_RING" tx "$ORIG_TX_RING" 2>/dev/null || true
    ok "Queue/ring settings restored"
}
trap restore_settings EXIT

# ── Sub-test A: Queue count scaling ──────────────────────────────────────────
run_queue_scaling() {
    info "=== Sub-test A: Queue count scaling ==="
    # Build power-of-2 list up to MAX_QUEUES
    local counts=()
    local q=1
    while [[ $q -le $MAX_QUEUES ]]; do
        counts+=("$q")
        q=$(( q * 2 ))
    done
    [[ "${counts[-1]}" -ne "$MAX_QUEUES" ]] && counts+=("$MAX_QUEUES")

    for q in "${counts[@]}"; do
        info "  ${q} queues..."
        ethtool -L "$IFACE" combined "$q" 2>/dev/null || { warn "  Cannot set $q queues"; continue; }
        sleep 1

        DURATION="$DURATION" OUTPUT_DIR="$OUTPUT_DIR" \
            python3 "${SCRIPT_DIR}/trex_run.py" --mode queue --label "qscale_q${q}" \
            || warn "  TRex non-zero for q=$q"
    done
}

# ── Sub-test B: Ring buffer depth ─────────────────────────────────────────────
run_ring_sweep() {
    info "=== Sub-test B: Ring buffer depth sweep ==="
    # Restore to max queues for this test
    ethtool -L "$IFACE" combined "$MAX_QUEUES" 2>/dev/null || true

    for ring in 64 128 256 512 1024 2048 4096; do
        # Check if ring size is valid (max ring size)
        local max_ring
        max_ring=$(ethtool -g "$IFACE" 2>/dev/null | awk 'NR<=4 && /RX:/{print $2}' || echo 4096)
        [[ $ring -gt $max_ring ]] && continue

        info "  Ring depth: $ring"
        ethtool -G "$IFACE" rx "$ring" tx "$ring" 2>/dev/null \
            || { warn "  Cannot set ring=$ring"; continue; }
        sleep 1

        # Capture ethtool -S drops before/after iperf3
        ethtool -S "$IFACE" > "${OUTPUT_DIR}/ring_${ring}_t0.txt" 2>/dev/null
        DURATION="$DURATION" OUTPUT_DIR="$OUTPUT_DIR" \
            python3 "${SCRIPT_DIR}/trex_run.py" --mode ring --label "ring_${ring}" \
            || warn "  TRex non-zero for ring=$ring"
        ethtool -S "$IFACE" > "${OUTPUT_DIR}/ring_${ring}_t1.txt" 2>/dev/null
    done
}

# ── Sub-test C: RSS hash distribution ─────────────────────────────────────────
run_rss_distribution() {
    info "=== Sub-test C: RSS queue distribution ==="
    # Restore original queue count
    ethtool -L "$IFACE" combined "$ORIG_QUEUES" 2>/dev/null || true
    ethtool -G "$IFACE" rx "$ORIG_RX_RING" tx "$ORIG_TX_RING" 2>/dev/null || true
    sleep 1

    # Snapshot per-queue counters before
    ethtool -S "$IFACE" > "${OUTPUT_DIR}/rss_t0.txt" 2>/dev/null

    # Send many parallel streams (should spread across queues via RSS)
    DURATION="$DURATION" OUTPUT_DIR="$OUTPUT_DIR" \
        python3 "${SCRIPT_DIR}/trex_run.py" --mode rss \
        || warn "TRex rss non-zero"

    # Snapshot after
    ethtool -S "$IFACE" > "${OUTPUT_DIR}/rss_t1.txt" 2>/dev/null
    ok "RSS snapshot done"
}

# ── Main ──────────────────────────────────────────────────────────────────────
log "=== 07_queue_scaling starting ==="
ENV_FILE="${OUTPUT_DIR}/env.json"
snapshot_env "$IFACE" "$ENV_FILE"
check_link "$IFACE"
check_peer "$PEER"
setup_cpu_isolation
pin_irqs_to_numa "$IFACE"
sleep 2

run_queue_scaling
run_ring_sweep
run_rss_distribution

RESULT="${OUTPUT_DIR}/result.json"
python3 "${SCRIPT_DIR}/analyse.py" \
    --results-dir "$OUTPUT_DIR" --iface "$IFACE" \
    --max-queues "$MAX_QUEUES" --output "$RESULT"

python3 "${SCRIPT_DIR}/report.py" \
    --result "$RESULT" --baseline "${SCRIPT_DIR}/baseline.json" \
    --env "$ENV_FILE" --output "${SCRIPT_DIR}/REPORT.md" --meta "$META"

restore_cpu_isolation
log "=== 07_queue_scaling complete ==="
