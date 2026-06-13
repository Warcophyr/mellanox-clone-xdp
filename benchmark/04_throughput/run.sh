#!/usr/bin/env bash
# 04_throughput/run.sh
#
# Sub-tests:
#   A) TCP stream scaling   — iperf3, 1/4/8/16/32 parallel streams
#   B) TCP bidir            — iperf3 --bidir, 4 streams
#   C) UDP PPS sweep        — pktgen kernel module, 7 frame sizes
#   D) CPU cost vs line-rate— mpstat while iperf3 runs at 25/50/75/100% rate
#
# Prerequisites on PEER:
#   iperf3 -s -D
#
# Usage:
#   sudo PEER=192.168.1.2 bash 04_throughput/run.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

IFACE="${IFACE:-eth0}"
PEER="${PEER:-}"
DURATION="${DURATION:-30}"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/results}"
BASELINE="${SCRIPT_DIR}/baseline.json"
SUITE="04_throughput"
META="${OUTPUT_DIR}/meta.json"

require_root
require_tool python3 ip ethtool mpstat
[[ -n "$PEER" ]] || die "PEER is not set."
mkdir -p "$OUTPUT_DIR"

# Resolve DUT addressing for TRex
DUT_MAC=$(ip link show "$IFACE" | awk '/ether/{print $2}')
DUT_IP=$(ip -4 addr show "$IFACE" | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
export DUT_MAC DUT_IP TREX_IP="$PEER"


# ── Peer MAC (needed for pktgen) ──────────────────────────────────────────────
get_peer_mac() {
    # Trigger ARP if not cached, then read
    ping -c 1 -W 1 "$PEER" &>/dev/null || true
    ip neigh show "$PEER" 2>/dev/null | awk 'NR==1{print $5}' || echo "ff:ff:ff:ff:ff:ff"
}

# ── Sub-tests A+B+D handled by trex_run.py ───────────────────────────────────
run_tcp_streams() { : ; }  # handled by run_trex() below
run_bidir()       { : ; }  # handled by run_trex() below

run_trex() {
    info "=== TRex: stream scaling + bidir + CPU cost ==="
    OUTPUT_DIR="$OUTPUT_DIR" DURATION="$DURATION" \
        python3 "${SCRIPT_DIR}/trex_run.py" \
        || warn "TRex run exited non-zero"
}

# ── Sub-test C: pktgen UDP PPS sweep ─────────────────────────────────────────
PKTGEN_AVAIL=0

pktgen_run() {
    local size="$1" dst_ip="$2" dst_mac="$3" secs="$4"
    local dev="/proc/net/pktgen/${IFACE}@0"
    local thread="/proc/net/pktgen/kpktgend_0"
    local ctrl="/proc/net/pktgen/pgctrl"

    echo "rem_device_all"       > "$thread"
    echo "add_device ${IFACE}@0" > "$thread"
    echo "count 0"              > "$dev"
    echo "clone_skb 0"          > "$dev"
    echo "pkt_size $size"       > "$dev"
    echo "delay 0"              > "$dev"
    echo "dst $dst_ip"          > "$dev"
    echo "dst_mac $dst_mac"     > "$dev"

    echo "start" > "$ctrl"
    sleep "$secs"
    echo "stop"  > "$ctrl"
    sleep 0.5

    cat "$dev"
}

run_pktgen() {
    info "=== Sub-test C: pktgen UDP PPS sweep ==="
    if ! modprobe pktgen 2>/dev/null; then
        warn "pktgen module not available — skipping PPS sweep"
        return
    fi
    PKTGEN_AVAIL=1

    local peer_mac
    peer_mac=$(get_peer_mac)
    info "  Peer MAC: $peer_mac"

    for size in 64 128 256 512 1024 1500 9000; do
        info "  Frame size: ${size}B"
        pktgen_run "$size" "$PEER" "$peer_mac" 10 \
            > "${OUTPUT_DIR}/pktgen_${size}B.txt" 2>&1 \
            || warn "pktgen failed for size=$size"
    done
}

# ── Sub-test D: handled by trex_run.py (run_trex above) ─────────────────────
run_cpu_cost_disabled() {
    info "=== Sub-test D: CPU cost vs line-rate ==="

    # Get link speed in Mbps
    local speed_mbps
    speed_mbps=$(ethtool "$IFACE" 2>/dev/null \
        | grep -oP 'Speed: \K\d+' || echo 100000)

    for pct in 25 50 75 100; do
        local target_bps=$(( speed_mbps * pct * 1000 / 100 ))  # bits/s
        local out_iperf="${OUTPUT_DIR}/cpu_cost_${pct}pct.json"
        local out_mpstat="${OUTPUT_DIR}/cpu_cost_${pct}pct_mpstat.txt"

        info "  ${pct}% line rate (~${target_bps} bps)..."

        # mpstat in background, capture 1-second samples during iperf3
        mpstat -P ALL 1 "$DURATION" > "$out_mpstat" 2>&1 &
        local mpstat_pid=$!

        iperf3 --client "$PEER" --time "$DURATION" --parallel 4 \
               --bandwidth "${target_bps}" \
               --json --logfile "$out_iperf" \
            || warn "iperf3 non-zero for ${pct}% rate"

        wait "$mpstat_pid" 2>/dev/null || true
    done
}

# ── Main ──────────────────────────────────────────────────────────────────────
log "=== ${SUITE} starting ==="
ENV_FILE="${OUTPUT_DIR}/env.json"
snapshot_env "$IFACE" "$ENV_FILE"
check_link "$IFACE"
check_peer "$PEER"
setup_cpu_isolation
pin_irqs_to_numa "$IFACE"
sleep 2

run_trex
run_pktgen

RESULT="${OUTPUT_DIR}/result.json"
python3 "${SCRIPT_DIR}/analyse.py" \
    --results-dir "$OUTPUT_DIR" --iface "$IFACE" --output "$RESULT"

python3 "${SCRIPT_DIR}/report.py" \
    --result "$RESULT" --baseline "$BASELINE" \
    --env "$ENV_FILE" --output "${SCRIPT_DIR}/REPORT.md" --meta "$META"

restore_cpu_isolation
log "=== ${SUITE} complete ==="
