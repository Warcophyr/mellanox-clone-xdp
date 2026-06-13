#!/usr/bin/env bash
# 05_interrupt/run.sh
#
# Three sub-tests in one run:
#
#   A) Coalescing sweep — 2D grid of (rx-usecs × rx-frames)
#      For each point: sockperf 15s (p99 latency) + iperf3 15s (throughput)
#
#   B) IRQ affinity comparison
#      Compare: irqbalance default vs NUMA-pinned vs per-CPU-pinned
#
#   C) softirq budget
#      Snapshot /proc/softirqs NET_RX / NET_TX delta under load
#
# Environment variables:
#   IFACE          — local NIC                          (default: eth0)
#   PEER           — IP of back-to-back peer             (required)
#   SOCK_PORT      — sockperf server port               (default: 11111)
#   SWEEP_SECS     — seconds per measurement point      (default: 15)
#   QUICK_SWEEP    — if "1", use a reduced 3×3 grid     (default: 0)
#
# Usage:
#   sudo PEER=192.168.1.2 bash 05_interrupt/run.sh
#   sudo QUICK_SWEEP=1 PEER=192.168.1.2 bash 05_interrupt/run.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

# ── Config ────────────────────────────────────────────────────────────────────
IFACE="${IFACE:-eth0}"
PEER="${PEER:-}"
SOCK_PORT="${SOCK_PORT:-11111}"
SWEEP_SECS="${SWEEP_SECS:-15}"
QUICK_SWEEP="${QUICK_SWEEP:-0}"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/results}"
BASELINE="${SCRIPT_DIR}/baseline.json"
SUITE="05_interrupt"

# ── Sweep grids ───────────────────────────────────────────────────────────────
if [[ "$QUICK_SWEEP" == "1" ]]; then
    RX_USECS_GRID=(0 25 100)
    RX_FRAMES_GRID=(0 16 64)
    info "Quick sweep mode: 3×3 grid"
else
    RX_USECS_GRID=(0 5 10 25 50 100)
    RX_FRAMES_GRID=(0 1 4 16 32 64)
fi

# ── Validation ────────────────────────────────────────────────────────────────
require_root
require_tool ethtool sockperf iperf3 python3 ip
[[ -n "$PEER" ]] || die "PEER is not set."
mkdir -p "$OUTPUT_DIR"

# ── Coalescing save / restore ─────────────────────────────────────────────────
save_coalescing() {
    local iface="$1" out="$2"
    ethtool -c "$iface" 2>/dev/null > "$out" \
        || warn "Could not save coalescing settings for $iface"
}

restore_coalescing() {
    local iface="$1" saved_file="$2"
    if [[ ! -f "$saved_file" ]]; then return; fi
    local rx_usecs rx_frames
    rx_usecs=$(awk '/^rx-usecs:/{print $2}' "$saved_file" || echo 50)
    rx_frames=$(awk '/^rx-frames:/{print $2}' "$saved_file" || echo 0)
    ethtool -C "$iface" rx-usecs "$rx_usecs" rx-frames "$rx_frames" 2>/dev/null \
        || warn "Could not restore coalescing"
    ok "Coalescing restored → rx-usecs=$rx_usecs rx-frames=$rx_frames"
}

set_coalescing() {
    local iface="$1" usecs="$2" frames="$3"
    ethtool -C "$iface" rx-usecs "$usecs" rx-frames "$frames" 2>/dev/null \
        || { warn "ethtool -C failed for usecs=$usecs frames=$frames"; return 1; }
}

# ── softirq snapshot helper ───────────────────────────────────────────────────
snapshot_softirq() {
    local outfile="$1"
    # Output: one line per CPU: "cpuN <NET_RX_count> <NET_TX_count>"
    python3 - "$outfile" <<'PY'
import sys, re
from pathlib import Path

out = sys.argv[1]
text = Path('/proc/softirqs').read_text()
lines = text.splitlines()

# Header: "                    CPU0       CPU1 ..."
header = lines[0]
cpus = re.findall(r'CPU(\d+)', header)

result = {}
for line in lines[1:]:
    parts = line.split()
    if not parts:
        continue
    irq_name = parts[0].rstrip(':')
    if irq_name not in ('NET_RX', 'NET_TX'):
        continue
    counts = parts[1:]
    for i, cpu in enumerate(cpus):
        key = f'cpu{cpu}'
        if key not in result:
            result[key] = {}
        result[key][irq_name] = int(counts[i]) if i < len(counts) else 0

import json
Path(out).write_text(json.dumps(result, indent=2))
PY
}

# ── Single coalescing measurement point ──────────────────────────────────────
# Writes:
#   ${OUTPUT_DIR}/sweep_u${usecs}_f${frames}_lat.txt    (sockperf summary)
#   ${OUTPUT_DIR}/sweep_u${usecs}_f${frames}_tput.json  (iperf3 json)
measure_point() {
    local usecs="$1" frames="$2"
    local tag="u${usecs}_f${frames}"

    set_coalescing "$IFACE" "$usecs" "$frames" || return
    sleep 1  # let coalescing timers settle

    # Use TRex for both latency and throughput at each grid point.
    # trex_sweep.py writes sweep_${tag}_lat.txt and sweep_${tag}_tput.json
    # in the format that analyse.py already expects (Gap 1 workaround: two
    # sequential runs per point instead of one simultaneous measurement).
    RX_USECS="$usecs" RX_FRAMES="$frames" \
    TREX_IP="$PEER" DUT_MAC="$DUT_MAC" DUT_IP="$DUT_IP" \
    SWEEP_SECS="$SWEEP_SECS" SWEEP_RATE_PPS="10000" SWEEP_SIZE_B="64" \
    OUTPUT_DIR="$OUTPUT_DIR" \
        python3 "${SCRIPT_DIR}/trex_sweep.py" \
        || warn "TRex sweep non-zero for $tag"

    local p99 gbps
    p99=$(grep -oP "Percentile 99\.0+ = \K[\d.]+" \
        "${OUTPUT_DIR}/sweep_${tag}_lat.txt" 2>/dev/null || echo "?")
    gbps=$(python3 -c "
import json,sys
try:
    d=json.load(open('${OUTPUT_DIR}/sweep_${tag}_tput.json'))
    bps=d.get('end',{}).get('sum_received',{}).get('bits_per_second',0)
    print(f'{bps/1e9:.2f}')
except: print('?')
" 2>/dev/null || echo "?")
    log "  [u=${usecs:>3} f=${frames:>2}]  p99=${p99} µs   throughput=${gbps} Gbps"
}

# ── Sub-test A: Coalescing sweep ──────────────────────────────────────────────
run_coalescing_sweep() {
    info "=== Sub-test A: Coalescing sweep ==="
    local total=$(( ${#RX_USECS_GRID[@]} * ${#RX_FRAMES_GRID[@]} ))
    local done=0

    COALESCE_SAVED="${OUTPUT_DIR}/coalesce_orig.txt"
    save_coalescing "$IFACE" "$COALESCE_SAVED"

    for usecs in "${RX_USECS_GRID[@]}"; do
        for frames in "${RX_FRAMES_GRID[@]}"; do
            measure_point "$usecs" "$frames"
            ((done++)) || true
            log "  Progress: $done / $total"
        done
    done

    restore_coalescing "$IFACE" "$COALESCE_SAVED"
    ok "Coalescing sweep complete"
}

# ── Sub-test B: IRQ affinity comparison ──────────────────────────────────────
run_irq_affinity() {
    info "=== Sub-test B: IRQ affinity comparison ==="
    local secs=20

    # Mode 1: irqbalance (restore daemon temporarily)
    systemctl start irqbalance 2>/dev/null || service irqbalance start 2>/dev/null || true
    sleep 2
    sockperf ping-pong --ip "$PEER" --port "$SOCK_PORT" \
        --msg-size 64 --time "$secs" --mps 10000 --warmup-num 200 \
        > "${OUTPUT_DIR}/affinity_irqbalance.txt" 2>&1 || true
    systemctl stop irqbalance 2>/dev/null || service irqbalance stop 2>/dev/null || true

    # Mode 2: NUMA-pinned (all IRQs on NIC's NUMA node)
    pin_irqs_to_numa "$IFACE"
    sleep 1
    sockperf ping-pong --ip "$PEER" --port "$SOCK_PORT" \
        --msg-size 64 --time "$secs" --mps 10000 --warmup-num 200 \
        > "${OUTPUT_DIR}/affinity_numa_pinned.txt" 2>&1 || true

    # Mode 3: per-CPU pinned (one IRQ per queue, round-robin)
    local numa_node
    numa_node=$(cat /sys/class/net/"$IFACE"/device/numa_node 2>/dev/null || echo 0)
    local cpulist
    cpulist=$(cat /sys/devices/system/node/node"${numa_node}"/cpulist 2>/dev/null || echo "0-7")
    mapfile -t CPUS < <(python3 -c "
cpus=[]
for p in '${cpulist}'.split(','):
    if '-' in p:
        a,b=map(int,p.split('-')); cpus.extend(range(a,b+1))
    else: cpus.append(int(p))
print('\n'.join(map(str, cpus)))
")
    local cpu_idx=0
    for irq in $(grep -E "${IFACE}" /proc/interrupts | awk -F: '{print $1}' | tr -d ' '); do
        local cpu="${CPUS[$((cpu_idx % ${#CPUS[@]}))]}"
        local mask
        mask=$(python3 -c "print(hex(1 << $cpu))")
        echo "$mask" > /proc/irq/"$irq"/smp_affinity 2>/dev/null || true
        ((cpu_idx++)) || true
    done
    sleep 1
    sockperf ping-pong --ip "$PEER" --port "$SOCK_PORT" \
        --msg-size 64 --time "$secs" --mps 10000 --warmup-num 200 \
        > "${OUTPUT_DIR}/affinity_percpu.txt" 2>&1 || true

    ok "IRQ affinity comparison complete"
}

# ── Sub-test C: softirq under load ────────────────────────────────────────────
run_softirq_snapshot() {
    info "=== Sub-test C: softirq budget measurement ==="
    local secs=20

    pin_irqs_to_numa "$IFACE"

    # Set a known-good coalescing baseline
    set_coalescing "$IFACE" 50 16

    snapshot_softirq "${OUTPUT_DIR}/softirq_t0.json"
    iperf3 --client "$PEER" --time "$secs" --parallel 4 > /dev/null 2>&1 &
    local iperf_pid=$!
    sleep "$secs"
    wait "$iperf_pid" 2>/dev/null || true
    snapshot_softirq "${OUTPUT_DIR}/softirq_t1.json"

    ok "softirq snapshot done"
}

# ── Main flow ─────────────────────────────────────────────────────────────────
log "=== ${SUITE} starting ==="
log "  IFACE=$IFACE  PEER=$PEER  SWEEP_SECS=$SWEEP_SECS  QUICK=$QUICK_SWEEP"
log "  Grid: ${#RX_USECS_GRID[@]} × ${#RX_FRAMES_GRID[@]} = $(( ${#RX_USECS_GRID[@]} * ${#RX_FRAMES_GRID[@]} )) points"

ENV_FILE="${OUTPUT_DIR}/env.json"
snapshot_env "$IFACE" "$ENV_FILE"
check_link "$IFACE"
check_peer "$PEER"

DUT_MAC=$(ip link show "$IFACE" | awk '/ether/{print $2}')
DUT_IP=$(ip -4 addr show "$IFACE" | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
export DUT_MAC DUT_IP
info "DUT_MAC=$DUT_MAC  DUT_IP=$DUT_IP"

setup_cpu_isolation

run_coalescing_sweep
run_irq_affinity
run_softirq_snapshot

# ── Analysis & Report ─────────────────────────────────────────────────────────
RESULT="${OUTPUT_DIR}/result.json"
info "Running analyse.py..."
python3 "${SCRIPT_DIR}/analyse.py" \
    --results-dir "$OUTPUT_DIR"       \
    --rx-usecs    "${RX_USECS_GRID[*]}" \
    --rx-frames   "${RX_FRAMES_GRID[*]}" \
    --iface       "$IFACE"            \
    --output      "$RESULT"

REPORT="${SCRIPT_DIR}/REPORT.md"
info "Running report.py..."
python3 "${SCRIPT_DIR}/report.py" \
    --result   "$RESULT"   \
    --baseline "$BASELINE" \
    --env      "$ENV_FILE" \
    --output   "$REPORT"

restore_cpu_isolation

log "=== ${SUITE} complete ==="
log "  Results : $OUTPUT_DIR"
log "  Report  : $REPORT"
