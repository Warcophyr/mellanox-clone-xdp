#!/usr/bin/env bash
# 02_cpu_microarch/run.sh
#
# For each traffic scenario, run 'perf stat' system-wide while iperf3
# generates load, then hand off raw perf output to analyse.py + report.py.
#
# Environment variables:
#   IFACE       — local NIC                   (default: eth0)
#   PEER        — IP of back-to-back peer      (required)
#   PERF_SECS   — perf stat window in seconds  (default: 20)
#   WARMUP_SECS — seconds before perf starts   (default: 3)
#   OUTPUT_DIR  — where to write results       (default: ./results)
#
# Prerequisites on PEER machine:
#   iperf3 -s -D    (iperf3 server running as daemon)
#
# Usage:
#   sudo PEER=192.168.1.2 bash 02_cpu_microarch/run.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

# ── Config ────────────────────────────────────────────────────────────────────
IFACE="${IFACE:-eth0}"
PEER="${PEER:-}"
PERF_SECS="${PERF_SECS:-20}"
WARMUP_SECS="${WARMUP_SECS:-3}"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/results}"
BASELINE="${SCRIPT_DIR}/baseline.json"
SUITE="02_cpu_microarch"

# ── Validation ────────────────────────────────────────────────────────────────
require_root
require_tool perf python3 ip ethtool
[[ -n "$PEER" ]] || die "PEER is not set. Export PEER=<ip> before running."

mkdir -p "$OUTPUT_DIR"

# Resolve DUT addressing for TRex
DUT_MAC=$(ip link show "$IFACE" | awk '/ether/{print $2}')
DUT_IP=$(ip -4 addr show "$IFACE" | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
export DUT_MAC DUT_IP TREX_IP="$PEER"


# ── perf events ───────────────────────────────────────────────────────────────
# Grouped so perf can multiplex if the PMU has fewer counters than events.
PERF_EVENTS=(
    "cycles"
    "instructions"
    "cache-references"
    "cache-misses"
    "LLC-loads"
    "LLC-load-misses"
    "branch-instructions"
    "branch-misses"
    "dTLB-loads"
    "dTLB-load-misses"
    "iTLB-loads"
    "iTLB-load-misses"
    "context-switches"
    "cpu-migrations"
)
PERF_EVENTS_STR=$(IFS=,; echo "${PERF_EVENTS[*]}")

# ── Scenario definitions ──────────────────────────────────────────────────────
# Format: "name:iperf3_extra_args"
# The runner will start iperf3 as a background client with these args
# then run perf stat for $PERF_SECS, then kill iperf3.
declare -A SCENARIOS=(
    ["rx_burst_64"]="--reverse --length 64"
    ["tx_burst_64"]="--length 64"
    ["bidir_mixed"]="--bidir"
    ["tx_jumbo_9k"]="--length 9000 --set-mss 9000"
    ["tx_many_flows"]="--parallel 32 --length 1400"
)

# ── Scenario runner ───────────────────────────────────────────────────────────
run_scenario() {
    local name="$1"
    local iperf_args="$2"
    local perf_out="${OUTPUT_DIR}/perf_${name}.txt"
    local pkts_t0="${OUTPUT_DIR}/pkts_${name}_t0.txt"
    local pkts_t1="${OUTPUT_DIR}/pkts_${name}_t1.txt"

    info "── Scenario: $name ──────────────────────────────────"
    info "  iperf3 args : $iperf_args"
    info "  perf window : ${PERF_SECS}s"

    # Snapshot packet counters at T0
    ethtool -S "$IFACE" > "$pkts_t0" 2>/dev/null || true

    # Start TRex background traffic matching the scenario pattern
    local total_dur=$(( PERF_SECS + WARMUP_SECS + 5 ))
    DURATION=$total_dur OUTPUT_DIR="$OUTPUT_DIR" \
        python3 "${SCRIPT_DIR}/trex_run.py" --scenario "$name" --duration "$total_dur" &
    local iperf_pid=$!

    # Let traffic warm up before measuring
    sleep "$WARMUP_SECS"

    # Run perf stat over the measurement window
    perf stat \
        --all-cpus \
        --no-big-num \
        --event "$PERF_EVENTS_STR" \
        --output "$perf_out" \
        -- sleep "$PERF_SECS" \
        2>&1 || warn "perf stat exited non-zero for scenario $name"

    # Stop TRex background process
    kill "$iperf_pid" 2>/dev/null || true
    wait "$iperf_pid" 2>/dev/null || true

    # Snapshot packet counters at T1
    ethtool -S "$IFACE" > "$pkts_t1" 2>/dev/null || true

    ok "Scenario $name done → $perf_out"
}

# ── Main flow ─────────────────────────────────────────────────────────────────
log "=== ${SUITE} starting ==="
log "  IFACE=$IFACE  PEER=$PEER  PERF_SECS=$PERF_SECS"

ENV_FILE="${OUTPUT_DIR}/env.json"
snapshot_env "$IFACE" "$ENV_FILE"

check_link "$IFACE"
check_peer "$PEER"
setup_cpu_isolation
pin_irqs_to_numa "$IFACE"

sleep 2  # settle

for scenario in "${!SCENARIOS[@]}"; do
    run_scenario "$scenario" "${SCENARIOS[$scenario]}"
    sleep 2  # cool-down between scenarios
done

# ── Analysis ──────────────────────────────────────────────────────────────────
RESULT="${OUTPUT_DIR}/result.json"
info "Running analyse.py..."
python3 "${SCRIPT_DIR}/analyse.py" \
    --perf-dir  "$OUTPUT_DIR" \
    --duration  "$PERF_SECS" \
    --iface     "$IFACE"     \
    --output    "$RESULT"

# ── Report ────────────────────────────────────────────────────────────────────
REPORT="${SCRIPT_DIR}/REPORT.md"
info "Running report.py..."
python3 "${SCRIPT_DIR}/report.py" \
    --result    "$RESULT"   \
    --baseline  "$BASELINE" \
    --env       "$ENV_FILE" \
    --output    "$REPORT"

restore_cpu_isolation

log "=== ${SUITE} complete ==="
log "  Results : $OUTPUT_DIR"
log "  Report  : $REPORT"
