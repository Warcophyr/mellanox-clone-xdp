#!/usr/bin/env bash
# run_all.sh — Mellanox driver benchmark suite orchestrator
#
# Runs all 10 benchmark suites in order and generates SUMMARY.md.
#
# Environment variables:
#   IFACE         — local NIC to benchmark         (required)
#   PEER          — IP of back-to-back peer         (required)
#   SUITES        — comma-separated subset to run   (default: all)
#                   e.g. SUITES=01,02,09
#   QUICK         — "1" to use reduced parameters   (default: 0)
#   STRESS_DURATION — override stress run duration  (default: 1800)
#
# Usage:
#   sudo IFACE=eth0 PEER=192.168.1.2 bash run_all.sh
#   sudo IFACE=eth0 PEER=192.168.1.2 SUITES=02,04,09 bash run_all.sh
#   sudo IFACE=eth0 PEER=192.168.1.2 QUICK=1 bash run_all.sh

set -euo pipefail
BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${BENCH_DIR}/lib/common.sh"

IFACE="${IFACE:-}"
PEER="${PEER:-}"
QUICK="${QUICK:-0}"
SUITES_ARG="${SUITES:-all}"

[[ -n "$IFACE" ]] || die "IFACE is not set. Export IFACE=<interface_name>."
[[ -n "$PEER"  ]] || die "PEER is not set.  Export PEER=<peer_ip>."

RUN_ID="$(date +%Y%m%d_%H%M%S)"
LOG_DIR="${BENCH_DIR}/run_logs/${RUN_ID}"
mkdir -p "$LOG_DIR"

# ── Suite registry ────────────────────────────────────────────────────────────
declare -A SUITE_NAMES=(
    ["01"]="01_hw_counters"
    ["02"]="02_cpu_microarch"
    ["03"]="03_latency"
    ["04"]="04_throughput"
    ["05"]="05_interrupt"
    ["06"]="06_memory_dma"
    ["07"]="07_queue_scaling"
    ["08"]="08_offloads"
    ["09"]="09_flamegraph"
    ["10"]="10_stress"
    ["11"]="11_ebpf_xdp"
)

# Override parameters for quick mode
if [[ "$QUICK" == "1" ]]; then
    export DURATION=10
    export PERF_SECS=10
    export SWEEP_SECS=8
    export QUICK_SWEEP=1
    export STRESS_DURATION=120
    export FLAP_COUNT=5
    export RECORD_SECS=10
    export SLAB_DURATION=30
    warn "QUICK mode: reduced durations (not suitable for production benchmarking)"
fi

# ── Build suite list ──────────────────────────────────────────────────────────
if [[ "$SUITES_ARG" == "all" ]]; then
    RUN_SUITES=("01" "02" "03" "04" "05" "06" "07" "08" "09" "10" "11")
else
    IFS=',' read -ra RUN_SUITES <<< "$SUITES_ARG"
fi

# ── Run a single suite ────────────────────────────────────────────────────────
run_suite() {
    local num="$1"
    local name="${SUITE_NAMES[$num]:-}"
    [[ -n "$name" ]] || { warn "Unknown suite number: $num"; return 1; }

    local suite_dir="${BENCH_DIR}/${name}"
    local run_sh="${suite_dir}/run.sh"
    local log_file="${LOG_DIR}/${name}.log"

    if [[ ! -f "$run_sh" ]]; then
        warn "Suite $name not found at $run_sh — skipping"
        return 0
    fi

    log "▶ Starting suite: $name"
    local t_start=$SECONDS

    IFACE="$IFACE" PEER="$PEER" bash "$run_sh" \
        2>&1 | tee "$log_file"
    local exit_code="${PIPESTATUS[0]}"

    local elapsed=$(( SECONDS - t_start ))
    if [[ $exit_code -eq 0 ]]; then
        ok "✓ Suite $name completed in ${elapsed}s"
    else
        warn "⚠ Suite $name exited with code $exit_code after ${elapsed}s (see $log_file)"
    fi
    return 0
}

# ── Main ──────────────────────────────────────────────────────────────────────
log "════════════════════════════════════════════════════"
log "  Mellanox Driver Benchmark Suite"
log "  Run ID  : $RUN_ID"
log "  IFACE   : $IFACE"
log "  PEER    : $PEER"
log "  Suites  : ${RUN_SUITES[*]}"
log "  Quick   : $QUICK"
log "════════════════════════════════════════════════════"

TOTAL=${#RUN_SUITES[@]}
DONE=0
FAILED=()

for num in "${RUN_SUITES[@]}"; do
    run_suite "$num" || FAILED+=("${SUITE_NAMES[$num]:-$num}")
    ((DONE++)) || true
    log "Progress: $DONE/$TOTAL suites done"
    echo ""
done

# ── Generate SUMMARY.md ───────────────────────────────────────────────────────
log "Generating SUMMARY.md..."
python3 "${BENCH_DIR}/lib/summary.py" \
    --benchmark-root "$BENCH_DIR" \
    --output "${BENCH_DIR}/SUMMARY.md"

log "════════════════════════════════════════════════════"
log "  All suites finished."
log "  Logs    : $LOG_DIR"
log "  Summary : ${BENCH_DIR}/SUMMARY.md"
if [[ ${#FAILED[@]} -gt 0 ]]; then
    warn "  Failed  : ${FAILED[*]}"
fi
log "════════════════════════════════════════════════════"
