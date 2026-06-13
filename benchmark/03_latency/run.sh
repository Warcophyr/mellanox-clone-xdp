#!/usr/bin/env bash
# 03_latency/run.sh
#
# Measure RTT latency via sockperf ping-pong across five scenario classes:
#
#   1. no_load_<size>       — 1 msg/s at 64 / 512 / 1400 / 4096 B (pure driver overhead)
#   2. loaded_<rate>_<size> — 10 k / 100 k msg/s at 64 B and 1400 B
#   3. busy_poll_<rate>     — repeat loaded scenarios with SO_BUSY_POLL enabled
#
# Environment variables:
#   IFACE        — local NIC                    (default: eth0)
#   PEER         — IP of back-to-back peer       (required)
#   SOCK_PORT    — sockperf server port          (default: 11111)
#   DURATION     — measurement window (seconds) (default: 30)
#   WARMUP       — warmup messages               (default: 400)
#   OUTPUT_DIR   — where to write results        (default: ./results)
#
# Prerequisites on PEER machine:
#   sockperf server --port 11111 --no-block &
#
# Usage:
#   sudo PEER=192.168.1.2 bash 03_latency/run.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

# ── Config ────────────────────────────────────────────────────────────────────
IFACE="${IFACE:-eth0}"
PEER="${PEER:-}"
SOCK_PORT="${SOCK_PORT:-11111}"
DURATION="${DURATION:-30}"
WARMUP="${WARMUP:-400}"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/results}"
BASELINE="${SCRIPT_DIR}/baseline.json"
SUITE="03_latency"

# ── Validation ────────────────────────────────────────────────────────────────
require_root
require_tool sockperf python3 ip ping sysctl
[[ -n "$PEER" ]] || die "PEER is not set. Export PEER=<ip> before running."
mkdir -p "$OUTPUT_DIR"

# ── Busy-poll sysctl helpers ──────────────────────────────────────────────────
ORIG_BUSY_POLL=$(sysctl -n net.core.busy_poll 2>/dev/null || echo 0)
ORIG_BUSY_READ=$(sysctl -n net.core.busy_read 2>/dev/null || echo 0)

enable_busy_poll() {
    info "Enabling SO_BUSY_POLL (50 µs)..."
    sysctl -qw net.core.busy_poll=50
    sysctl -qw net.core.busy_read=50
}
disable_busy_poll() {
    sysctl -qw net.core.busy_poll=0
    sysctl -qw net.core.busy_read=0
}
restore_busy_poll() {
    sysctl -qw net.core.busy_poll="$ORIG_BUSY_POLL" || true
    sysctl -qw net.core.busy_read="$ORIG_BUSY_READ" || true
}

# ── Core scenario runner ──────────────────────────────────────────────────────
# run_sockperf <name> <msg_size_bytes> <rate_msg_per_s|"max"> [<extra_args>...]
run_sockperf() {
    local name="$1"
    local size="$2"
    local rate="$3"
    shift 3

    local summary="${OUTPUT_DIR}/summary_${name}.txt"
    local fulllog="${OUTPUT_DIR}/raw_${name}.csv"

    info "  [$name] size=${size}B  rate=${rate}msg/s  dur=${DURATION}s"

    local rate_arg=""
    [[ "$rate" != "max" ]] && rate_arg="--mps $rate"

    # shellcheck disable=SC2086
    sockperf ping-pong \
        --ip       "$PEER" \
        --port     "$SOCK_PORT" \
        --msg-size "$size" \
        --time     "$DURATION" \
        --warmup-num "$WARMUP" \
        --full-log "$fulllog" \
        $rate_arg \
        "$@" \
        > "$summary" 2>&1 \
        || warn "sockperf exited non-zero for $name — check $summary"

    ok "  [$name] done → $summary"
}

# ── Main flow ─────────────────────────────────────────────────────────────────
log "=== ${SUITE} starting ==="
log "  IFACE=$IFACE  PEER=$PEER  DURATION=${DURATION}s"

ENV_FILE="${OUTPUT_DIR}/env.json"
snapshot_env "$IFACE" "$ENV_FILE"

check_link "$IFACE"
check_peer "$PEER"

# Verify sockperf server is reachable on peer
info "Checking sockperf server on ${PEER}:${SOCK_PORT}..."
sockperf ping-pong --ip "$PEER" --port "$SOCK_PORT" \
    --msg-size 64 --time 2 --mps 10 \
    > /dev/null 2>&1 \
    || die "sockperf server not responding on ${PEER}:${SOCK_PORT}. Start it with: sockperf server --port ${SOCK_PORT}"
ok "sockperf server is responding"

setup_cpu_isolation
pin_irqs_to_numa "$IFACE"
sleep 2  # settle

# ── Resolve DUT MAC + IP (TRex needs them to address packets) ─────────────────
DUT_MAC=$(ip link show "$IFACE" | awk '/ether/{print $2}')
DUT_IP=$(ip -4 addr show "$IFACE" | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
export DUT_MAC DUT_IP TREX_IP="$PEER"
info "DUT_MAC=$DUT_MAC  DUT_IP=$DUT_IP  TREX_IP=$PEER"

# ── Classes 1, 2, 3a+3b — all driven by trex_run.py ─────────────────────────
# trex_run.py runs all no-load, loaded, and busy-poll scenarios in sequence.
# busy-poll sysctl is toggled by trex_run.py internally via the env flag.
info "=== Running TRex latency scenarios ==="
disable_busy_poll
python3 "${SCRIPT_DIR}/trex_run.py"     || warn "TRex run exited non-zero — check OUTPUT_DIR for partial results"
restore_busy_poll

# ── Analysis & Report ─────────────────────────────────────────────────────────
RESULT="${OUTPUT_DIR}/result.json"
info "Running analyse.py..."
python3 "${SCRIPT_DIR}/analyse.py" \
    --results-dir "$OUTPUT_DIR" \
    --iface       "$IFACE"     \
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
