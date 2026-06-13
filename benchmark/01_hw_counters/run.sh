#!/usr/bin/env bash
# 01_hw_counters/run.sh
#
# Collect ethtool -S hardware counters before and after a 30-second
# iperf3 traffic run, then produce a delta JSON and a Markdown report.
#
# Environment variables (override with env or command-line exports):
#   IFACE       — local NIC to benchmark        (default: eth0)
#   PEER        — IP of the back-to-back peer   (required)
#   DURATION    — iperf3 run time in seconds     (default: 30)
#   PARALLEL    — iperf3 parallel streams        (default: 4)
#   OUTPUT_DIR  — where to write results         (default: ./results)
#
# Prerequisites on PEER machine:
#   iperf3 -s -D     (iperf3 server running as daemon)
#
# Usage:
#   sudo PEER=192.168.1.2 bash 01_hw_counters/run.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

# ── Config ────────────────────────────────────────────────────────────────────
IFACE="${IFACE:-eth0}"
PEER="${PEER:-}"
DURATION="${DURATION:-30}"
PARALLEL="${PARALLEL:-4}"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/results}"
BASELINE="${SCRIPT_DIR}/baseline.json"
SUITE="01_hw_counters"

# ── Validation ────────────────────────────────────────────────────────────────
require_root
require_tool ethtool python3 ip
[[ -n "$PEER" ]] || die "PEER is not set. Export PEER=<ip> before running."

ensure_output_dir() { mkdir -p "$1"; }
ensure_output_dir "$OUTPUT_DIR"

log "=== ${SUITE} starting ==="
log "  IFACE=$IFACE  PEER=$PEER  DURATION=${DURATION}s  PARALLEL=$PARALLEL"

# ── Environment snapshot ──────────────────────────────────────────────────────
ENV_FILE="${OUTPUT_DIR}/env.json"
snapshot_env "$IFACE" "$ENV_FILE"

# ── Pre-flight ────────────────────────────────────────────────────────────────
check_link "$IFACE"
check_peer "$PEER"
setup_cpu_isolation
pin_irqs_to_numa "$IFACE"

# Give the system 2 s to settle after IRQ pinning
sleep 2

# ── T0 snapshot ───────────────────────────────────────────────────────────────
T0="${OUTPUT_DIR}/counters_t0.txt"
info "Capturing baseline counters (T0)..."
ethtool -S "$IFACE" > "$T0" 2>/dev/null || die "ethtool -S failed for $IFACE"
ok "T0 → $T0"

# ── Traffic ───────────────────────────────────────────────────────────────────
info "Starting TRex flood (${DURATION}s) → $PEER ..."
IPERF_LOG="${OUTPUT_DIR}/iperf3.json"
DURATION="$DURATION" PARALLEL="$PARALLEL" OUTPUT_DIR="$OUTPUT_DIR" \
    python3 "${SCRIPT_DIR}/trex_run.py" \
    || warn "TRex exited non-zero — check $OUTPUT_DIR"
ok "TRex flood finished"

# ── T1 snapshot ───────────────────────────────────────────────────────────────
T1="${OUTPUT_DIR}/counters_t1.txt"
info "Capturing counters after traffic (T1)..."
ethtool -S "$IFACE" > "$T1" 2>/dev/null || die "ethtool -S failed for $IFACE"
ok "T1 → $T1"

# ── Analysis ──────────────────────────────────────────────────────────────────
RESULT="${OUTPUT_DIR}/result.json"
info "Running collect.py..."
python3 "${SCRIPT_DIR}/collect.py" \
    --t0       "$T0"        \
    --t1       "$T1"        \
    --iperf    "$IPERF_LOG" \
    --duration "$DURATION"  \
    --iface    "$IFACE"     \
    --output   "$RESULT"

# ── Report ────────────────────────────────────────────────────────────────────
REPORT="${SCRIPT_DIR}/REPORT.md"
info "Running report.py..."
python3 "${SCRIPT_DIR}/report.py" \
    --result   "$RESULT"   \
    --baseline "$BASELINE" \
    --env      "$ENV_FILE" \
    --output   "$REPORT"

# ── Restore ───────────────────────────────────────────────────────────────────
restore_cpu_isolation

log "=== ${SUITE} complete ==="
log "  Results : $OUTPUT_DIR"
log "  Report  : $REPORT"
