#!/usr/bin/env bash
# 10_stress/run.sh
#
# Sub-tests:
#   A) Long-run packet loss  — iperf3 UDP 90% for STRESS_DURATION seconds
#      (polls ethtool -S every POLL_INTERVAL seconds via monitor.py)
#   B) Link flap recovery    — ip link down/up × FLAP_COUNT, measure RTT recovery
#   C) Memory leak detection — slab delta + kmemleak (if kernel supports it)
#   D) Lock contention       — perf lock record during traffic
#
# Usage:
#   sudo PEER=192.168.1.2 bash 10_stress/run.sh
#   sudo STRESS_DURATION=300 PEER=192.168.1.2 bash 10_stress/run.sh  # 5-min run

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

IFACE="${IFACE:-eth0}"
PEER="${PEER:-}"
STRESS_DURATION="${STRESS_DURATION:-1800}"   # 30 min default
POLL_INTERVAL="${POLL_INTERVAL:-10}"
FLAP_COUNT="${FLAP_COUNT:-20}"
LOCK_SECS="${LOCK_SECS:-30}"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/results}"
META="${OUTPUT_DIR}/meta.json"

require_root
require_tool python3 ip ping ethtool
[[ -n "$PEER" ]] || die "PEER is not set."
mkdir -p "$OUTPUT_DIR"

# Resolve DUT addressing for TRex
DUT_MAC=$(ip link show "$IFACE" | awk '/ether/{print $2}')
DUT_IP=$(ip -4 addr show "$IFACE" | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
export DUT_MAC DUT_IP TREX_IP="$PEER"


# ── Sub-test A: Long-run packet loss ──────────────────────────────────────────
run_longrun() {
    info "=== Sub-test A: Long-run packet loss (${STRESS_DURATION}s) ==="
    local monitor_log="${OUTPUT_DIR}/monitor.jsonl"
    local iperf_log="${OUTPUT_DIR}/longrun_iperf.json"

    # Get link speed for 90% rate target
    local speed_mbps
    speed_mbps=$(ethtool "$IFACE" 2>/dev/null | grep -oP 'Speed: \K\d+' || echo 10000)
    local target_bps=$(( speed_mbps * 90 * 1000 / 100 ))
    info "  Target: 90% of ${speed_mbps} Mbps = ${target_bps} bps"

    # Start counter monitor in background
    python3 "${SCRIPT_DIR}/monitor.py" \
        --iface    "$IFACE" \
        --interval "$POLL_INTERVAL" \
        --output   "$monitor_log" &
    local monitor_pid=$!

    # Run TRex at 90% line rate with live stats polling
    STRESS_DURATION="$STRESS_DURATION" POLL_INTERVAL="$POLL_INTERVAL" \
    OUTPUT_DIR="$OUTPUT_DIR" \
        python3 "${SCRIPT_DIR}/trex_run.py" \
        || warn "TRex long-run non-zero"

    # Stop monitor
    kill "$monitor_pid" 2>/dev/null || true
    wait "$monitor_pid" 2>/dev/null || true
    ok "Long-run test complete. Monitor log: $monitor_log"
}

# ── Sub-test B: Link flap recovery ────────────────────────────────────────────
run_link_flap() {
    info "=== Sub-test B: Link flap recovery (${FLAP_COUNT} flaps) ==="
    local flap_log="${OUTPUT_DIR}/flap_recovery.jsonl"

    for i in $(seq 1 "$FLAP_COUNT"); do
        local t_down t_up recovery_ms

        # Bring link down
        t_down=$(date +%s%N)
        ip link set "$IFACE" down 2>/dev/null
        sleep 1
        ip link set "$IFACE" up   2>/dev/null

        # Poll until first successful ping (up to 10s)
        local recovered=0
        local attempts=0
        while [[ $attempts -lt 100 ]]; do
            if ping -c 1 -W 1 "$PEER" &>/dev/null; then
                t_up=$(date +%s%N)
                recovery_ms=$(( (t_up - t_down) / 1000000 ))
                recovered=1
                break
            fi
            sleep 0.1
            ((attempts++)) || true
        done

        if [[ $recovered -eq 1 ]]; then
            echo "{\"flap\": $i, \"recovery_ms\": $recovery_ms}" >> "$flap_log"
            log "  Flap $i: ${recovery_ms}ms recovery"
        else
            echo "{\"flap\": $i, \"recovery_ms\": null, \"timeout\": true}" >> "$flap_log"
            warn "  Flap $i: TIMEOUT (>10s) — link may not have come back"
        fi
        sleep 1
    done

    # Check dmesg for WARNs/ERRs during flap test
    dmesg --since "5 minutes ago" 2>/dev/null \
        | grep -E 'WARN|BUG|ERROR|mlx5|eno|eth' \
        > "${OUTPUT_DIR}/dmesg_flap.txt" || true
    ok "Link flap test complete → $flap_log"
}

# ── Sub-test C: Memory leak detection ─────────────────────────────────────────
run_memleak() {
    info "=== Sub-test C: Memory leak detection ==="

    # Slab snapshot before
    python3 - "${OUTPUT_DIR}/memleak_slab_t0.json" <<'PY'
import json, sys
from pathlib import Path
result = {}
for line in Path('/proc/slabinfo').read_text().splitlines()[2:]:
    parts = line.split()
    if len(parts) >= 3:
        result[parts[0]] = int(parts[2])  # num_objs
Path(sys.argv[1]).write_text(json.dumps(result))
PY

    # kmemleak scan before traffic
    if [[ -f /sys/kernel/debug/kmemleak ]]; then
        info "  kmemleak: triggering initial scan..."
        echo clear  > /sys/kernel/debug/kmemleak
        echo scan   > /sys/kernel/debug/kmemleak
    fi

    # Run moderate traffic for SLAB_DURATION seconds
    local slab_secs=120
    iperf3 --client "$PEER" --time "$slab_secs" --parallel 4 > /dev/null 2>&1 || true

    # Slab snapshot after
    python3 - "${OUTPUT_DIR}/memleak_slab_t1.json" <<'PY'
import json, sys
from pathlib import Path
result = {}
for line in Path('/proc/slabinfo').read_text().splitlines()[2:]:
    parts = line.split()
    if len(parts) >= 3:
        result[parts[0]] = int(parts[2])
Path(sys.argv[1]).write_text(json.dumps(result))
PY

    # kmemleak report after traffic
    if [[ -f /sys/kernel/debug/kmemleak ]]; then
        echo scan   > /sys/kernel/debug/kmemleak
        sleep 5
        cat /sys/kernel/debug/kmemleak > "${OUTPUT_DIR}/kmemleak_report.txt"
        ok "  kmemleak report → ${OUTPUT_DIR}/kmemleak_report.txt"
    else
        warn "  kmemleak not available (enable CONFIG_DEBUG_KMEMLEAK)"
        echo "NOT_AVAILABLE" > "${OUTPUT_DIR}/kmemleak_report.txt"
    fi
}

# ── Sub-test D: Lock contention ───────────────────────────────────────────────
run_lock_contention() {
    info "=== Sub-test D: Lock contention ==="

    if ! perf lock record -- sleep 0.1 &>/dev/null; then
        warn "perf lock not available — skipping"
        echo "NOT_AVAILABLE" > "${OUTPUT_DIR}/lock_report.txt"
        return
    fi

    iperf3 --client "$PEER" \
           --time $(( LOCK_SECS + 5 )) \
           --parallel 4 \
           > /dev/null 2>&1 &
    local iperf_pid=$!
    sleep 2

    perf lock record \
        --output "${OUTPUT_DIR}/perf_lock.data" \
        -- sleep "$LOCK_SECS" 2>/dev/null || true

    kill "$iperf_pid" 2>/dev/null || true
    wait "$iperf_pid" 2>/dev/null || true

    perf lock report \
        --input "${OUTPUT_DIR}/perf_lock.data" \
        2>/dev/null \
        | head -40 > "${OUTPUT_DIR}/lock_report.txt" \
        || warn "perf lock report failed"

    ok "Lock contention report → ${OUTPUT_DIR}/lock_report.txt"
}

# ── Main ──────────────────────────────────────────────────────────────────────
log "=== 10_stress starting ==="
log "  STRESS_DURATION=${STRESS_DURATION}s  FLAP_COUNT=$FLAP_COUNT"

ENV_FILE="${OUTPUT_DIR}/env.json"
snapshot_env "$IFACE" "$ENV_FILE"
check_link "$IFACE"
check_peer "$PEER"
setup_cpu_isolation
pin_irqs_to_numa "$IFACE"
sleep 2

run_longrun
run_link_flap
run_memleak
run_lock_contention

RESULT="${OUTPUT_DIR}/result.json"
python3 "${SCRIPT_DIR}/report.py" \
    --results-dir "$OUTPUT_DIR" \
    --iface       "$IFACE" \
    --baseline    "${SCRIPT_DIR}/baseline.json" \
    --env         "$ENV_FILE" \
    --output      "${SCRIPT_DIR}/REPORT.md" \
    --meta        "$META" \
    --result-out  "$RESULT"

restore_cpu_isolation
log "=== 10_stress complete ==="
