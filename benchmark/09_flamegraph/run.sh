#!/usr/bin/env bash
# 09_flamegraph/run.sh
#
# For each traffic scenario: perf record → stackcollapse → flamegraph SVG.
# Scenarios: rx_flood_64, tx_flood_64, rx_bulk_9k, tx_tso_bulk, bidir_100pct
#
# Prerequisites:
#   - FlameGraph scripts: https://github.com/brendangregg/FlameGraph
#     Set FLAMEGRAPH_DIR or ensure stackcollapse-perf.pl/flamegraph.pl are on PATH
#   - Kernel built with frame pointers (or use --call-graph dwarf)
#
# Usage:
#   sudo PEER=192.168.1.2 FLAMEGRAPH_DIR=/opt/FlameGraph bash 09_flamegraph/run.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

IFACE="${IFACE:-eth0}"
PEER="${PEER:-}"
RECORD_SECS="${RECORD_SECS:-20}"
WARMUP_SECS="${WARMUP_SECS:-3}"
PERF_FREQ="${PERF_FREQ:-999}"
FLAMEGRAPH_DIR="${FLAMEGRAPH_DIR:-/usr/local/FlameGraph}"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/results}"
META="${OUTPUT_DIR}/meta.json"

require_root
require_tool perf python3 ip
[[ -n "$PEER" ]] || die "PEER is not set."
mkdir -p "$OUTPUT_DIR"

# Resolve DUT addressing for TRex
DUT_MAC=$(ip link show "$IFACE" | awk '/ether/{print $2}')
DUT_IP=$(ip -4 addr show "$IFACE" | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
export DUT_MAC DUT_IP TREX_IP="$PEER"


# ── Locate FlameGraph scripts ─────────────────────────────────────────────────
COLLAPSE=""
FLAMEGRAPH_PL=""
for dir in "$FLAMEGRAPH_DIR" /opt/FlameGraph /usr/share/FlameGraph; do
    if [[ -x "${dir}/stackcollapse-perf.pl" ]]; then
        COLLAPSE="${dir}/stackcollapse-perf.pl"
        FLAMEGRAPH_PL="${dir}/flamegraph.pl"
        break
    fi
done
if command -v stackcollapse-perf.pl &>/dev/null; then
    COLLAPSE="stackcollapse-perf.pl"
    FLAMEGRAPH_PL="flamegraph.pl"
fi

if [[ -z "$COLLAPSE" ]]; then
    warn "FlameGraph scripts not found."
    warn "Install with: git clone https://github.com/brendangregg/FlameGraph ${FLAMEGRAPH_DIR}"
    warn "SVG generation will be skipped — perf.data files will still be recorded."
    FLAMEGRAPH_AVAIL=0
else
    ok "FlameGraph found: $COLLAPSE"
    FLAMEGRAPH_AVAIL=1
fi

# Choose call-graph method: lbr > fp > dwarf (in order of overhead)
CALLGRAPH="fp"
if perf record --call-graph lbr -e cycles -- sleep 0.1 &>/dev/null; then
    CALLGRAPH="lbr"
    ok "Using LBR call graphs (low overhead)"
elif perf record --call-graph fp -e cycles -- sleep 0.1 &>/dev/null; then
    CALLGRAPH="fp"
    ok "Using frame-pointer call graphs"
else
    CALLGRAPH="dwarf"
    warn "Falling back to DWARF call graphs (high memory, slow)"
fi

# ── Core record + generate function ──────────────────────────────────────────
# record_flame <scenario_name> <traffic_cmd_in_background>
record_flame() {
    local name="$1"
    local perf_data="${OUTPUT_DIR}/perf_${name}.data"
    local perf_script="${OUTPUT_DIR}/perf_${name}.script"
    local folded="${OUTPUT_DIR}/perf_${name}.folded"
    local svg="${SCRIPT_DIR}/${name}.svg"
    local top10="${OUTPUT_DIR}/top10_${name}.txt"

    info "  [$name] recording ${RECORD_SECS}s..."

    # Start TRex background traffic for this scenario
    DURATION=$(( RECORD_SECS + WARMUP_SECS + 5 )) OUTPUT_DIR="$OUTPUT_DIR" \
        python3 "${SCRIPT_DIR}/trex_run.py" --scenario "$name" &
    local traffic_pid=$!
    sleep "$WARMUP_SECS"

    # Record
    perf record \
        --all-cpus \
        --freq "$PERF_FREQ" \
        --call-graph "$CALLGRAPH" \
        --output "$perf_data" \
        -- sleep "$RECORD_SECS" \
        2>/dev/null || warn "  perf record exited non-zero for $name"

    # Stop traffic
    kill "$traffic_pid" 2>/dev/null || true
    wait "$traffic_pid" 2>/dev/null || true

    # Extract top-10 symbols
    perf report --input "$perf_data" --stdio --no-children \
        2>/dev/null | head -50 | grep -E '^\s+[0-9]+\.' \
        > "$top10" 2>/dev/null || true

    # Generate SVG if FlameGraph available
    if [[ $FLAMEGRAPH_AVAIL -eq 1 ]]; then
        perf script --input "$perf_data" 2>/dev/null > "$perf_script"
        "$COLLAPSE" "$perf_script" > "$folded"
        "$FLAMEGRAPH_PL" \
            --title "${name} — $(date '+%Y-%m-%d')" \
            --width 1600 \
            --colors java \
            "$folded" > "$svg"
        ok "  [$name] SVG → $svg"
    fi
}

# ── Scenarios ─────────────────────────────────────────────────────────────────
log "=== 09_flamegraph starting ==="
ENV_FILE="${OUTPUT_DIR}/env.json"
snapshot_env "$IFACE" "$ENV_FILE"
check_link "$IFACE"
check_peer "$PEER"
setup_cpu_isolation
pin_irqs_to_numa "$IFACE"
sleep 2

# 1. RX flood 64B (--reverse: server sends to us)
record_flame "rx_flood_64"
           --parallel 4 --reverse --length 64
sleep 2

# 2. TX flood 64B
record_flame "tx_flood_64"
           --parallel 4 --length 64
sleep 2

# 3. RX bulk 9K jumbo
record_flame "rx_bulk_9k"
           --parallel 4 --reverse --length 9000
sleep 2

# 4. TX TSO bulk (large TCP segments, driver does segmentation)
record_flame "tx_tso_bulk"
           --parallel 4 --length 128k
sleep 2

# 5. Bidirectional full rate
record_flame "bidir_full"
           --parallel 4 --bidir
sleep 2

python3 "${SCRIPT_DIR}/report.py" \
    --results-dir "$OUTPUT_DIR" \
    --script-dir  "$SCRIPT_DIR" \
    --flamegraph-avail "$FLAMEGRAPH_AVAIL" \
    --env "$ENV_FILE" \
    --output "${SCRIPT_DIR}/REPORT.md" \
    --meta "$META"

restore_cpu_isolation
log "=== 09_flamegraph complete ==="
