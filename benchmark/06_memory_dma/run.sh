#!/usr/bin/env bash
# 06_memory_dma/run.sh
#
# Sub-tests:
#   A) DMA alloc/free timing — bpftrace kprobe (falls back to ftrace)
#   B) NUMA placement penalty — numactl cross-node vs local-node iperf3
#   C) Hugepage impact        — 4K pages vs 2M hugepages
#   D) Slab pressure          — /proc/slabinfo delta during 5-min traffic run
#
# Usage:
#   sudo PEER=192.168.1.2 bash 06_memory_dma/run.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

IFACE="${IFACE:-eth0}"
PEER="${PEER:-}"
DURATION="${DURATION:-30}"
SLAB_DURATION="${SLAB_DURATION:-120}"   # 2-min slab run (use 300 for full test)
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/results}"
BASELINE="${SCRIPT_DIR}/baseline.json"
META="${OUTPUT_DIR}/meta.json"

require_root
require_tool numactl python3 ip
[[ -n "$PEER" ]] || die "PEER is not set."
mkdir -p "$OUTPUT_DIR"

# Resolve DUT addressing for TRex
DUT_MAC=$(ip link show "$IFACE" | awk '/ether/{print $2}')
DUT_IP=$(ip -4 addr show "$IFACE" | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
export DUT_MAC DUT_IP TREX_IP="$PEER"


NUMA_NODE=$(cat /sys/class/net/"$IFACE"/device/numa_node 2>/dev/null || echo 0)

# ── Sub-test A: DMA alloc/free latency ───────────────────────────────────────
run_dma_timing() {
    info "=== Sub-test A: DMA alloc/free timing ==="
    local out="${OUTPUT_DIR}/dma_timing.txt"

    if command -v bpftrace &>/dev/null; then
        info "  Using bpftrace kprobes..."
        # Measure dma_alloc_coherent and dma_map_single latency during NIC traffic
        # Run bpftrace for DURATION seconds while iperf3 generates load
        iperf3 --client "$PEER" --time $(( DURATION + 5 )) --parallel 4 \
               > /dev/null 2>&1 &
        local iperf_pid=$!
        sleep 2

        timeout "$DURATION" bpftrace - <<'BPFTRACE' > "$out" 2>&1 || true
interval:s:1 { printf("tick\n"); }

kprobe:dma_alloc_coherent
{
    @dma_alloc_start[tid] = nsecs;
}
kretprobe:dma_alloc_coherent
/ @dma_alloc_start[tid] /
{
    @dma_alloc_lat_ns = hist(nsecs - @dma_alloc_start[tid]);
    @dma_alloc_count++;
    delete(@dma_alloc_start[tid]);
}

kprobe:dma_map_single
{
    @dma_map_start[tid] = nsecs;
}
kretprobe:dma_map_single
/ @dma_map_start[tid] /
{
    @dma_map_lat_ns = hist(nsecs - @dma_map_start[tid]);
    @dma_map_count++;
    delete(@dma_map_start[tid]);
}

END
{
    printf("dma_alloc_count: %d\n", @dma_alloc_count);
    printf("dma_map_count:   %d\n", @dma_map_count);
    print(@dma_alloc_lat_ns);
    print(@dma_map_lat_ns);
}
BPFTRACE
        kill "$iperf_pid" 2>/dev/null || true
        ok "  bpftrace DMA timing complete → $out"

    elif [[ -d /sys/kernel/debug/tracing ]]; then
        info "  Using ftrace function_graph (bpftrace not available)..."
        local tracefs="/sys/kernel/debug/tracing"
        echo 0         > "${tracefs}/tracing_on"
        echo "function_graph" > "${tracefs}/current_tracer"
        echo "dma_alloc_coherent" > "${tracefs}/set_graph_function"
        echo "dma_map_single"     >> "${tracefs}/set_graph_function"
        echo 1         > "${tracefs}/tracing_on"

        iperf3 --client "$PEER" --time "$DURATION" --parallel 4 > /dev/null 2>&1

        echo 0         > "${tracefs}/tracing_on"
        head -2000 "${tracefs}/trace" > "$out"
        echo nop       > "${tracefs}/current_tracer"
        ok "  ftrace DMA timing complete → $out"
    else
        warn "  Neither bpftrace nor ftrace available — skipping DMA timing"
        echo "UNAVAILABLE" > "$out"
    fi
}

# ── Sub-test B: NUMA placement ────────────────────────────────────────────────
run_numa() {
    info "=== Sub-test B: NUMA placement ==="
    local local_node="$NUMA_NODE"
    local remote_node
    remote_node=$(python3 -c "
nodes=[int(d.name.replace('node','')) for d in __import__('pathlib').Path('/sys/devices/system/node').glob('node[0-9]*')]
local_n = $local_node
remote = [n for n in nodes if n != local_n]
print(remote[0] if remote else local_n)
")

    info "  Local NUMA test (node $local_node → node $local_node)..."
    numactl --cpunodebind="$local_node" --membind="$local_node" \
        env TEST_LABEL="numa_local" DURATION="$DURATION" OUTPUT_DIR="$OUTPUT_DIR" \
        python3 "${SCRIPT_DIR}/trex_run.py" || warn "TRex numa_local non-zero"

    if [[ "$remote_node" != "$local_node" ]]; then
        info "  Cross-NUMA test (cpu=node $local_node, mem=node $remote_node)..."
        numactl --cpunodebind="$local_node" --membind="$remote_node" \
            env TEST_LABEL="numa_remote" DURATION="$DURATION" OUTPUT_DIR="$OUTPUT_DIR" \
            python3 "${SCRIPT_DIR}/trex_run.py" || warn "TRex numa_remote non-zero"
    else
        warn "  Single-NUMA system — skipping cross-NUMA test"
        echo '{"single_numa": true}' > "${OUTPUT_DIR}/numa_remote.json"
    fi
}

# ── Sub-test C: Hugepage impact ───────────────────────────────────────────────
run_hugepage() {
    info "=== Sub-test C: Hugepage impact ==="

    # Save original hugepage count
    local orig_hp
    orig_hp=$(cat /proc/sys/vm/nr_hugepages 2>/dev/null || echo 0)

    # Test 1: No hugepages
    echo 0 > /proc/sys/vm/nr_hugepages
    sleep 1
    TEST_LABEL="hugepage_none" DURATION="$DURATION" OUTPUT_DIR="$OUTPUT_DIR" \
        python3 "${SCRIPT_DIR}/trex_run.py" || warn "TRex hugepage_none non-zero"

    # Test 2: 512 × 2M hugepages = 1 GB pre-allocated
    echo 512 > /proc/sys/vm/nr_hugepages
    sleep 2   # give kernel time to allocate
    local actual_hp
    actual_hp=$(grep HugePages_Total /proc/meminfo | awk '{print $2}')
    info "  Allocated $actual_hp hugepages (requested 512)"

    TEST_LABEL="hugepage_2M" DURATION="$DURATION" OUTPUT_DIR="$OUTPUT_DIR" \
        python3 "${SCRIPT_DIR}/trex_run.py" || warn "TRex hugepage_2M non-zero"

    # Restore
    echo "$orig_hp" > /proc/sys/vm/nr_hugepages
    ok "  Hugepage test complete"
}

# ── Sub-test D: Slab pressure ─────────────────────────────────────────────────
run_slab() {
    info "=== Sub-test D: Slab pressure monitoring ==="

    python3 - "${OUTPUT_DIR}/slab_t0.json" <<'PY'
import json, re, sys
from pathlib import Path
text = Path('/proc/slabinfo').read_text()
result = {}
for line in text.splitlines()[2:]:  # skip header lines
    parts = line.split()
    if len(parts) >= 3:
        result[parts[0]] = {"active_objs": int(parts[1]), "num_objs": int(parts[2])}
Path(sys.argv[1]).write_text(json.dumps(result))
print(f"slab snapshot T0: {len(result)} caches")
PY

    info "  Running traffic for ${SLAB_DURATION}s while monitoring slab..."
    iperf3 --client "$PEER" --time "$SLAB_DURATION" --parallel 4 \
           > /dev/null 2>&1 || warn "iperf3 slab run non-zero"

    python3 - "${OUTPUT_DIR}/slab_t1.json" <<'PY'
import json, sys
from pathlib import Path
text = Path('/proc/slabinfo').read_text()
result = {}
for line in text.splitlines()[2:]:
    parts = line.split()
    if len(parts) >= 3:
        result[parts[0]] = {"active_objs": int(parts[1]), "num_objs": int(parts[2])}
Path(sys.argv[1]).write_text(json.dumps(result))
print(f"slab snapshot T1: {len(result)} caches")
PY
    ok "  Slab snapshot done"
}

# ── Main ──────────────────────────────────────────────────────────────────────
log "=== 06_memory_dma starting ==="
ENV_FILE="${OUTPUT_DIR}/env.json"
snapshot_env "$IFACE" "$ENV_FILE"
check_link "$IFACE"
check_peer "$PEER"
setup_cpu_isolation
pin_irqs_to_numa "$IFACE"
sleep 2

run_dma_timing
run_numa
run_hugepage
run_slab

RESULT="${OUTPUT_DIR}/result.json"
python3 "${SCRIPT_DIR}/analyse.py" \
    --results-dir "$OUTPUT_DIR" --iface "$IFACE" --output "$RESULT"

python3 "${SCRIPT_DIR}/report.py" \
    --result "$RESULT" --baseline "${SCRIPT_DIR}/baseline.json" \
    --env "$ENV_FILE" --output "${SCRIPT_DIR}/REPORT.md" --meta "$META"

restore_cpu_isolation
log "=== 06_memory_dma complete ==="
