#!/usr/bin/env bash
# 11_ebpf_xdp/run.sh
#
# Five sub-tests, each answering a specific driver question:
#
#   A) Hook overhead    — no XDP vs XDP_PASS (drv + skb mode)
#                         Δ latency and Δ throughput = pure driver XDP cost
#
#   B) RX ceiling       — XDP_DROP (drv mode) max PPS from ethtool counters
#                         Without SKB alloc — shows driver's raw RX capacity
#
#   C) RSS validation   — XDP_COUNTER per-CPU map vs ethtool per-queue stats
#                         Validates driver queue steering correctness
#
#   D) Mode comparison  — same XDP_PASS in skb / drv / hw mode
#                         Shows whether driver has native XDP support
#
#   E) XDP_TX bounce    — MAC-swap XDP_TX, measure RTT from peer
#                         Tests driver's buffer-recycle TX path (optional)
#
# Prerequisites:
#   clang + libbpf-dev   (compile BPF programs)
#   bpftool              (read BPF maps)
#   iperf3 + sockperf    (traffic)
#   Peer: iperf3 -s -D && sockperf server --port 11111
#
# Usage:
#   sudo PEER=192.168.1.2 bash 11_ebpf_xdp/run.sh
#   sudo PEER=192.168.1.2 SKIP_XDP_TX=1 bash 11_ebpf_xdp/run.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

IFACE="${IFACE:-eth0}"
PEER="${PEER:-}"
DURATION="${DURATION:-20}"
SOCK_PORT="${SOCK_PORT:-11111}"
SKIP_XDP_TX="${SKIP_XDP_TX:-0}"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/results}"
BPF_DIR="${SCRIPT_DIR}/bpf"
META="${OUTPUT_DIR}/meta.json"

require_root
require_tool clang ip python3 iperf3 sockperf
[[ -n "$PEER" ]] || die "PEER is not set."
mkdir -p "$OUTPUT_DIR"

# ── BPF tool check ─────────────────────────────────────────────────────────────
BPFTOOL=""
for bt in bpftool /usr/sbin/bpftool /usr/local/sbin/bpftool; do
    command -v "$bt" &>/dev/null && { BPFTOOL="$bt"; break; }
done
[[ -n "$BPFTOOL" ]] || warn "bpftool not found — counter map reads will be skipped"

# ── Compile BPF programs ──────────────────────────────────────────────────────
info "Compiling BPF programs..."
make -C "$BPF_DIR" clean all 2>&1 | tee "${OUTPUT_DIR}/compile.log" \
    || die "BPF compilation failed — check ${OUTPUT_DIR}/compile.log"
ok "BPF programs compiled"

# ── XDP attach / detach helpers ───────────────────────────────────────────────
xdp_attach() {
    local mode="$1"   # xdpdrv | xdpgeneric | xdphw | xdp
    local prog="$2"   # path to .o file
    local section="${3:-xdp}"

    # Detach any existing program first
    ip link set dev "$IFACE" xdp off    2>/dev/null || true
    ip link set dev "$IFACE" xdpdrv off 2>/dev/null || true
    ip link set dev "$IFACE" xdpgeneric off 2>/dev/null || true

    ip link set dev "$IFACE" "$mode" obj "$prog" sec "$section" 2>/dev/null
    local rc=$?
    if [[ $rc -eq 0 ]]; then
        ok "  XDP attached: mode=$mode prog=$(basename $prog)"
        return 0
    else
        warn "  XDP attach failed: mode=$mode prog=$(basename $prog)"
        return 1
    fi
}

xdp_detach() {
    ip link set dev "$IFACE" xdp off        2>/dev/null || true
    ip link set dev "$IFACE" xdpdrv off     2>/dev/null || true
    ip link set dev "$IFACE" xdpgeneric off 2>/dev/null || true
    ip link set dev "$IFACE" xdphw off      2>/dev/null || true
}

# Check current XDP mode from ip link output
get_xdp_mode() {
    ip link show "$IFACE" 2>/dev/null | grep -oP 'xdp\S*' | head -1 || echo "none"
}

# ── Traffic helpers ───────────────────────────────────────────────────────────
run_iperf() {
    local label="$1"
    iperf3 --client "$PEER" --time "$DURATION" --parallel 4 \
           --json --logfile "${OUTPUT_DIR}/iperf_${label}.json" \
        2>/dev/null || warn "iperf3 non-zero for $label"
}

run_sockperf() {
    local label="$1"
    sockperf ping-pong \
        --ip "$PEER" --port "$SOCK_PORT" \
        --msg-size 64 --time "$DURATION" \
        --mps 10000 --warmup-num 200 \
        > "${OUTPUT_DIR}/sockperf_${label}.txt" 2>&1 \
        || warn "sockperf non-zero for $label"
}

ethtool_snap() {
    ethtool -S "$IFACE" > "$1" 2>/dev/null || true
}

# ── Sub-test A: XDP hook overhead ─────────────────────────────────────────────
run_hook_overhead() {
    info "=== Sub-test A: XDP hook overhead ==="

    # 1. Baseline — no XDP attached
    info "  [no_xdp] baseline..."
    xdp_detach
    XDP_STATE="no_xdp" OUTPUT_DIR="$OUTPUT_DIR" \
        TREX_IP="$PEER" DUT_MAC="$DUT_MAC" DUT_IP="$DUT_IP" \
        python3 "${SCRIPT_DIR}/trex_run.py"

    # 2. XDP_PASS in native driver mode
    if xdp_attach "xdpdrv" "${BPF_DIR}/xdp_pass.o"; then
        info "  [xdp_pass_drv]..."
        XDP_STATE="xdp_pass_drv" OUTPUT_DIR="$OUTPUT_DIR" \
            TREX_IP="$PEER" DUT_MAC="$DUT_MAC" DUT_IP="$DUT_IP" \
            python3 "${SCRIPT_DIR}/trex_run.py"
        echo "drv" > "${OUTPUT_DIR}/native_xdp_supported.txt"
    else
        warn "  Driver does NOT support native XDP (xdpdrv) — recording finding"
        echo "no" > "${OUTPUT_DIR}/native_xdp_supported.txt"
    fi
    xdp_detach

    # 3. XDP_PASS in generic (skb) mode — always works, higher overhead
    if xdp_attach "xdpgeneric" "${BPF_DIR}/xdp_pass.o"; then
        info "  [xdp_pass_skb]..."
        XDP_STATE="xdp_pass_skb" OUTPUT_DIR="$OUTPUT_DIR" \
            TREX_IP="$PEER" DUT_MAC="$DUT_MAC" DUT_IP="$DUT_IP" \
            python3 "${SCRIPT_DIR}/trex_run.py"
    fi
    xdp_detach

    ok "Sub-test A done"
}

# ── Sub-test B: RX ceiling with XDP_DROP ─────────────────────────────────────
run_rx_ceiling() {
    info "=== Sub-test B: RX ceiling (XDP_DROP) ==="

    for mode in "xdpdrv" "xdpgeneric"; do
        label="${mode/xdp/}"  # "drv" or "generic"
        label="drop_${label}"

        xdp_attach "$mode" "${BPF_DIR}/xdp_drop.o" || continue

        # Snapshot T0
        ethtool_snap "${OUTPUT_DIR}/${label}_t0.txt"

        # Flood from peer — drive RX at max rate for DURATION seconds
        # iperf3 --reverse: peer sends to us (DUT receives)
        iperf3 --client "$PEER" --time "$DURATION" --parallel 4 --reverse \
               --json --logfile "${OUTPUT_DIR}/iperf_${label}.json" \
            2>/dev/null || warn "iperf3 non-zero for $label"

        # Snapshot T1
        ethtool_snap "${OUTPUT_DIR}/${label}_t1.txt"

        xdp_detach
        ok "  RX ceiling test done: $label"
    done
}

# ── Sub-test C: RSS validation via per-CPU counter ───────────────────────────
run_rss_validation() {
    info "=== Sub-test C: RSS validation (XDP_COUNTER) ==="
    [[ -n "$BPFTOOL" ]] || { warn "  bpftool not available — skipping"; return; }

    # Attach counter in drv mode (fall back to generic)
    if ! xdp_attach "xdpdrv" "${BPF_DIR}/xdp_counter.o"; then
        xdp_attach "xdpgeneric" "${BPF_DIR}/xdp_counter.o" \
            || { warn "  Cannot attach xdp_counter — skipping"; return; }
    fi

    # Snapshot ethtool queues at T0
    ethtool_snap "${OUTPUT_DIR}/counter_ethtool_t0.txt"

    # 32 parallel flows — should spread across all RSS queues
    iperf3 --client "$PEER" --time "$DURATION" --parallel 32 \
           --reverse \
           > /dev/null 2>&1 || warn "iperf3 non-zero for rss validation"

    # Snapshot ethtool queues at T1
    ethtool_snap "${OUTPUT_DIR}/counter_ethtool_t1.txt"

    # Dump per-CPU BPF map — find map by name
    local map_id
    map_id=$("$BPFTOOL" map show 2>/dev/null \
        | awk '/rx_cnt/{print $1}' | tr -d ':' | head -1)

    if [[ -n "$map_id" ]]; then
        "$BPFTOOL" map dump id "$map_id" \
            > "${OUTPUT_DIR}/counter_bpf_percpu.json" 2>/dev/null \
            || warn "  bpftool map dump failed"
        ok "  BPF per-CPU map → ${OUTPUT_DIR}/counter_bpf_percpu.json"
    else
        warn "  Could not find rx_cnt map id"
    fi

    xdp_detach
}

# ── Sub-test D: Attachment mode comparison ────────────────────────────────────
run_mode_comparison() {
    info "=== Sub-test D: Attachment mode comparison ==="
    local modes=("xdpdrv:drv" "xdpgeneric:skb" "xdphw:hw")

    for pair in "${modes[@]}"; do
        local ip_flag="${pair%%:*}"
        local label="${pair##*:}"

        if xdp_attach "$ip_flag" "${BPF_DIR}/xdp_pass.o"; then
            actual_mode=$(get_xdp_mode)
            info "  [$label] attached (actual: $actual_mode)..."
            ethtool_snap "${OUTPUT_DIR}/mode_${label}_t0.txt"
            iperf3 --client "$PEER" --time "$DURATION" --parallel 4 \
                   --json --logfile "${OUTPUT_DIR}/iperf_mode_${label}.json" \
                2>/dev/null || warn "iperf3 non-zero for mode=$label"
            ethtool_snap "${OUTPUT_DIR}/mode_${label}_t1.txt"
            echo "$actual_mode" > "${OUTPUT_DIR}/mode_${label}_actual.txt"
            xdp_detach
        else
            echo "unsupported" > "${OUTPUT_DIR}/mode_${label}_actual.txt"
        fi
        sleep 1
    done
    ok "Mode comparison done"
}

# ── Sub-test E: XDP_TX bounce latency ────────────────────────────────────────
run_xdp_tx() {
    [[ "$SKIP_XDP_TX" == "1" ]] && { info "XDP_TX test skipped (SKIP_XDP_TX=1)"; return; }
    info "=== Sub-test E: XDP_TX bounce latency ==="

    if ! xdp_attach "xdpdrv" "${BPF_DIR}/xdp_tx.o"; then
        warn "  xdpdrv attach failed for XDP_TX — driver may not support TX recycling"
        echo "unsupported" > "${OUTPUT_DIR}/xdp_tx_result.txt"
        return
    fi

    # Measure RTT via ping flood from peer (the DUT bounces via XDP_TX)
    # We SSH to peer... but since we don't have SSH setup here, measure
    # indirectly: watch ethtool TX counters grow (proves XDP_TX is working)
    ethtool_snap "${OUTPUT_DIR}/xdp_tx_t0.txt"

    # Send pings from DUT to peer — peer's replies arrive at DUT → XDP_TX → peer
    ping -c $(( DURATION * 1000 )) -i 0.001 -q "$PEER" \
        > "${OUTPUT_DIR}/xdp_tx_ping.txt" 2>&1 \
        || warn "  ping returned non-zero"

    ethtool_snap "${OUTPUT_DIR}/xdp_tx_t1.txt"
    xdp_detach
    ok "XDP_TX test done"
}

# ── Main ──────────────────────────────────────────────────────────────────────
log "=== 11_ebpf_xdp starting ==="
ENV_FILE="${OUTPUT_DIR}/env.json"
DUT_MAC=$(ip link show "$IFACE" | awk '/ether/{print $2}')
DUT_IP=$(ip -4 addr show "$IFACE" | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
export DUT_MAC DUT_IP
snapshot_env "$IFACE" "$ENV_FILE"

check_link "$IFACE"
check_peer "$PEER"
setup_cpu_isolation
pin_irqs_to_numa "$IFACE"
sleep 2

# Record kernel + BPF feature info
{
    echo "kernel: $(uname -r)"
    echo "clang:  $(clang --version | head -1)"
    echo "bpftool: ${BPFTOOL:-not found}"
    $BPFTOOL feature 2>/dev/null | grep -E 'XDP|xdp|map_type|prog_type' || true
} > "${OUTPUT_DIR}/bpf_features.txt"

run_hook_overhead
run_rx_ceiling
run_rss_validation
run_mode_comparison
run_xdp_tx

RESULT="${OUTPUT_DIR}/result.json"
python3 "${SCRIPT_DIR}/analyse.py" \
    --results-dir "$OUTPUT_DIR" \
    --iface       "$IFACE"      \
    --duration    "$DURATION"   \
    --output      "$RESULT"

python3 "${SCRIPT_DIR}/report.py" \
    --result   "$RESULT"   \
    --baseline "${SCRIPT_DIR}/baseline.json" \
    --env      "$ENV_FILE" \
    --output   "${SCRIPT_DIR}/REPORT.md" \
    --meta     "$META"

xdp_detach   # safety: ensure clean state on exit
restore_cpu_isolation
log "=== 11_ebpf_xdp complete ==="
