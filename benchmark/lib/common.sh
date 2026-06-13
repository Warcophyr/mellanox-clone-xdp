#!/usr/bin/env bash
# lib/common.sh — shared utilities for the Mellanox benchmark suite
#
# Usage in every run.sh:
#   source "$(dirname "$0")/../lib/common.sh"

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
_RED='\033[0;31m'; _YEL='\033[0;33m'; _GRN='\033[0;32m'
_BLU='\033[0;34m'; _RST='\033[0m'

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
info() { echo -e "${_BLU}[INFO]${_RST}  $*"; }
ok()   { echo -e "${_GRN}[ OK ]${_RST}  $*"; }
warn() { echo -e "${_YEL}[WARN]${_RST}  $*" >&2; }
err()  { echo -e "${_RED}[ERR ]${_RST}  $*" >&2; }
die()  { err "$*"; exit 1; }

# ── Pre-flight checks ─────────────────────────────────────────────────────────
require_root() {
    [[ $EUID -eq 0 ]] || die "Must run as root (try: sudo $0)"
}

require_tool() {
    local missing=()
    for t in "$@"; do
        command -v "$t" &>/dev/null || missing+=("$t")
    done
    [[ ${#missing[@]} -eq 0 ]] || die "Missing required tools: ${missing[*]}"
}

# ── CPU isolation ─────────────────────────────────────────────────────────────
setup_cpu_isolation() {
    info "Setting CPU governor → performance..."
    if command -v cpupower &>/dev/null; then
        cpupower frequency-set -g performance &>/dev/null \
            || warn "cpupower failed — freq scaling may skew results"
    else
        for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
            [[ -f "$f" ]] && echo performance > "$f" 2>/dev/null || true
        done
    fi

    info "Disabling turbo boost..."
    if   [[ -f /sys/devices/system/cpu/intel_pstate/no_turbo ]]; then
        echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo
    elif [[ -f /sys/devices/system/cpu/cpufreq/boost ]]; then
        echo 0 > /sys/devices/system/cpu/cpufreq/boost
    else
        warn "No turbo-disable sysfs path found — continuing anyway"
    fi

    info "Stopping irqbalance..."
    systemctl stop irqbalance 2>/dev/null \
        || service irqbalance stop 2>/dev/null \
        || warn "Could not stop irqbalance — IRQ migrations may affect results"

    info "Disabling ASLR..."
    echo 0 > /proc/sys/kernel/randomize_va_space

    ok "CPU isolation active"
}

restore_cpu_isolation() {
    info "Restoring CPU governor → ondemand..."
    if command -v cpupower &>/dev/null; then
        cpupower frequency-set -g ondemand &>/dev/null || true
    else
        for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
            [[ -f "$f" ]] && echo ondemand > "$f" 2>/dev/null || true
        done
    fi

    if   [[ -f /sys/devices/system/cpu/intel_pstate/no_turbo ]]; then
        echo 0 > /sys/devices/system/cpu/intel_pstate/no_turbo
    elif [[ -f /sys/devices/system/cpu/cpufreq/boost ]]; then
        echo 1 > /sys/devices/system/cpu/cpufreq/boost
    fi

    systemctl start irqbalance 2>/dev/null \
        || service irqbalance start 2>/dev/null || true

    echo 2 > /proc/sys/kernel/randomize_va_space
    ok "CPU isolation restored"
}

# ── NIC helpers ───────────────────────────────────────────────────────────────
check_link() {
    local iface="$1"
    ip link show "$iface" &>/dev/null || die "Interface '$iface' not found"
    local state
    state=$(cat /sys/class/net/"$iface"/operstate 2>/dev/null || echo "unknown")
    [[ "$state" == "up" ]] || die "Interface $iface is not up (operstate=$state)"
    ok "Link $iface is up"
}

check_peer() {
    local peer="$1"
    # info "Checking peer reachability ($peer)..."
    # ping -c 3 -W 2 "$peer" &>/dev/null || die "Peer $peer is unreachable — is it up?"
    # ok "Peer $peer is reachable"
}

get_nic_numa() {
    local iface="$1"
    cat /sys/class/net/"$iface"/device/numa_node 2>/dev/null || echo 0
}

pin_irqs_to_numa() {
    # Pins all IRQs for iface to the CPUs on the NIC's NUMA node
    local iface="$1"
    local numa_node
    numa_node=$(get_nic_numa "$iface")
    local cpulist
    cpulist=$(cat /sys/devices/system/node/node"${numa_node}"/cpulist 2>/dev/null || echo "0")
    info "Pinning $iface IRQs → NUMA-${numa_node} CPUs ($cpulist)..."

    local mask
    mask=$(python3 - "$cpulist" <<'PY'
import sys
cpus = []
for part in sys.argv[1].split(','):
    if '-' in part:
        a, b = map(int, part.split('-'))
        cpus.extend(range(a, b + 1))
    else:
        cpus.append(int(part))
print(hex(sum(1 << c for c in cpus)))
PY
)
    local count=0
    while IFS= read -r irq; do
        echo "$mask" > /proc/irq/"$irq"/smp_affinity 2>/dev/null && ((count++)) || true
    done < <(grep -E "${iface}" /proc/interrupts | awk -F: '{print $1}' | tr -d ' ')
    ok "Pinned $count IRQs (affinity mask=$mask)"
}

# ── Environment snapshot ──────────────────────────────────────────────────────
# Writes a JSON env snapshot to $outfile.
# Used by every suite so all reports carry identical metadata.
snapshot_env() {
    local iface="$1"
    local outfile="$2"

    python3 - "$iface" "$outfile" <<'PY'
import sys, json, subprocess, re
from datetime import datetime, timezone
from pathlib import Path

iface   = sys.argv[1]
outfile = sys.argv[2]

def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL,
                                       text=True).strip()
    except Exception:
        return "unknown"

ei = run(f"ethtool -i {iface}")
es = run(f"ethtool {iface}")

def search(pattern, text, fallback="unknown"):
    m = re.search(pattern, text)
    return m.group(1) if m else fallback

data = {
    "timestamp"      : datetime.now(timezone.utc).isoformat(),
    "kernel"         : run("uname -r"),
    "driver"         : search(r'driver:\s+(\S+)', ei),
    "driver_version" : run("modinfo mlx5_core 2>/dev/null | awk '/^version:/{print $2}'"),
    "fw_version"     : search(r'firmware-version:\s+(\S+)', ei),
    "nic_pci"        : search(r'bus-info:\s+(\S+)', ei),
    "link_speed"     : search(r'Speed:\s+(\S+)', es),
    "numa_node"      : int(run(f"cat /sys/class/net/{iface}/device/numa_node") or 0),
    "cpu_model"      : run("grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs"),
    "cpu_count"      : int(run("nproc") or 0),
    "hugepages_2m"   : int(run("grep HugePages_Total /proc/meminfo | awk '{print $2}'") or 0),
    "iface"          : iface,
}

Path(outfile).parent.mkdir(parents=True, exist_ok=True)
Path(outfile).write_text(json.dumps(data, indent=2))
print(f"[env] Snapshot → {outfile}")
PY
}

# ── Misc ──────────────────────────────────────────────────────────────────────
BENCHMARK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB_DIR="${BENCHMARK_ROOT}/lib"
