"""
lib/trex_runner.py

Thin wrapper around TRexOrchestrator for all benchmark suites.
Uses add_stream(), set_bidir(), set_warmup(), SweepRunner, set_flow_count(),
and get_live_stats() natively — no workarounds required.

Environment variables read by TRexRunner.from_env():
    TREX_IP     — TRex server IP  (same as PEER)
    DUT_MAC     — MAC of the DUT NIC
    DUT_IP      — IP of the DUT NIC
    TREX_PORT   — TRex TX port (default 0)
    WARMUP_SECS — warmup before each measurement (default 3)
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from src.orchestrator import TRexOrchestrator
from src.addons.sweep import SweepRunner
from src.exporters import TotalStatsExporter
from src.exceptions import OrchestratorError


# ── Packet factory ────────────────────────────────────────────────────────────

def _udp(dst_mac: str, dst_ip: str, size_b: int,
         src_ip: str = "10.0.0.1", sport: int = 1234, dport: int = 5678):
    from scapy.all import Ether, IP, UDP
    pad = max(0, size_b - 42)
    return Ether(dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / (b"\x00" * pad)


def _icmp(dst_mac: str, dst_ip: str, size_b: int = 64):
    from scapy.all import Ether, IP, ICMP
    pad = max(0, size_b - 42)
    return Ether(dst=dst_mac) / IP(dst=dst_ip) / ICMP() / (b"\x00" * pad)


# ── Result dataclasses ────────────────────────────────────────────────────────

@dataclass
class LatencyResult:
    label     : str   = ""
    size_b    : int   = 64
    rate_pps  : int   = 0
    duration_s: int   = 0
    p50_us    : float | None = None
    p90_us    : float | None = None
    p95_us    : float | None = None
    p99_us    : float | None = None
    p999_us   : float | None = None
    min_us    : float | None = None
    max_us    : float | None = None
    avg_us    : float | None = None
    jitter_us : float | None = None
    drops     : int   = 0
    total_pkts: int   = 0

    def to_dict(self) -> dict:
        return asdict(self)

    def to_iperf3_json(self) -> str:
        """Iperf3-compatible JSON for analyse.py backwards compatibility."""
        return json.dumps({"end": {
            "sum_sent":     {"bits_per_second": 0, "retransmits": 0},
            "sum_received": {"bits_per_second": 0},
        }, "trex_latency": asdict(self)})

    def to_sockperf_txt(self) -> str:
        return (
            f"[trex] label={self.label}\n"
            f"sockperf: [including warm-up] {self.total_pkts} observations\n"
            f"sockperf: Percentile 50.000 = {self.p50_us or 0:.3f} (usec)\n"
            f"sockperf: Percentile 90.000 = {self.p90_us or 0:.3f} (usec)\n"
            f"sockperf: Percentile 95.000 = {self.p95_us or 0:.3f} (usec)\n"
            f"sockperf: Percentile 99.000 = {self.p99_us or 0:.3f} (usec)\n"
            f"sockperf: Percentile 99.900 = {self.p999_us or 0:.3f} (usec)\n"
            f"sockperf: ---> <MAX> observation =  {self.max_us or 0:.3f}\n"
            f"sockperf: ---> <MIN> observation =  {self.min_us or 0:.3f}\n"
        )


@dataclass
class ThroughputResult:
    label       : str   = ""
    size_b      : int   = 0
    rate_pps_req: int   = 0
    tx_pps      : float = 0.0
    rx_pps      : float = 0.0
    tx_gbps     : float = 0.0
    rx_gbps     : float = 0.0
    tx_mpps     : float = 0.0
    drops       : int   = 0
    drop_rate   : float = 0.0
    duration_s  : int   = 0

    def to_dict(self) -> dict:
        return asdict(self)

    def to_iperf3_json(self) -> str:
        return json.dumps({"end": {
            "sum_sent":     {"bits_per_second": self.tx_gbps * 1e9, "retransmits": 0},
            "sum_received": {"bits_per_second": self.rx_gbps * 1e9},
        }, "trex_throughput": asdict(self)})


# ── Core runner ───────────────────────────────────────────────────────────────

class TRexRunner:

    def __init__(self, trex_ip: str, dut_mac: str, dut_ip: str,
                 trex_port: int = 0, warmup_s: int = 3):
        self.trex_ip   = trex_ip
        self.dut_mac   = dut_mac
        self.dut_ip    = dut_ip
        self.trex_port = trex_port
        self.warmup_s  = warmup_s

    @classmethod
    def from_env(cls) -> "TRexRunner":
        return cls(
            trex_ip   = os.environ["TREX_IP"],
            dut_mac   = os.environ["DUT_MAC"],
            dut_ip    = os.environ["DUT_IP"],
            trex_port = int(os.environ.get("TREX_PORT", "0")),
            warmup_s  = int(os.environ.get("WARMUP_SECS", "3")),
        )

    def _orch(self, ports: list[int] | None = None) -> TRexOrchestrator:
        return TRexOrchestrator(
            server_ip=self.trex_ip,
            ports=ports or [self.trex_port],
            verbose_level="error",
        )

    def _extract_stats(self, orch: TRexOrchestrator, duration: int) -> dict[str, float]:
        raw = getattr(
            TotalStatsExporter.flow_stats().export(orch), "_data", {}
        ) or {}
        total    = raw.get("total", {})
        tx_bytes = total.get("tx_bytes", 0)
        rx_bytes = total.get("rx_bytes", 0)
        tx_pkts  = total.get("tx_pkts", 0)
        dur = duration or 1
        return {
            "tx_gbps" : round(tx_bytes * 8 / 1e9 / dur, 3),
            "rx_gbps" : round(rx_bytes * 8 / 1e9 / dur, 3),
            "tx_pps"  : round(tx_pkts / dur, 1),
            "tx_mpps" : round(tx_pkts / dur / 1e6, 3),
            "drops"   : total.get("drops", 0),
        }

    def _extract_latency(self, orch: TRexOrchestrator,
                         size_b: int, rate_pps: int,
                         duration: int, label: str) -> LatencyResult:
        r = LatencyResult(label=label, size_b=size_b, rate_pps=rate_pps,
                          duration_s=duration)
        pcts = orch.export_percentiles()
        # Library returns keys like 'P50', 'P99' etc.
        r.p50_us  = pcts.get("P50") or pcts.get("p50")
        r.p90_us  = pcts.get("P90") or pcts.get("p90")
        r.p95_us  = pcts.get("P95") or pcts.get("p95")
        r.p99_us  = pcts.get("P99") or pcts.get("p99")
        r.p999_us = pcts.get("P99.9") or pcts.get("P999") or pcts.get("p999")
        hist = orch.get_latency_histogram()
        r.min_us    = hist.min_us
        r.max_us    = hist.max_us
        r.avg_us    = hist.avg_us
        r.jitter_us = hist.jitter_us
        r.drops     = hist.drops
        r.total_pkts= hist.total_packets
        return r

    # ── Latency under load: background flood + latency probe simultaneously ──

    def run_latency_under_load(
        self,
        size_b       : int   = 64,
        probe_pps    : int   = 1_000,
        flood_pps    : int   = 5_000_000,
        duration     : int   = 30,
        flow_count   : int   = 1,
        label        : str   = "",
    ) -> LatencyResult:
        """
        Background UDP flood + ICMP latency probe simultaneously via add_stream().
        Latency percentiles come exclusively from the probe stream.
        """
        flood_pkt = _udp(self.dut_mac, self.dut_ip, size_b)
        probe_pkt = _icmp(self.dut_mac, self.dut_ip, 64)

        with self._orch() as orch:
            (orch
             .add_stream(
                 packet       = flood_pkt,
                 name         = "background_flood",
                 pps          = flood_pps,
                 latency_probe= False,
                 flow_count   = flow_count,
                 src_port_range=(1000, 60000),
             )
             .add_stream(
                 packet       = probe_pkt,
                 name         = "latency_probe",
                 pps          = probe_pps,
                 latency_probe= True,
             )
             .set_warmup(seconds=self.warmup_s)
             .set_duration(seconds=duration)
             .start_sync())
            return self._extract_latency(orch, size_b, probe_pps, duration, label)

    # ── Pure latency (no flood, used for no-load baseline) ───────────────────

    def run_latency(
        self,
        size_b   : int  = 64,
        rate_pps : int  = 1_000,
        duration : int  = 30,
        label    : str  = "",
    ) -> LatencyResult:
        pkt = _udp(self.dut_mac, self.dut_ip, size_b)
        with self._orch() as orch:
            (orch
             .load_scapy(pkt, name=label or f"lat_{size_b}B")
             .set_multiplier(pps=rate_pps)
             .set_warmup(seconds=self.warmup_s)
             .set_duration(seconds=duration)
             .enable_latency_tracking()
             .start_sync())
            return self._extract_latency(orch, size_b, rate_pps, duration, label)

    # ── Throughput (single stream, no latency) ────────────────────────────────

    def run_throughput(
        self,
        size_b       : int   = 1400,
        rate_pps     : int   = 0,       # 0 = 100% line rate
        duration     : int   = 30,
        label        : str   = "",
        flow_count   : int   = 1,
    ) -> ThroughputResult:
        pkt = _udp(self.dut_mac, self.dut_ip, size_b)
        with self._orch() as orch:
            orch.load_scapy(pkt, name=label or f"tput_{size_b}B")
            if flow_count > 1:
                orch.set_flow_count(flow_count)
            if rate_pps > 0:
                orch.set_multiplier(pps=rate_pps)
            else:
                orch.set_multiplier(percent=100)
            orch.set_warmup(seconds=self.warmup_s).set_duration(seconds=duration).start_sync()
            s = self._extract_stats(orch, duration)
        return ThroughputResult(
            label=label, size_b=size_b, rate_pps_req=rate_pps,
            duration_s=duration, **s, drop_rate=round(s["drops"]/(max(1,int(s["tx_pps"]*duration))), 6),
        )

    # ── Bidirectional throughput ──────────────────────────────────────────────

    def run_bidir(
        self,
        size_b   : int = 1400,
        duration : int = 30,
    ) -> dict[str, float]:
        pkt = _udp(self.dut_mac, self.dut_ip, size_b)
        with self._orch(ports=[0, 1]) as orch:
            (orch
             .set_bidir(True)
             .load_scapy(pkt, name="bidir")
             .set_multiplier(percent=100)
             .set_warmup(seconds=self.warmup_s)
             .set_duration(seconds=duration)
             .start_sync())
            return self._extract_stats(orch, duration)

    # ── Frame-size sweep via SweepRunner ──────────────────────────────────────

    def run_frame_size_sweep(
        self,
        sizes_b  : list[int],
        duration : int = 10,
    ) -> list[dict]:
        pkt = _udp(self.dut_mac, self.dut_ip, 64)   # SweepRunner overrides size
        results = []
        with self._orch() as orch:
            orch.load_scapy(pkt)
            runner = SweepRunner(orch)
            sweep  = runner.sweep(
                frame_sizes    = sizes_b,
                rates_pps      = [0],          # 0 = max rate per size
                duration_s     = float(duration),
                latency_tracking = False,
            )
            for pt in sweep.points:
                pps  = getattr(pt.result, "tx_pps",  0) or 0
                gbps = getattr(pt.result, "tx_gbps", 0) or 0
                results.append({
                    "size_b"  : pt.frame_size_b,
                    "tx_mpps" : round(pps / 1e6, 3),
                    "tx_pps"  : int(pps),
                    "tx_gbps" : round(gbps, 3),
                    "drops"   : getattr(pt.result, "drops", 0),
                })
                print(f"[trex] sweep {pt.frame_size_b:>4}B  "
                      f"{results[-1]['tx_mpps']:.3f} Mpps  {gbps:.2f} Gbps")
        return results

    # ── Precise rate for CPU cost measurement ─────────────────────────────────

    def run_at_fraction(
        self,
        fraction     : float,
        line_rate_gbps: float,
        size_b       : int   = 1400,
        duration     : int   = 30,
        label        : str   = "",
    ) -> ThroughputResult:
        bps = int(line_rate_gbps * fraction * 1e9)
        pkt = _udp(self.dut_mac, self.dut_ip, size_b)
        with self._orch() as orch:
            (orch
             .load_scapy(pkt, name=label)
             .set_multiplier(bps_l1=bps)
             .set_warmup(seconds=self.warmup_s)
             .set_duration(seconds=duration)
             .start_sync())
            s = self._extract_stats(orch, duration)
        return ThroughputResult(label=label, size_b=size_b,
                                duration_s=duration, **s,
                                drop_rate=round(s["drops"]/(max(1,int(s["tx_pps"]*duration))),6))

    # ── Coalescing sweep point: simultaneous lat + tput ───────────────────────

    def run_coalesce_point(
        self,
        rx_usecs  : int,
        rx_frames : int,
        size_b    : int   = 64,
        probe_pps : int   = 10_000,
        flood_pps : int   = 5_000_000,
        duration  : int   = 15,
    ) -> dict:
        """
        Single coalescing grid point measured in ONE window:
        background flood drives the driver to its operating point while
        the latency probe measures p99 simultaneously.
        """
        flood_pkt = _udp(self.dut_mac, self.dut_ip, size_b)
        probe_pkt = _icmp(self.dut_mac, self.dut_ip, 64)

        with self._orch() as orch:
            (orch
             .add_stream(packet=flood_pkt, name="flood",
                         pps=flood_pps, latency_probe=False,
                         flow_count=1000, src_port_range=(1024, 60000))
             .add_stream(packet=probe_pkt, name="probe",
                         pps=probe_pps, latency_probe=True)
             .set_warmup(seconds=self.warmup_s)
             .set_duration(seconds=duration)
             .start_sync())
            lat   = self._extract_latency(orch, size_b, probe_pps, duration,
                                          f"u{rx_usecs}_f{rx_frames}")
            stats = self._extract_stats(orch, duration)

        return {
            "rx_usecs" : rx_usecs,
            "rx_frames": rx_frames,
            "p99_us"   : lat.p99_us,
            "gbps"     : stats["tx_gbps"],
            "drops"    : stats["drops"] + lat.drops,
        }

    # ── Long-run with live stats polling ─────────────────────────────────────

    def run_long_with_live_stats(
        self,
        duration     : int   = 1800,
        target_gbps  : float = 90.0,
        size_b       : int   = 1400,
        poll_interval: int   = 10,
        output_path  : Path | None = None,
    ) -> list[dict]:
        pkt      = _udp(self.dut_mac, self.dut_ip, size_b)
        timeline = []
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)

        with self._orch() as orch:
            (orch
             .load_scapy(pkt, name="stress_flood")
             .set_multiplier(bps_l1=int(target_gbps * 1e9))
             .set_duration(seconds=duration)
             .start_async())

            while orch.is_running():
                time.sleep(poll_interval)
                stats = orch.get_live_stats()
                snapshot = {
                    "elapsed_s" : stats.get("elapsed_s", 0),
                    "tx_gbps"   : round(stats.get("tx_pps_port0", 0) * size_b * 8 / 1e9, 3),
                    "drops"     : stats.get("drops", 0),
                    "ts"        : time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
                timeline.append(snapshot)
                if output_path:
                    with output_path.open("a") as f:
                        f.write(json.dumps(snapshot) + "\n")
                print(f"[trex] stress t={snapshot['elapsed_s']:>5.0f}s  "
                      f"gbps={snapshot['tx_gbps']}  drops={snapshot['drops']}")
        return timeline

    # ── Background traffic (for perf/flamegraph suites) ───────────────────────

    def run_background(
        self,
        duration     : int   = 120,
        size_b       : int   = 64,
        flow_count   : int   = 1,
        rate_percent : int   = 100,
    ) -> None:
        """Run traffic for duration seconds and exit. Use as background job."""
        import signal
        pkt = _udp(self.dut_mac, self.dut_ip, size_b)
        with self._orch() as orch:
            (orch
             .load_scapy(pkt, name="background")
             .set_multiplier(percent=rate_percent)
             .set_duration(seconds=duration)
             .start_async())

            def _stop(sig, frame):
                orch.stop()
            signal.signal(signal.SIGINT,  _stop)
            signal.signal(signal.SIGTERM, _stop)

            while orch.is_running():
                time.sleep(0.5)

    # ── RSS validation flood (diverse flows) ─────────────────────────────────

    def run_rss_flood(
        self,
        duration   : int = 30,
        flow_count : int = 10_000,
        size_b     : int = 64,
    ) -> ThroughputResult:
        pkt = _udp(self.dut_mac, self.dut_ip, size_b)
        with self._orch() as orch:
            (orch
             .add_stream(packet=pkt, name="rss_flood",
                         pps=0,  # will be overridden by percent
                         latency_probe=False,
                         flow_count=flow_count,
                         src_port_range=(1024, 60000))
             .set_multiplier(percent=100)
             .set_warmup(seconds=self.warmup_s)
             .set_duration(seconds=duration)
             .start_sync())
            s = self._extract_stats(orch, duration)
        return ThroughputResult(label="rss_flood", size_b=size_b,
                                duration_s=duration, **s,
                                drop_rate=round(s["drops"]/(max(1,int(s["tx_pps"]*duration))),6))

    # ── XDP_TX bounce latency ─────────────────────────────────────────────────

    def run_xdp_tx_latency(
        self,
        size_b   : int = 64,
        rate_pps : int = 1_000,
        duration : int = 30,
    ) -> LatencyResult:
        pkt = _icmp(self.dut_mac, self.dut_ip, size_b)
        with self._orch() as orch:
            (orch
             .load_scapy(pkt, name="xdp_tx_bounce")
             .set_multiplier(pps=rate_pps)
             .set_warmup(seconds=self.warmup_s)
             .set_duration(seconds=duration)
             .enable_latency_tracking()
             .start_sync())
            return self._extract_latency(orch, size_b, rate_pps, duration, "xdp_tx_bounce")

    # ── Serialise ─────────────────────────────────────────────────────────────

    @staticmethod
    def save(data: Any, path: Path | str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        if hasattr(data, "to_dict"):
            data = data.to_dict()
        elif isinstance(data, list):
            data = [x.to_dict() if hasattr(x, "to_dict") else x for x in data]
        p.write_text(json.dumps(data, indent=2))
        print(f"[trex] Saved → {p}")
