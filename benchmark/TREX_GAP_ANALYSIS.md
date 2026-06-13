# TRex Orchestrator — Gap Analysis for Mellanox Driver Benchmark Suite

This document describes the features that **do not exist** in the current
`trex-py-venti` library but are required to run the benchmark suite correctly.
Each gap is described in terms of what it must do, why it is necessary, what
data it must produce, and which benchmark suites are blocked without it.

No implementation code is provided here. The benchmark integration code
(`lib/trex_runner.py` and the per-suite `trex_run.py` scripts) documents which
gaps it works around and how.

---

## Gap 1 — Simultaneous Multi-Stream Composition

### What is missing

The library exposes a single-stream model: one call to `load_scapy()` or
`load_bytes()` defines the packet, one call to `set_multiplier()` sets the
rate, and `start_sync()` runs it. There is no API to load two independent
streams — each with its own rate, frame size, and tracking configuration —
and run them simultaneously on the same port.

### Why the benchmark suite needs it

Accurate latency-under-load measurement requires two concurrent streams
on the same port at all times:

- **Background flood stream**: a high-rate stream (e.g. 10 Mpps at 64 B)
  that saturates the driver's RX ring and forces it into the realistic
  operating point where coalescing, NAPI budget, and IRQ affinity interact.
  This stream must **not** contribute to latency histograms.

- **Latency probe stream**: a low-rate stream (e.g. 1 000 pps) of tagged
  packets with hardware TX timestamps. TRex measures the RTT of these
  packets independently and reports p50/p99/p99.9 without being polluted
  by the flood. This is the standard TRex `lat` stream pattern.

Without this composition the benchmark can only measure latency at idle
or latency at full flood — never latency *under* a controlled background
load. Suite 03 (latency) and suite 05 (interrupt coalescing sweep) are
entirely blocked, because the coalescing sweep's value is precisely the
`(latency, throughput)` pair at each grid point, which requires both
measurements to happen in the same 15-second window.

### What the feature must do

The library must allow multiple named streams to be registered before a
run starts. Each stream must independently carry:

- its own Scapy packet or raw bytes definition
- its own rate (`pps`, `bps_l1`, or `percent`)
- a flag marking it as a **latency-probe stream** (hardware-timestamped,
  contributes to `LatencyHistogram`) or a **background stream** (counted
  in flow stats only)

When `start_sync()` is called, all registered streams must be active
simultaneously. After the run, `get_latency_histogram()` must return
statistics derived only from the latency-probe stream packets, and
`TotalStatsExporter.flow_stats()` must report the aggregate across all
streams.

The existing `assert_p99_under()` and `auto_tune()` methods must continue
to operate on the latency-probe stream only.

---

## Gap 2 — Frame-Size and Rate Sweep Automation

### What is missing

There is no mechanism to iterate a test over a list of frame sizes or
rates and collect a structured per-point result set. Each measurement
requires a full connect/configure/run/disconnect cycle written manually
by the caller.

### Why the benchmark suite needs it

Suite 04 (throughput) needs a **PPS vs MTU curve** at seven frame sizes
(64, 128, 256, 512, 1024, 1500, 9000 bytes). This curve is the primary
evidence that the driver handles variable-size descriptors correctly and
that pktgen's pps claims are reproducible.

Suite 05 (interrupt coalescing) needs a **2D sweep** over a
6 × 6 grid of `(rx_usecs, rx_frames)` pairs, each requiring an independent
latency measurement and an independent throughput measurement. The sweep
has 36 points; without automation each point requires the caller to write
the same connect/configure/run block manually, which makes the test fragile.

### What the feature must do

A `sweep()` method (or a standalone `SweepRunner` class) must accept:

- a list of frame sizes in bytes
- a list of target rates (PPS, or fractions of line-rate)
- per-point duration
- whether to enable latency tracking at each point

It must run each combination in sequence, collecting a result object per
point. The result object must contain the same fields that single-run
exports contain (throughput, p99, drop rate) plus the sweep parameters
(`frame_size_b`, `rate_pps`) that identify the point.

The method must return a list of these result objects so the caller can
write them to a JSON file and feed them to the existing analysis pipeline
without additional parsing.

---

## Gap 3 — Bidirectional Simultaneous Traffic

### What is missing

The library works with a configurable port list but there is no way to
instruct two ports to transmit simultaneously and return **per-direction**
statistics (TX PPS port 0, RX PPS port 0, TX PPS port 1, RX PPS port 1,
drops per direction).

### Why the benchmark suite needs it

Suite 04 (throughput) measures bidir throughput, which is the relevant
metric for any workload that both sends and receives (storage, RPC,
distributed databases). A driver that achieves 95 Gbps TX and 95 Gbps RX
separately may achieve only 80 Gbps in each direction simultaneously if
the RX and TX descriptor rings share DMA space or if IRQ affinity is
misconfigured.

The bidir test is also the most realistic proxy for production workloads
and is the single number most likely to regress when the interrupt
coalescing path is changed.

### What the feature must do

The library must expose a mode — either a `set_bidir(True)` flag or a
per-port `load_scapy()` variant — that causes TRex to transmit on both
ports simultaneously. After the run, the result must contain separate
`tx_gbps`, `rx_gbps`, and `drop_rate` for each direction so the benchmark
can detect asymmetric regressions (e.g. TX path improves but RX path
degrades).

The latency-probe stream (Gap 1) must still be available in bidir mode,
attached to one direction.

---

## Gap 4 — Periodic Live Stats During an Async Run

### What is missing

`start_async()` begins a test and returns immediately, but there is no
method to query the current in-flight statistics (PPS, drops, latency
p99) without stopping the test. `start_sync()` blocks and only returns
statistics at completion.

### Why the benchmark suite needs it

Suite 10 (stress) runs iperf3 for up to 30 minutes and uses `monitor.py`
to poll `ethtool -S` every 10 seconds to build a **drop counter timeline**.
The key finding the stress test looks for is not just the total drop count
at the end, but *when* drops first appeared — which reveals whether the
regression is time-dependent (e.g. a ring buffer that fills under sustained
load) or rate-dependent.

Without live stats the stress test can only report a scalar total after
the run ends, making it impossible to distinguish a driver that dropped
1 000 packets in the first second from one that dropped 1 000 packets
in the last second of a 30-minute run.

Suite 05 (coalescing sweep) could also benefit: measuring p99 and
throughput simultaneously in a single 15-second window (rather than two
sequential 15-second runs) would cut sweep time in half and eliminate
the measurement noise introduced by two separate traffic starts.

### What the feature must do

After `start_async()`, the library must expose a `get_live_stats()` method
that returns a snapshot of the current counters:

- TX PPS and bytes/s (per port)
- RX PPS and bytes/s (per port)
- current drop count (cumulative since run start)
- current latency p99 (rolling window of the last N probe packets)
- elapsed seconds since run start

The method must be callable at any frequency without disturbing the
in-flight traffic. The benchmark's monitoring loop would call it every
10 seconds and append each snapshot to a JSONL timeline file, replacing
the current `monitor.py` + `ethtool -S` approach with a single TRex-native
data source.

---

## Gap 5 — L3/L4 Flow Diversity Control

### What is missing

`load_scapy()` and `load_bytes()` load a single fixed packet. There is no
way to instruct TRex to vary L3/L4 header fields (source IP, destination
IP, source port, destination port) across a configurable number of unique
values, which is how TRex natively generates diverse flows using its
field-engine.

### Why the benchmark suite needs it

Suite 07 (queue scaling) validates RSS by sending many unique flows and
checking whether the driver distributes them evenly across queues. If all
packets share the same 5-tuple, the RSS hash is constant and all packets
land on a single queue — the test produces no useful signal about driver
queue steering. The current workaround (32 parallel iperf3 streams) only
generates 32 flows, which is far fewer than the 10 000+ flows needed to
exercise the full RSS hash table.

Suite 02 (CPU micro-architecture) has a `many_flows` scenario specifically
to stress the driver's internal flow classification and any per-flow state
it maintains. Without flow diversity, this scenario is identical to the
single-flow burst scenario.

Suite 11 (eBPF/XDP) validates that the `xdp_counter` program's per-CPU
distribution matches `ethtool -S` per-queue stats. That comparison is only
meaningful if traffic is distributed across queues, which requires diverse
5-tuples.

### What the feature must do

The library must expose a **field-engine configuration** API that wraps
TRex's native VM (virtual machine) field modifier. At minimum it must support:

- `set_flow_count(n)`: vary the source IP or source port across `n` unique
  values, cycling sequentially or using a random distribution
- `set_src_ip_range(start, end)`: explicit source IP range
- `set_src_port_range(start, end)`: explicit source port range
- `set_dst_ip_range(start, end)`: explicit destination IP range

The feature must be composable with latency tracking: the latency-probe
stream (Gap 1) should have a fixed 5-tuple (so TRex can identify probe
packets by signature), while the background stream uses the field engine
for flow diversity.

The result object must include a `flow_count` field confirming how many
unique flows were actually generated, derived from the field-engine
configuration.

---

## Gap 6 — Warmup Period Separation from Measurement Window

### What is missing

`set_duration(seconds=N)` defines the total run time. Statistics are
accumulated from the moment `start_sync()` begins, which means the
first few seconds of traffic — before CPU caches are warm, before IRQ
affinity has settled, and before TRex's own transmit pipeline has reached
steady state — contribute to the latency histogram and throughput numbers.

### Why the benchmark suite needs it

The driver benchmark's most sensitive measurement is the no-load p99
latency in suite 03 (the "floor" that all other latency comparisons are
measured against). On cold start, the first 100–500 ms of measurements
typically show 2–5× higher latency than steady state because:

- CPU frequency scaling may not have reached the performance governor yet
  (even with `cpupower` applied, there is a transient)
- The NIC's internal scheduler and coalescing timers need a few interrupt
  cycles to reach their configured state
- TRex's own packet injection pipeline has a startup transient

Without a warmup window, the p99 computed from the entire run is
inflated by these transients, making it impossible to compare results
across kernel versions where the warmup transient duration may differ.

Suite 05 (coalescing sweep) is particularly sensitive: the 36 measurement
points are run sequentially, and each point starts cold after an
`ethtool -C` reconfiguration. Without warmup separation, each point's
latency figure includes the coalescing timer's own settling time, which
is a driver artefact rather than a steady-state characteristic.

### What the feature must do

`set_warmup(seconds=W)` must instruct the library to begin traffic at
`start_sync()` time but suppress all statistics collection for the first
`W` seconds. After the warmup window, statistics collection begins for
the configured `duration`. The histogram, percentiles, and flow stats
returned after the run must reflect only the measurement window.

The warmup period must not be subtracted from the duration; the total
elapsed time must be `warmup + duration`. The `start_sync()` call must
block for the full `warmup + duration` wall-clock time.

The warmup period must still transmit full-rate traffic — it is not a
ramp-up. A traffic ramp-up would introduce its own measurement artefacts
by changing the load presented to the driver during warmup.

---

## Summary Table

| Gap | Blocking suites | Workaround in current benchmark |
|-----|----------------|--------------------------------|
| 1 · Multi-stream composition | 03, 05 | Two sequential runs (latency-only + throughput-only); measurement window mismatch accepted |
| 2 · Frame/rate sweep | 04, 05 | Manual Python loop over sizes; extra connect/disconnect overhead per point |
| 3 · Bidirectional | 04 | iperf3 `--bidir` kept as fallback |
| 4 · Live stats polling | 10 | `monitor.py` continues to poll `ethtool -S`; TRex used only for rate control |
| 5 · Flow diversity | 07, 02, 11 | iperf3 `-P 32` kept as fallback for RSS; XDP counter validation degraded |
| 6 · Warmup separation | 03, 05 | First `WARMUP_SECS` of sockperf discarded via `--warmup-num`; TRex stats not split |
