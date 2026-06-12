# A-XDP Example Programs

The seven XDP network functions from the A-XDP paper. Each is written against
standard XDP/eBPF plus the proposed A-XDP extensions declared in `axdp.h`:

- **RX computation offloads** — kfuncs that surface NIC-computed CQE fields
  (timestamp, RSS hash, parsed L3/L4/tunnel type, checksum, byte count,
  `flow_table_metadata`) to the program. Each returns `-ENODATA` when the field
  is unavailable, so every program falls back to software.
- **RX match/action offloads** — `bpf_xdp_axdp_ft_install()` / `_remove()`
  install hardware Flow Table entries as a side effect of processing a packet.
- **TX offloads (lazy)** — `tx_select_queue`, `tx_encap`, `tx_rewrite`,
  `tx_metadata` record a command in the WQE metadata; the NIC applies it at
  transmit time. Because they are lazy, re-reading the packet after the call
  returns the *original* bytes.

## The programs

| # | File | Regime | RX accel | TX accel |
|---|------|--------|----------|----------|
| 1 | `01_tunnel.c`    | 1st pkt   | `l4_type`; VNI HW decap        | lazy inline encap |
| 2 | `02_router.c`    | 1st pkt   | `l3_type`; HW steer to queue   | per-flow egress queue |
| 3 | `03_firewall.c`  | 1st pkt   | HW pass/drop of est. flows     | — |
| 4 | `04_dnat.c`      | 1st pkt   | HW modify-header; binding id   | lazy reverse rewrite |
| 5 | `05_katran.c`    | 1st pkt   | RSS hash; HW rewrite+steer     | per-flow QoS queue |
| 6 | `06_policer.c`   | every pkt | timestamp, byte count, class   | metadata tag |
| 7 | `07_telemetry.c` | every pkt | ingress timestamp, byte count  | — |

Programs 1–5 are *flow-cached*: the slow path runs once per flow to install a
Flow Table rule, after which the NIC handles subsequent packets. Programs 6–7
are *per-packet*: the verdict changes on every packet, so no rule is installed
and only the computation offloads apply.

## Building

These target the A-XDP kfunc interface, which is not present in a stock kernel.
With an A-XDP-patched kernel and libbpf installed:

```sh
clang -O2 -g -target bpf -c 05_katran.c -o 05_katran.o \
      -I /usr/include/$(uname -m)-linux-gnu
ip link set dev eth0 xdpdrv obj 05_katran.o sec xdp
```

On a stock kernel the kfuncs resolve to the capability-unavailable path and the
programs run entirely in software (the fallback branches in each file).
