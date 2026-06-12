# A-XDP flow-steering playground (`mlx5/core/xdp`)

This folder collects the BPF programs and userspace tools used to experiment
with **A-XDP** (accelerated XDP) flow steering on Mellanox/NVIDIA **mlx5**
NICs. The common goal across most of these programs is to install or remove
hardware **flow-steering DROP rules** — either on the RX (ingress) or TX
(egress) path — and to push/read per-packet **metadata** between the XDP
program and the driver.

The driver-side counterparts live one directory up:

- [`../en_ioctl.h`](../en_ioctl.h) / `../en_ioctl.c` — the `/dev/mlx5_axdp`
  ioctl char device and its ABI.
- `../en_flowtable.c` / `../en_flowtable.h` — `add_meta_rule()`,
  `add_rx_rule()`, `del_rule()` and the `axdp_flow_ctx` flow tables.

---

## Driving flow rules

Flow rules are added/removed through the **`/dev/mlx5_axdp` ioctl device**,
used by [`axdp_add_rule.c`](axdp_add_rule.c) and
[`axdp_rule_daemon.c`](axdp_rule_daemon.c). Every operation is one of four
codes:

| code | operation | operand (`value`) |
|------|-----------|-------------------|
| 1 | ADD TX rule | WQE metadata tag (`reg_a`), network order |
| 2 | ADD RX rule | destination IPv4, network order |
| 3 | DEL TX rule | TX rule index returned by a previous ADD |
| 4 | DEL RX rule | RX rule index returned by a previous ADD |

---

## BPF programs (`*.bpf.c` → `*.bpf.o`)

Built with `clang -O2 -target bpf`. Attach with `bpftool` (see the Makefile
targets; they expect the interface in `ETH`, e.g. `make ETH=enp7s0np0 ...`).

### [`tx_header.bpf.c`](tx_header.bpf.c) — `xdptx_header`
Bare header-push experiment. On each packet it randomly reserves either
`META_MIN` (16) or `META_MAX` (64) bytes of metadata via
`bpf_xdp_adjust_meta()`, fills it with a marker pattern, then
`bpf_xdp_adjust_head()` + `XDP_TX`. Used to validate WQE inline-header
push/replace; carries no flow-rule semantics.

### [`tx_metadata_flow.bpf.c`](tx_metadata_flow.bpf.c) — `xdptx_metadata_flow`
Metadata read/write experiment. It reads NIC-computed RX metadata (hash and
timestamp, via the helpers in [`axdp.h`](axdp.h)), then writes a header into
`data_meta`:
- `header[0]` = flow metadata stamp (`reg_a`)
- `header[1]` = inline header length

It also stamps the WQE metadata and an inline header, then returns `XDP_TX`.

### [`axdp_ringbuf.bpf.c`](axdp_ringbuf.bpf.c) — `axdp_rb_producer`
Producer for the ring-buffer control channel consumed by
`axdp_rule_daemon`. Declares the pinned `BPF_MAP_TYPE_RINGBUF` map `axdp_rb`
and an `axdp_emit(op, value)` helper to enqueue one operation. The example
`SEC("xdp")` program emits a single `ADD_RX` rule once; drop `axdp_emit()` into
your own datapath wherever a rule should be installed/removed.

---

## Userspace tools

### [`axdp_add_rule.c`](axdp_add_rule.c) — one-shot ioctl CLI
Adds or removes a single flow rule through `/dev/mlx5_axdp`. The simplest way
to drive the driver by hand.
```
cc -Wall -o axdp_add_rule axdp_add_rule.c
./axdp_add_rule tx 0x2a2a2a2a       # ADD TX: drop WQE reg_a == tag
./axdp_add_rule rx 204.71.200.129   # ADD RX: drop ingress to this dst IP
./axdp_add_rule del-tx 0            # remove TX rule at index 0
./axdp_add_rule del-rx 0            # remove RX rule at index 0
```
ADD prints the assigned rule index; that index is what you pass to `del-*`.

### [`axdp_rule_daemon.c`](axdp_rule_daemon.c) — ring-buffer consumer
Streaming counterpart of `axdp_add_rule`: instead of one rule from argv, it
drains a continuous stream of operations from the BPF ring buffer
(`axdp_ringbuf.bpf.c`) and replays each onto `/dev/mlx5_axdp`. Links against
libbpf.
```
cc -Wall -O2 -o axdp_rule_daemon axdp_rule_daemon.c -lbpf
make ETH=enp7s0np0 attach-axdp_ringbuf   # load producer, pin map at /sys/fs/bpf/axdp_rb
sudo ./axdp_rule_daemon [pinned_ringbuf_path]   # default /sys/fs/bpf/axdp_rb
```
The producer must store `value` in the byte order the kernel expects (network
order for the TX tag / RX IPv4, host-order index for deletes); the daemon
forwards it verbatim.

---

## Headers

- [`axdp.h`](axdp.h) — BPF-side inline helpers to read NIC-computed RX metadata
  (`meta_read_timestamp`, `meta_read_hash`) from `data_meta`, with software
  fallbacks. Included by the metadata BPF programs.
- [`axdp_ringbuf.h`](axdp_ringbuf.h) — shared ABI between
  `axdp_ringbuf.bpf.c` and `axdp_rule_daemon.c`: the `enum axdp_op` codes and
  `struct axdp_rb_event { __u32 op; __u32 value; }`.

---

## Building

```
make ETH=enp7s0np0           # builds all *.bpf.o and axdp_rule_daemon
```
The `axdp_add_rule` CLI is compiled standalone with the `cc` line shown above;
only `axdp_rule_daemon` is wired into `make all`, since it needs libbpf.

Useful Makefile targets (pass `ETH=<ifname>`):

| target | what it does |
|--------|--------------|
| `all` | build BPF objects + `axdp_rule_daemon` |
| `attach-tx_metadata_flow` / `detach-tx_metadata_flow` | load/attach/detach `xdptx_metadata_flow` |
| `attach-tx_header` | load/attach `xdptx_header` |
| `attach-axdp_ringbuf` / `detach-axdp_ringbuf` | load producer + pin ring buffer, or tear down |
| `run-daemon` | run `axdp_rule_daemon` (producer must be loaded first) |

## Requirements

- mlx5 NIC with A-XDP-patched out-of-tree driver loaded (provides
  `/dev/mlx5_axdp`).
- `clang`/`llvm`, `bpftool`, and **libbpf** (≥ 1.0) for the BPF + daemon path.
- Root privileges for loading/attaching BPF and the ioctl device.
```
sudo apt install clang llvm libbpf-dev bpftool
```
