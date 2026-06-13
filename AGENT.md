# XDP Clone — Project Agent Guide

## Overview

This project extends the Mellanox (mlx5) out-of-tree kernel driver (based on Ubuntu linux-headers-6.8.0-60-generic) with two new XDP return actions — `XDP_CLONE_PASS` and `XDP_CLONE_TX` — that allow an XDP BPF program to clone an incoming packet into N independent copies, each re-dispatched through the same XDP program, while the original packet follows its natural fate (pass-to-stack or transmit).

The entire cloning logic lives in the receive path of the mlx5e NIC driver, in `mlx5e_skb_from_cqe_linear`.

---

## Repository Layout

```
mellanox-clone-xdp/
├── mellanox-out-of-tree-clone/   # Modified mlx5 kernel driver
│   └── mlx5/core/
│       ├── en_rx.c               # Core XDP clone implementation
│       └── Makefile              # Build + load/reload/reset targets
├── examples/
│   ├── clone/                    # Basic XDP_CLONE_TX example (n clones)
│   ├── clone-cnt/                # Clone with packet counter/modification
│   ├── clone-pass/               # XDP_CLONE_PASS variant example
│   ├── clone_astc/               # Clone with astc integration
│   └── afxdp-clone/              # AF_XDP cloning example
├── benchmark/                    # Performance benchmarks (latency, throughput…)
└── README.md
```

---

## New XDP Actions

### Action Codes (driver-side constants)

```c
const int XDP_CLONE_PASS = 5;   // Original → XDP_PASS, copies dispatched
const int XDP_CLONE_TX   = 6;   // Original → XDP_TX,   copies dispatched
```

### BPF Program Encoding

The BPF program returns a single integer that packs both the action and the copy count:

```c
#define __XDP_CLONE_PASS 5
#define __XDP_CLONE_TX   6

// Return XDP_CLONE_PASS with N copies (N+1 packets total)
#define XDP_CLONE_PASS(num_copy)  (((int)(num_copy) << 5) | __XDP_CLONE_PASS)

// Return XDP_CLONE_TX with N copies (N+1 packets total)
#define XDP_CLONE_TX(num_copy)    (((int)(num_copy) << 5) | __XDP_CLONE_TX)
```

- **Bits [4:0]** — XDP action code (5 = CLONE_PASS, 6 = CLONE_TX)
- **Bits [31:5]** — number of copies to create (`num_copy = return_value >> 5`)

The driver detects any return value `> 4`, then unpacks the count and action:

```c
// en_rx.c:1782–1786
if (act > 4) {
    int __num_copy = act >> 5;
    int __xdp_clone = (act & 0x1F);
    num_copy = __num_copy >= 0 ? __num_copy : 0;
    act = __xdp_clone;
}
```

---

## Metadata ID System

Every packet processed under a clone action carries a 4-byte integer in its XDP metadata area (`ctx->data_meta`). This allows the BPF program to distinguish the original from each copy.

| Packet         | Metadata ID value |
|----------------|-------------------|
| Original       | `0`               |
| 1st copy       | `1`               |
| 2nd copy       | `2`               |
| N-th copy      | `N`               |

### Driver writes metadata (en_rx.c:1789–1799)

For the original packet (before copies are dispatched):
```c
mxbuf.xdp.data_meta = xdp->data - sizeof(num_copy);
__builtin_memcpy(mxbuf.xdp.data_meta, &num_copy, sizeof(num_copy));
```

For each copy `i` (0-indexed), the driver writes `i+1`:
```c
int __num_copy = i + 1;
copy_xdp[i].data_meta = copy_xdp[i].data - sizeof(__num_copy);
__builtin_memcpy(copy_xdp[i].data_meta, &__num_copy, sizeof(__num_copy));
```

### BPF program reads metadata

```c
if (ctx->data_meta + sizeof(__u32) <= ctx->data) {
    int id = 0;
    __builtin_memcpy(&id, (void *)(long)ctx->data_meta, sizeof(id));
    // id == 0  → original packet
    // id > 0   → copy number `id`
}
```

---

## Driver Implementation — `mlx5e_skb_from_cqe_linear`

**File:** `mellanox-out-of-tree-clone/mlx5/core/en_rx.c`, line 1736

This function is the receive-path handler for linear (single-fragment) packets. The XDP clone logic is inserted after the initial `bpf_prog_run_xdp()` call on the original packet.

### XDP_CLONE_PASS flow (en_rx.c:1802–2030)

1. Compute `rx_headroom`, `metasize`, `cqe_bcnt`, `frag_size` from the modified `mxbuf.xdp`.
2. Allocate an skb for the **original** with `napi_alloc_skb` and copy data via `skb_put_data`.
3. Mark for recycle (`skb_mark_for_recycle`), complete CQE metadata, submit to kernel stack via `napi_gro_receive`.
4. Allocate `num_copy` fresh pages from `rq->page_pool`.
5. For each copy `i`:
   - `memcpy` from `va` (original page address + headroom) to `copy_va[i]`.
   - Initialize `copy_xdp[i]` with `xdp_init_buff` / `xdp_prepare_buff`.
6. For each copy `i`, write metadata ID `i+1` into `copy_xdp[i].data_meta` and call `bpf_prog_run_xdp(prog, &copy_xdp[i])`.
7. Handle the copy's XDP return code (only standard actions accepted):
   - `XDP_PASS` → allocate skb, `skb_put_data`, `napi_gro_receive`.
   - `XDP_TX` → `mlx5e_xmit_xdp_buff`, set `MLX5E_RQ_FLAG_XDP_XMIT`.
   - `XDP_REDIRECT` → `xdp_do_redirect`, set redirect flags.
   - `XDP_DROP` / `XDP_ABORTED` → drop, increment `xdp_drop` stat.
8. Return `NULL` (the original skb was already delivered inline).

### XDP_CLONE_TX flow (en_rx.c:2031–2163)

1. Transmit the **original** packet via `mlx5e_xmit_xdp_buff(rq->xdpsq, rq, xdp)`.
2. Allocate `num_copy` fresh pages from `rq->page_pool`.
3. `memcpy` + `xdp_init_buff` / `xdp_prepare_buff` for each copy (same as PASS).
4. For each copy `i`, write metadata ID `i+1`, call `bpf_prog_run_xdp`, handle result identically to CLONE_PASS copies.
5. Return `NULL`.

### Copy memory model

All copies are allocated **before** any copy's XDP program runs. Each copy is a `memcpy` of the **original** `va` buffer (not of the previous copy). The BPF program runs on copies sequentially after all pages are allocated. Modifications made by copy `i`'s XDP run do **not** propagate to copy `i+1`'s initial data.

---

## BPF Program Contract

### Original packet (metadata ID = 0)
- May return any value including `XDP_CLONE_PASS(N)` or `XDP_CLONE_TX(N)`.
- Returning `XDP_CLONE_PASS(N)` → original → stack, N copies dispatched.
- Returning `XDP_CLONE_TX(N)` → original → TX, N copies dispatched.

### Copy packets (metadata ID > 0)
- May only return standard XDP actions: `XDP_PASS`, `XDP_TX`, `XDP_REDIRECT`, `XDP_DROP`, `XDP_ABORTED`.
- Returning `XDP_CLONE_PASS` or `XDP_CLONE_TX` again is treated as `XDP_DROP`.
- `XDP_REDIRECT` after a clone is partially supported but may have undefined behavior — use at your own risk.

---

## Build Instructions

### Driver

```bash
cd mellanox-out-of-tree-clone/mlx5/core
make           # compile
make load      # remove mlx5_ib + mlx5_fwctl, then reload driver
make reload    # bring interface down, rmmod, insmod, configure IP/promisc/ethtool
make reset     # unload custom driver, restore default mlx5_core via modprobe
make unload    # rmmod mlx5_core only
```

**Interface configuration** — set the `ETH` variable in `Makefile` (default: `enp52s0f1np1`) and `IP` (default: `192.168.101.1`) to match your environment before loading.

The `reload` target also disables striding RQ, enables promiscuous mode, sets RX indirection table to 1 queue, and disables XDP TX mpwqe for compatibility with the XDP clone path.

### Example programs

```bash
cd examples/clone
make xdp_clone
./xdp_clone <ifname> [n_clones]   # default n_clones = 4
```

The user-space loader (`xdp_clone.c`) uses libbpf to open/load the BPF skeleton, writes `n_clone` into the BPF global data section, and attaches the XDP program via `bpf_xdp_attach`.

---

## Key Data Structures and Helpers

| Symbol | Location | Purpose |
|--------|----------|---------|
| `mlx5e_skb_from_cqe_linear` | `en_rx.c:1736` | Receive handler where clone logic lives |
| `mlx5e_fill_mxbuf_metadata` | `en_rx.c` | Fills `mlx5e_xdp_buff` from CQE for XDP prog |
| `mlx5e_xmit_xdp_buff` | `en/xdp.c` | Transmits an xdp_buff on the XDP TX SQ |
| `page_pool_dev_alloc_pages` | kernel | Allocates a new DMA page for each copy |
| `xdp_init_buff` / `xdp_prepare_buff` | kernel | Initializes xdp_buff from raw page + offsets |
| `bpf_prog_run_xdp` | kernel | Invokes the BPF program on an xdp_buff |
| `napi_gro_receive` | kernel | Delivers skb to kernel network stack |

---

## Constraints and Known Limitations

- **Linear packets only** — `mlx5e_skb_from_cqe_linear` handles single-fragment packets. Multi-fragment (non-linear) packets go through `mlx5e_skb_from_cqe_nonlinear` which does not implement cloning.
- **XDP_REDIRECT copies** — officially unsupported after a clone; behavior is undefined.
- **Copy ordering** — copies are dispatched sequentially; there is no batching of the BPF re-invocation.
- **Page pool pressure** — each copy allocates one page from `rq->page_pool`. Under high clone counts or high packet rates, page pool exhaustion drops packets with an `xdp_drop` stat increment.
- **No chaining of copy modifications** — all copies are memcpy'd from the original before any copy's XDP prog runs; copy `i` does not see modifications from copy `i-1`.
- **Error path on copy allocation failure** — if `page_pool_dev_alloc_pages` fails for copy `i`, the function returns `NULL` immediately, leaking already-allocated pages for copies `0..i-1` (they are not released in the current code).
- **XDP metadata headroom requirement** — the driver checks that `(char *)xdp->data - (char *)xdp->data_hard_start >= sizeof(int)` before writing the metadata ID; if headroom is insufficient the action is silently demoted to `XDP_ABORTED`.
- **ethtool flags required** — `rx_striding_rq off` and `xdp_tx_mpwqe off` must be set (the `reload` make target does this automatically).
