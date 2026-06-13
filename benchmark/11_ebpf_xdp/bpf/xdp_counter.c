// SPDX-License-Identifier: GPL-2.0
//
// xdp_counter.c — per-CPU packet counter + XDP_PASS
//
// Purpose: count packets independently on each CPU via a BPF_MAP_TYPE_PERCPU_ARRAY.
// After the test, read the map and compare the distribution against
// ethtool -S per-queue stats to validate that:
//   a) The driver is steering packets to the correct CPU (RSS → IRQ affinity)
//   b) The per-queue counters in ethtool match what the BPF program sees
//   c) No packets are being mis-steered to a single CPU (RSS imbalance)
//
// The per-CPU map has zero lock contention — each CPU writes its own slot.
// The BPF instruction count is 4 (lookup + NULL check + add + pass),
// so overhead above XDP_PASS is ~2–3 ns on a modern CPU.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key,         __u32);
    __type(value,       __u64);
    __uint(max_entries, 1);
} rx_cnt SEC(".maps");

SEC("xdp")
int xdp_counter_prog(struct xdp_md *ctx)
{
    __u32  key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&rx_cnt, &key);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
