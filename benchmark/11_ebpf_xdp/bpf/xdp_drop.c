// SPDX-License-Identifier: GPL-2.0
//
// xdp_drop.c — trivial XDP_DROP
//
// Purpose: drop every packet at the earliest possible point.
// This removes SKB allocation, GRO, and the network stack entirely,
// so the PPS you measure is the driver's raw RX processing ceiling.
//
// Compare against:
//   - iperf3 RX PPS  →  shows SKB-alloc + stack overhead
//   - pktgen TX PPS  →  shows TX ceiling on the DUT side
//
// If XDP_DROP PPS >> iperf3 RX PPS, your driver is spending most of its
// time on SKB allocation and GRO coalescing, which is normal.
// If XDP_DROP PPS ≈ iperf3 RX PPS, SKB allocation is negligible —
// investigate DMA path or descriptor ring processing.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_drop_prog(struct xdp_md *ctx)
{
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
