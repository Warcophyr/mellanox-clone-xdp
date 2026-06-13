// SPDX-License-Identifier: GPL-2.0
//
// xdp_pass.c — trivial XDP_PASS
//
// Purpose: attach this to measure the overhead of having ANY XDP program
// loaded on the driver vs no XDP at all.  A delta here is 100% driver
// cost (hook dispatch, memory barriers, etc.) — there is no BPF logic.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass_prog(struct xdp_md *ctx)
{
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
