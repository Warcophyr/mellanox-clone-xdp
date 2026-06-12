/* SPDX-License-Identifier: GPL-2.0 */
/*
 * 2. Router — parse headers up to IP, look up the destination in a routing
 *    table, and forward (redirect) to the egress interface.
 *
 * Flow-cached: the next hop for a destination prefix is stable. On the first
 * packet matching a route the program installs a Flow Table STEER rule that
 * forwards subsequent packets directly to the egress queue/CPU in hardware,
 * removing the per-packet routing-table lookup from the host.
 */
#include "axdp.h"

struct route {
	__u32 egress_ifindex;
	__u16 tx_queue;
};

/* Software routing table (longest-prefix elided; use /32 keys for the demo). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __be32);          /* dst_ip */
	__type(value, struct route);
	__uint(max_entries, 1000000);
} routes SEC(".maps");

/* devmap for XDP_REDIRECT to egress ports. */
struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} tx_ports SEC(".maps");

SEC("xdp")
int xdp_router(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	/* RX computation offload: trust the NIC's L3 parse. */
	__u16 l3;
	if (bpf_xdp_axdp_rx_l3_type(ctx, &l3) == 0 &&
	    l3 != ETH_P_IP)
		return XDP_PASS;

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;

	struct route *r = bpf_map_lookup_elem(&routes, &iph->daddr);
	if (!r)
		return XDP_PASS;          /* unknown route -> kernel stack */

	/* SLOW PATH (first packet to this dst): install a hardware steer
	 * rule so subsequent packets are forwarded in silicon. */
	struct flow_key k = {};
	if (parse_5tuple(data, data_end, &k) == 0) {
		struct axdp_ft_entry e = {
			.key      = k,
			.action   = AXDP_ACT_STEER,
			.tx_queue = r->tx_queue,
		};
		bpf_xdp_axdp_ft_install(ctx, &e);
	}

	/* TX offload: select the egress queue for this forward. */
	bpf_xdp_axdp_tx_select_queue(ctx, r->tx_queue);

	return bpf_redirect_map(&tx_ports, r->egress_ifindex, 0);
}

char _license[] SEC("license") = "GPL";
