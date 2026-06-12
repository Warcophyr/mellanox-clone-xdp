/* SPDX-License-Identifier: GPL-2.0 */
/*
 * 3. Firewall — a stateful firewall that checks bidirectional connectivity for
 *    UDP flows: a return packet is allowed only if the host first sent an
 *    outbound packet of the same flow.
 *
 * Flow-cached: once a flow is established (or denied) the verdict is stable.
 * The program installs a Flow Table PASS rule for established flows and a DROP
 * rule for denied ones. A DROP rule means subsequent unwanted packets never
 * cross the PCIe bus — free DDoS-style filtering at line rate.
 */
#include "axdp.h"

enum { FW_NEW = 0, FW_ESTABLISHED = 1, FW_DENIED = 2 };

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct flow_key);
	__type(value, __u8);          /* connection state */
	__uint(max_entries, 1000000);
} conntrack SEC(".maps");

/* Reverse a flow key so we can test the opposite direction. */
static __always_inline void reverse_key(struct flow_key *k, struct flow_key *r)
{
	r->src_ip   = k->dst_ip;
	r->dst_ip   = k->src_ip;
	r->src_port = k->dst_port;
	r->dst_port = k->src_port;
	r->proto    = k->proto;
}

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct flow_key k = {};

	if (parse_5tuple(data, data_end, &k) < 0)
		return XDP_PASS;
	if (k.proto != IPPROTO_UDP)
		return XDP_PASS;

	
	__u8 *state = bpf_map_lookup_elem(&conntrack, &k);
	if (state && *state == FW_ESTABLISHED)
		return XDP_PASS;          /* known good (usually HW-handled) */

	/* Is this the return half of a flow we originated? */
	struct flow_key rev = {};
	reverse_key(&k, &rev);
	__u8 *fwd = bpf_map_lookup_elem(&conntrack, &rev);

	if (fwd) {
		/* SLOW PATH: establish the flow and offload PASS to hardware. */
		__u8 est = FW_ESTABLISHED;
		bpf_map_update_elem(&conntrack, &k, &est, BPF_ANY);

		struct axdp_ft_entry e = {
			.key    = k,
			.action = AXDP_ACT_PASS,
		};
		bpf_xdp_axdp_ft_install(ctx, &e);
		return XDP_PASS;
	}

	/* Unsolicited inbound: deny. Install a hardware DROP rule so the
	 * rest of this (possibly hostile) flow never reaches the host. */
	__u8 denied = FW_DENIED;
	bpf_map_update_elem(&conntrack, &k, &denied, BPF_ANY);

	struct axdp_ft_entry e = {
		.key    = k,
		.action = AXDP_ACT_DROP,
	};
	bpf_xdp_axdp_ft_install(ctx, &e);
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
