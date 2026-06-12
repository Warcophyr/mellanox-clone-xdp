/* SPDX-License-Identifier: GPL-2.0 */
/*
 * 1. Tunnel — parse a packet up to L4, encapsulate it, and XDP_TX.
 *
 * Flow-cached: the encapsulation header for a flow is fixed after the first
 * packet. On the first packet the program builds the outer header and installs
 * a Flow Table ENCAP rule; subsequent packets of the flow are encapsulated and
 * retransmitted entirely in NIC silicon. The TX-side encap is applied lazily —
 * the NIC prepends the header at transmit time (inline_hdr in the WQE), so the
 * program never copies bytes itself.
 */
#include "axdp.h"

#define VXLAN_HDR_LEN 50   /* eth(14)+ip(20)+udp(8)+vxlan(8) */

/* Per-flow outer header template, built once on the slow path. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct flow_key);
	__type(value, __u8[VXLAN_HDR_LEN]);
	__uint(max_entries, 100000);
} encap_templates SEC(".maps");

SEC("xdp")
int xdp_tunnel(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct flow_key k = {};

	/* RX computation offload: skip software parse if NIC already
	 * classified the inner protocol.
	 * CQE_L4_HDR_TYPE_NONE			= 0x0,
	 * CQE_L4_HDR_TYPE_TCP_NO_ACK	= 0x1,
	 * CQE_L4_HDR_TYPE_UDP			= 0x2,
	 * CQE_L4_HDR_TYPE_TCP_ACK_NO_DATA	= 0x3,
	 * CQE_L4_HDR_TYPE_TCP_ACK_AND_DATA	= 0x4
    */
	//__u8 l4=meta_read_l4type(ctx);
	//if (l4 == 0)   
	//	return XDP_PASS;   /* not L4, hand to stack */

	__u8 l4;
	if (bpf_xdp_axdp_rx_l4_type(ctx, &l4) == 0 && l4 == 0)   
		return XDP_PASS;   /* not L4, hand to stack */
		
	
	if (parse_5tuple(data, data_end, &k) < 0)
		return XDP_PASS;
	
	__u8 (*tmpl)[VXLAN_HDR_LEN] = bpf_map_lookup_elem(&encap_templates, &k);
	if (!tmpl) {
		/* SLOW PATH (first packet): build the outer header here.
		 * (Header construction elided for brevity.) */
		__u8 hdr[VXLAN_HDR_LEN] = {};
		/* ... fill hdr with eth/ip/udp/vxlan for this flow ... */
		bpf_map_update_elem(&encap_templates, &k, &hdr, BPF_ANY);

		/* Install hardware ENCAP rule so the NIC encapsulates the
		 * rest of the flow without invoking us again. */
		struct axdp_ft_entry e = {
			.key      = k,
			.action   = AXDP_ACT_ENCAP,
			.tx_queue = 0,
		};
		bpf_xdp_axdp_ft_install(ctx, &e);

		/* This first packet: ask the NIC to encap+TX lazily. */
		bpf_xdp_axdp_tx_encap(ctx, hdr, VXLAN_HDR_LEN);
		return XDP_TX;
	}

	/* If the offload took, we normally never reach here for this flow.
	 * Fallback path: lazy encap on transmit. */
	bpf_xdp_axdp_tx_encap(ctx, tmpl, VXLAN_HDR_LEN);
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
