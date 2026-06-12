/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Stateful TCP firewall (pure software XDP).
 *
 * Policy: allow outbound connections initiated from the protected (inside)
 * network and the return traffic that belongs to them; drop unsolicited
 * inbound connection attempts. The connection state is tracked by following
 * the TCP handshake and teardown, per 5-tuple, in a BPF hash map.
 *
 * Direction is decided by the inside prefix INSIDE_NET/INSIDE_MASK: a packet
 * whose source is inside is "outbound", otherwise "inbound". Adjust to taste.
 *
 * This is the standard-XDP baseline; every packet is parsed and looked up on
 * the CPU. No hardware offload.
 */

#include "common.h"

/* The protected network: 10.0.0.0/8 by default (network byte order). */
#define INSIDE_NET   bpf_htonl(0x0a000000)   /* 10.0.0.0   */
#define INSIDE_MASK  bpf_htonl(0xff000000)   /* /8         */

/* Connection states. */
enum ct_state {
	CT_NONE = 0,
	CT_SYN_SENT,      /* outbound SYN seen, awaiting SYN-ACK   */
	CT_ESTABLISHED,   /* handshake complete                    */
	CT_FIN,           /* a FIN seen, connection closing        */
};

struct ct_entry {
	__u8  state;
	__u8  pad[3];
	__u64 last_seen;  /* ns, for ageing (not GC'd here)        */
};

/* Connection table, keyed by a canonical (direction-independent) 5-tuple. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct flow_key);
	__type(value, struct ct_entry);
	__uint(max_entries, 1000000);
} conntrack SEC(".maps");

/* Build a canonical key so both directions of a connection map to one entry:
 * order the (ip,port) endpoints so the smaller one is always "src". */
static __always_inline void
canon_key(const struct flow_key *in, struct flow_key *out)
{
	__u64 a = ((__u64)bpf_ntohl(in->src_ip) << 16) | bpf_ntohs(in->src_port);
	__u64 b = ((__u64)bpf_ntohl(in->dst_ip) << 16) | bpf_ntohs(in->dst_port);

	__builtin_memset(out, 0, sizeof(*out));
	out->proto = in->proto;
	if (a <= b) {
		out->src_ip = in->src_ip;   out->src_port = in->src_port;
		out->dst_ip = in->dst_ip;   out->dst_port = in->dst_port;
	} else {
		out->src_ip = in->dst_ip;   out->src_port = in->dst_port;
		out->dst_ip = in->src_ip;   out->dst_port = in->src_port;
	}
}

static __always_inline int ip_is_inside(__be32 ip)
{
	return (ip & INSIDE_MASK) == INSIDE_NET;
}

SEC("xdp")
int xdp_tcp_firewall(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct flow_key k = {};

	/* Only inspect TCP/IPv4; everything else is passed to the stack. */
	if (parse_5tuple(data, data_end, &k) < 0)
		return XDP_PASS;
	if (k.proto != IPPROTO_TCP)
		return XDP_PASS;

	/* Re-locate the TCP header to read flags (verifier needs the checks). */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;
	struct tcphdr *th = (void *)iph + iph->ihl * 4;
	if ((void *)(th + 1) > data_end)
		return XDP_PASS;

	int outbound = ip_is_inside(iph->saddr);

	struct flow_key ck;
	canon_key(&k, &ck);
	struct ct_entry *ct = bpf_map_lookup_elem(&conntrack, &ck);

	__u64 now = bpf_ktime_get_ns();

	/* ---- Existing connection ------------------------------------- */
	if (ct) {
		/* Teardown: a FIN or RST moves the connection toward closed. */
		if (th->rst) {
			bpf_map_delete_elem(&conntrack, &ck);
			return XDP_PASS;   /* let both ends see the reset */
		}
		if (th->fin) {
			ct->state = CT_FIN;
			ct->last_seen = now;
			return XDP_PASS;
		}

		/* Complete the handshake: inbound SYN-ACK for our SYN. */
		if (ct->state == CT_SYN_SENT && th->syn && th->ack && !outbound) {
			ct->state = CT_ESTABLISHED;
			ct->last_seen = now;
			return XDP_PASS;
		}

		/* Any packet on an established (or closing) flow is allowed. */
		ct->last_seen = now;
		return XDP_PASS;
	}

	/* ---- New connection ------------------------------------------- */

	/* A bare SYN (no ACK) from the inside opens a new outbound flow. */
	if (th->syn && !th->ack && outbound) {
		struct ct_entry e = { .state = CT_SYN_SENT, .last_seen = now };
		bpf_map_update_elem(&conntrack, &ck, &e, BPF_ANY);
		return XDP_PASS;
	}

	/* Anything else without state is unsolicited:
	 *  - inbound SYN  -> someone trying to open a connection to us
	 *  - mid-stream packets with no tracked flow
	 * Drop them. A drop here is the firewall doing its job. */
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";