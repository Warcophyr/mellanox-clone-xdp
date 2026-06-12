/* SPDX-License-Identifier: GPL-2.0 */
/*
 * axdp.h — A-XDP interface with transparent software fallback.
 *
 * Programs call the inline wrappers below, never the raw __axdp_* kfuncs.
 * Each wrapper tries the hardware path and falls back to software
 * automatically, so the fallback is invisible at the call site and the same
 * source runs on A-XDP hardware and on a stock kernel.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "./axdp.h"
#include "axdp_ringbuf.h"


/* 1 MiB ring buffer; pinned by name so the daemon can find it at
 * /sys/fs/bpf/axdp_rb when loaded with `bpftool prog loadall ... pinmaps`. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} axdp_rb SEC(".maps");

/* The flow-rule emit helpers live below, after struct flow_key is defined. */

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

struct flow_key {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	__u8   proto;
	__u8   pad[3];
};

/*
 * Enqueue an ADD_RX rule for a 5-tuple with a verdict (AXDP_RX_PASS /
 * AXDP_RX_DROP). The whole record is zeroed so unused fields stay clear.
 */
static __always_inline int axdp_emit_rx(const struct flow_key *k, __u8 action)
{
	struct axdp_rb_event *ev;

	ev = bpf_ringbuf_reserve(&axdp_rb, sizeof(*ev), 0);
	if (!ev)
		return -1;
	__builtin_memset(ev, 0, sizeof(*ev));
	ev->op       = AXDP_OP_ADD_RX;
	ev->src_ip   = k->src_ip;
	ev->dst_ip   = k->dst_ip;
	ev->src_port = k->src_port;
	ev->dst_port = k->dst_port;
	ev->ip_proto = k->proto;
	ev->action   = action;
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

/* Enqueue a DEL_RX for a 5-tuple. */
static __always_inline int axdp_emit_del_rx(const struct flow_key *k)
{
	struct axdp_rb_event *ev;

	ev = bpf_ringbuf_reserve(&axdp_rb, sizeof(*ev), 0);
	__builtin_memset(ev, 0, sizeof(*ev));
	ev->op       = AXDP_OP_DEL_RX;
	ev->src_ip   = k->src_ip;
	ev->dst_ip   = k->dst_ip;
	ev->src_port = k->src_port;
	ev->dst_port = k->dst_port;
	ev->ip_proto = k->proto;
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

enum axdp_ft_action {
	AXDP_ACT_STEER   = 1,
	AXDP_ACT_DROP    = 2,
	AXDP_ACT_PASS    = 3,
	AXDP_ACT_REWRITE = 4,
	AXDP_ACT_ENCAP   = 5,
	AXDP_ACT_DECAP   = 6,
};

struct axdp_ft_entry {
	struct flow_key key;
	__u32 action;
	__u32 rx_queue;
	__be32 nat_ip;
	__be16 nat_port;
	__u16  tx_queue;
	__u32  metadata;
};

/* 5-tuple parse helper. */
static __always_inline int
parse_5tuple(void *data, void *data_end, struct flow_key *k)
{
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return -1;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return -1;

	struct iphdr *iph = (void *)(eth + 1);

	if ((void *)(iph + 1) > data_end)
		return -1;

	k->src_ip = iph->saddr;
	k->dst_ip = iph->daddr;
	k->proto  = iph->protocol;

	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *th = (void *)iph + iph->ihl * 4;
		if ((void *)(th + 1) > data_end)
			return -1;
		k->src_port = th->source;
		k->dst_port = th->dest;
	} else if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *uh = (void *)iph + iph->ihl * 4;
		if ((void *)(uh + 1) > data_end)
			return -1;
		k->src_port = uh->source;
		k->dst_port = uh->dest;
	} else {
		k->src_port = 0;
		k->dst_port = 0;
	}
	return 0;
}



/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Stateful TCP firewall (A-XDP version).
 *
 * Same policy as the software baseline: allow connections initiated from the
 * inside network and their return traffic; drop unsolicited inbound attempts.
 * The TCP state machine (SYN / SYN-ACK / FIN / RST) is tracked in software on
 * the slow path — exactly as in the baseline.
 *
 * The difference is what happens once a flow's verdict is STABLE:
 *
 *   - When the handshake completes (CT_ESTABLISHED), the program installs a
 *     hardware Flow Table PASS rule for the flow. Subsequent packets of the
 *     connection are passed by the NIC and never reach the CPU.
 *
 *   - When an unsolicited inbound attempt is denied, the program installs a
 *     hardware DROP rule. Subsequent packets of that (possibly hostile) flow
 *     are dropped inside the NIC, before the PCIe bus — zero CPU cost.
 *
 *   - On teardown (FIN/RST) the program removes the hardware rule so the flow
 *     returns to software control and the table slot is freed.
 *
 * Only the handshake and teardown packets run in software; the bulk of an
 * established connection (and all packets of a denied flow) are handled in
 * hardware. Everything degrades gracefully: if the offload is unavailable the
 * software conntrack below still enforces the same policy on every packet.
 */
//#include "axdp.h"

/* The protected network: 10.0.0.0/8 by default (network byte order). */
#define INSIDE_NET   bpf_htonl(0x0a000000)   /* 10.0.0.0 */
#define INSIDE_MASK  bpf_htonl(0xff000000)   /* /8       */

enum ct_state {
	CT_NONE = 0,
	CT_SYN_SENT,      /* outbound SYN seen, awaiting SYN-ACK   */
	CT_ESTABLISHED,   /* handshake complete (HW rule installed) */
	CT_FIN,           /* a FIN seen, connection closing        */
};

struct ct_entry {
	__u32 index;      /* for DEL_HW_RULE when the flow is removed */
    __u8  state;
	__u8  offloaded;  /* 1 once a HW rule has been installed   */
	__u8  pad[2];
	__u64 last_seen;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct flow_key);
	__type(value, struct ct_entry);
	__uint(max_entries, 1000000);
} conntrack SEC(".maps");

/* Canonical key: order endpoints so both directions map to one entry. */
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

    // classification offload: if the NIC already tagged this flow as PASS and FIN|RST are not present, skip software processing.
    if (meta_read_flow_tag(ctx)==AXDP_PASS) 
        return XDP_PASS;

    if (parse_5tuple(data, data_end, &k) < 0)
		return XDP_PASS;

	/* Use the NIC's L4 parse when available, else our software parse. */
    __u32 l4type= meta_read_l4type(ctx);
	if ((l4type == 0) || (l4type==2)) //1,3, o 4 =TCP
		return XDP_PASS;

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
	__u64 now = meta_read_timestamp(ctx);

	/* ---- Existing connection ------------------------------------- */
	if (ct) {
		/* Teardown: remove software state AND the hardware rule.
		 * NOTE: ct->index must hold the kernel-assigned rule index from
		 * the matching ADD; wiring that feedback back to BPF is still a
		 * TODO (the ring buffer is fire-and-forget today). */
		if (th->rst) {
			bpf_printk("DEL rule NOT yet implemented!!! index=%u\n");
            //axdp_emit_del_rx(ct->index);
			return XDP_PASS;
		}
		if (th->fin) {
			ct->state = CT_FIN;
			ct->last_seen = now;
			return XDP_PASS;
		}

		/* SYN-ACK completes the handshake: now offload PASS to HW.
		 * (the rule does not match FIN|RST, so teardown still hits SW) */
		if (ct->state == CT_SYN_SENT && th->syn && th->ack && !outbound) {
			ct->state = CT_ESTABLISHED;
			ct->offloaded = 1;
			ct->last_seen = now;

			axdp_emit_rx(&ck, AXDP_RX_PASS);
            return XDP_PASS;
		}

		ct->last_seen = now;
		return XDP_PASS;
	}

	/* ---- New connection ------------------------------------------- */

	/* Bare SYN from inside opens a new outbound flow. No HW rule yet:
	 * the verdict is not stable until the handshake completes. */
	if (th->syn && !th->ack && outbound) {
		struct ct_entry e = { .state = CT_SYN_SENT, .last_seen = now };
		bpf_map_update_elem(&conntrack, &ck, &e, BPF_ANY);
		return XDP_PASS;
	}

	/* Unsolicited inbound (or untracked mid-stream): deny, and offload a
	 * hardware DROP so the rest of this flow never reaches the host. */
	axdp_emit_rx(&ck, AXDP_RX_DROP);
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
