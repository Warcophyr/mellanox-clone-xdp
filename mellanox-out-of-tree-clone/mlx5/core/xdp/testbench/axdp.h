/* SPDX-License-Identifier: GPL-2.0 */
/*
 * axdp.h — A-XDP interface definitions.
 *
 * This header declares the proposed A-XDP extensions used by the seven
 * example programs. They fall into three groups:
 *
 *   1. RX computation offloads  — kfuncs that surface CQE fields the NIC
 *      already computed (timestamp, hash, parsed types, checksum) into the
 *      XDP program. Each returns 0 on success, -ENODATA if the field is null
 *      (graceful fallback to software).
 *
 *   2. RX match/action offloads — a new BPF map type (BPF_MAP_TYPE_FLOWTABLE)
 *      plus kfuncs to install / remove hardware Flow Table entries as a side
 *      effect of processing a packet.
 *
 *   3. TX offloads (lazy)       — kfuncs that record an offload command in the
 *      XDP metadata; the NIC applies it at transmit time. NOTE: these are lazy
 *      — packet bytes are NOT modified until the program returns, so code that
 *      re-reads the packet after the call sees the original content.
 *
 * On hardware without A-XDP support every kfunc returns a negative error and
 * the program falls back to handling the packet in software.
 */
#ifndef __AXDP_H
#define __AXDP_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_IP
#define ETH_P_IP   0x0800
#endif

/* ------------------------------------------------------------------ */
/* Flow key shared by match/action programs                            */
/* ------------------------------------------------------------------ */
struct flow_key {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	__u8   proto;
	__u8   pad[3];
};

/* A hardware Flow Table action to install for a flow. */
enum axdp_ft_action {
	AXDP_ACT_STEER   = 1,   /* steer to rx_queue                    */
	AXDP_ACT_DROP    = 2,   /* drop in hardware before PCIe         */
	AXDP_ACT_PASS    = 3,   /* deliver to host normally             */
	AXDP_ACT_REWRITE = 4,   /* modify-header (NAT) then steer/tx    */
	AXDP_ACT_ENCAP   = 5,   /* inline tunnel encapsulation          */
	AXDP_ACT_DECAP   = 6,   /* inline tunnel decapsulation          */
};

struct axdp_ft_entry {
	struct flow_key key;
	__u32 action;           /* enum axdp_ft_action                  */
	__u32 rx_queue;         /* target queue for STEER               */
	__be32 nat_ip;          /* new addr for REWRITE                 */
	__be16 nat_port;        /* new port for REWRITE                 */
	__u16  tx_queue;        /* egress queue / QoS class             */
	__u32  metadata;        /* value placed in flow_table_metadata  */
};

/* ------------------------------------------------------------------ */
/* (1) RX computation offloads — read NIC-computed CQE fields          */
/* ------------------------------------------------------------------ */
extern int  bpf_xdp_metadata_rx_timestamp(const struct xdp_md *ctx,
					   __u64 *timestamp) __ksym;
extern int  bpf_xdp_metadata_rx_hash(const struct xdp_md *ctx, __u32 *hash,
				     enum xdp_rss_hash_type *type) __ksym;
/* A-XDP additions: parsed types, length, checksum, flow metadata. */
extern int  bpf_xdp_axdp_rx_l3_type(const struct xdp_md *ctx, __u16 *l3) __ksym;
extern int  bpf_xdp_axdp_rx_l4_type(const struct xdp_md *ctx, __u8  *l4) __ksym;
extern int  bpf_xdp_axdp_rx_tunnel_type(const struct xdp_md *ctx,
					__u8 *tun) __ksym;
extern int  bpf_xdp_axdp_rx_csum_ok(const struct xdp_md *ctx) __ksym;
extern int  bpf_xdp_axdp_rx_byte_count(const struct xdp_md *ctx,
				       __u32 *len) __ksym;
extern int  bpf_xdp_axdp_rx_flow_metadata(const struct xdp_md *ctx,
					  __u32 *meta) __ksym;

/* ------------------------------------------------------------------ */
/* (2) RX match/action offloads — install hardware Flow Table entries  */
/* ------------------------------------------------------------------ */
extern int  bpf_xdp_axdp_ft_install(const struct xdp_md *ctx,
				    struct axdp_ft_entry *e) __ksym;
extern int  bpf_xdp_axdp_ft_remove(const struct xdp_md *ctx,
				   struct flow_key *k) __ksym;

/* ------------------------------------------------------------------ */
/* (3) TX offloads — lazy, applied by the NIC at transmit time         */
/* ------------------------------------------------------------------ */
extern int  bpf_xdp_axdp_tx_select_queue(const struct xdp_md *ctx,
					 __u16 tx_queue) __ksym;
extern int  bpf_xdp_axdp_tx_encap(const struct xdp_md *ctx,
				  const void *hdr, __u32 hdr_len) __ksym;
extern int  bpf_xdp_axdp_tx_rewrite(const struct xdp_md *ctx,
				    __be32 new_dst_ip, __be16 new_dst_port) __ksym;
extern int  bpf_xdp_axdp_tx_metadata(const struct xdp_md *ctx,
				     __u32 metadata) __ksym;

/* ------------------------------------------------------------------ */
/* small parse helper used by every program                            */
/* ------------------------------------------------------------------ */
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

#endif /* __AXDP_H */
