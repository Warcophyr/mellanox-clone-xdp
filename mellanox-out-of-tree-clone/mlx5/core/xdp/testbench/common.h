/* SPDX-License-Identifier: GPL-2.0 */
/* common.h — shared definitions for the pure-software XDP programs.
 * Standard XDP/eBPF only: no A-XDP kfuncs, no hardware offload. */
#ifndef __COMMON_H
#define __COMMON_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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

static __always_inline __u32 sw_hash(const struct flow_key *k)
{
	return k->src_ip ^ k->dst_ip ^
	       ((__u32)k->src_port << 16 | k->dst_port) ^ k->proto;
}

static __always_inline int swap_mac(void *data, void *data_end)
{
	struct ethhdr *eth = data;
	__u8 tmp[ETH_ALEN];

	if ((void *)(eth + 1) > data_end)
		return -1;
	__builtin_memcpy(tmp, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, tmp, ETH_ALEN);
	return 0;
}

#endif /* __COMMON_H */