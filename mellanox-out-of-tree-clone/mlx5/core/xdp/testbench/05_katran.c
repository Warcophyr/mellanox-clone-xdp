/* SPDX-License-Identifier: GPL-2.0 */
/*
 * 5. Katran — a stateful L4 load balancer. For each new connection, choose a
 *    backend by consistent hashing, rewrite the destination, and XDP_TX. The
 *    choice is pinned for the life of the connection.
 *
 * Flow-cached: the backend assignment is stable after the first packet. The
 * program installs a Flow Table REWRITE+STEER rule so the rest of the
 * connection is DNAT'd and forwarded in hardware, and selects a QoS-privileged
 * TX queue per flow for high-priority backends.
 */
#include "axdp.h"

struct backend {
	__be32 ip;
	__be16 port;
	__u16  tx_queue;     /* QoS class / priority queue */
};

/* Backend pool, indexed by hash bucket. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct backend);
	__uint(max_entries, 256);
} backends SEC(".maps");

/* Connection table: pins each flow to its chosen backend. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct flow_key);
	__type(value, struct backend);
	__uint(max_entries, 4000000);
} conns SEC(".maps");

SEC("xdp")
int xdp_katran(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct flow_key k = {};

	if (parse_5tuple(data, data_end, &k) < 0)
		return XDP_PASS;

	struct backend *be = bpf_map_lookup_elem(&conns, &k);
	if (!be) {
		/* SLOW PATH (first packet): pick a backend.
		 * Prefer the NIC's RSS hash to avoid recomputing it. */
		__u32 hash = 0;
		enum xdp_rss_hash_type ht;
		if (bpf_xdp_metadata_rx_hash(ctx, &hash, &ht) != 0) {
			/* fallback: hash the 5-tuple in software */
			hash = k.src_ip ^ k.dst_ip ^
			       ((__u32)k.src_port << 16 | k.dst_port);
		}
		__u32 bucket = hash % 256;
		struct backend *chosen = bpf_map_lookup_elem(&backends, &bucket);
		if (!chosen)
			return XDP_DROP;

		bpf_map_update_elem(&conns, &k, chosen, BPF_ANY);

		/* Offload the rest of the connection: hardware rewrites the
		 * destination and steers to the backend's TX queue. */
		struct axdp_ft_entry e = {
			.key      = k,
			.action   = AXDP_ACT_REWRITE,
			.nat_ip   = chosen->ip,
			.nat_port = chosen->port,
			.tx_queue = chosen->tx_queue,
		};
		bpf_xdp_axdp_ft_install(ctx, &e);
		be = chosen;
	}

	/* TX offloads (lazy): per-flow QoS queue + destination rewrite. */
	bpf_xdp_axdp_tx_select_queue(ctx, be->tx_queue);
	bpf_xdp_axdp_tx_rewrite(ctx, be->ip, be->port);
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
