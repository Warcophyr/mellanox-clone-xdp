/* SPDX-License-Identifier: GPL-2.0 */
/*
 * 4. DNAT — dynamic source NAT. The first packet of a flow allocates a binding
 *    (new source address/port); subsequent packets reuse it.
 *
 * Flow-cached: the binding is fixed once allocated. The program installs a
 * Flow Table REWRITE rule so the NIC performs the header rewrite in hardware
 * for the rest of the flow, and applies the reverse-direction rewrite as a
 * lazy TX offload. flow_table_metadata carries the binding id back to the CPU
 * on slow-path events (e.g. binding expiry).
 */
#include "axdp.h"

struct binding {
	__be32 nat_ip;
	__be16 nat_port;
	__u32  id;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct flow_key);
	__type(value, struct binding);
	__uint(max_entries, 1000000);
} nat_table SEC(".maps");

/* Simple monotonically increasing binding allocator. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} next_id SEC(".maps");

static const __be32 NAT_POOL_IP = 0x0100000a;   /* 10.0.0.1, net order */

SEC("xdp")
int xdp_dnat(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct flow_key k = {};

	if (parse_5tuple(data, data_end, &k) < 0)
		return XDP_PASS;

	struct binding *b = bpf_map_lookup_elem(&nat_table, &k);
	if (!b) {
		/* SLOW PATH (first packet): allocate a binding. */
		__u32 zero = 0;
		__u32 *idp = bpf_map_lookup_elem(&next_id, &zero);
		if (!idp)
			return XDP_PASS;
		__u32 id = __sync_fetch_and_add(idp, 1);

		struct binding nb = {
			.nat_ip   = NAT_POOL_IP,
			.nat_port = bpf_htons(20000 + (id & 0x3fff)),
			.id       = id,
		};
		bpf_map_update_elem(&nat_table, &k, &nb, BPF_ANY);

		/* Install a hardware REWRITE rule; metadata carries the
		 * binding id so the CPU is signalled only on expiry. */
		struct axdp_ft_entry e = {
			.key      = k,
			.action   = AXDP_ACT_REWRITE,
			.nat_ip   = nb.nat_ip,
			.nat_port = nb.nat_port,
			.metadata = id,
		};
		bpf_xdp_axdp_ft_install(ctx, &e);
		b = &nb;
	}

	/* TX offload (lazy): rewrite applied by the NIC at transmit. */
	bpf_xdp_axdp_tx_rewrite(ctx, b->nat_ip, b->nat_port);
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
