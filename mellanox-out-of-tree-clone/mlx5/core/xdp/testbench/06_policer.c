/* SPDX-License-Identifier: GPL-2.0 */
/*
 * 6. Rate Policer — a token-bucket policer. PER-PACKET: the verdict changes on
 *    every packet, so it cannot be reduced to a stable Flow Table rule and the
 *    program must run on every packet.
 *
 * A-XDP still accelerates it via COMPUTATION offloads only:
 *   - the NIC hardware timestamp drives token refill (no software clock call),
 *   - the NIC byte count avoids re-deriving packet length,
 *   - flow_table_metadata supplies a per-flow class id (no software lookup).
 * No Flow Table rule is ever installed.
 */
#include "axdp.h"

struct bucket {
	__u64 tokens;       /* bytes available  */
	__u64 last_ts;      /* ns of last refill */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);          /* traffic-class id from NIC metadata */
	__type(value, struct bucket);
	__uint(max_entries, 4096);
} buckets SEC(".maps");

#define RATE_BYTES_PER_NS 12ULL    /* ~100 Gbps */
#define BURST_BYTES       (1u << 20)

SEC("xdp")
int xdp_policer(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* COMPUTATION offload: per-flow class id straight from the NIC. */
	__u32 class = 0;
	if (bpf_xdp_axdp_rx_flow_metadata(ctx, &class) != 0)
		class = 0;   /* fallback: single default class */

	/* COMPUTATION offload: hardware timestamp for refill. */
	__u64 now = 0;
	if (bpf_xdp_metadata_rx_timestamp(ctx, &now) != 0)
		now = bpf_ktime_get_ns();   /* fallback: software clock */

	/* COMPUTATION offload: hardware byte count. */
	__u32 len = 0;
	if (bpf_xdp_axdp_rx_byte_count(ctx, &len) != 0)
		len = data_end - data;      /* fallback */

	struct bucket *b = bpf_map_lookup_elem(&buckets, &class);
	if (!b) {
		struct bucket nb = { .tokens = BURST_BYTES, .last_ts = now };
		bpf_map_update_elem(&buckets, &class, &nb, BPF_ANY);
		b = bpf_map_lookup_elem(&buckets, &class);
		if (!b)
			return XDP_PASS;
	}

	/* Per-packet token arithmetic — this is all the program does. */
	__u64 elapsed = now - b->last_ts;
	__u64 refill  = elapsed * RATE_BYTES_PER_NS;
	__u64 tokens  = b->tokens + refill;
	if (tokens > BURST_BYTES)
		tokens = BURST_BYTES;
	b->last_ts = now;

	if (tokens >= len) {
		b->tokens = tokens - len;
		/* conforming: tag for downstream and transmit */
		bpf_xdp_axdp_tx_metadata(ctx, class);
		return XDP_PASS;
	}

	b->tokens = tokens;   /* not enough tokens — drop */
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
