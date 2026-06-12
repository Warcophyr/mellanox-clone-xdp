/* SPDX-License-Identifier: GPL-2.0 */
/*
 * 7. Telemetry Monitor — an INT-style monitor. PER-PACKET by definition: every
 *    packet must be observed (latency stamped, counters incremented), so no
 *    packet can be skipped by a hardware fast path.
 *
 * A-XDP accelerates it via COMPUTATION offloads only:
 *   - the NIC ingress hardware timestamp (far more accurate than software) is
 *     read from CQE metadata,
 *   - parsed header types and byte count avoid software re-parsing.
 * The program updates per-flow stats every packet and passes the packet on;
 * no Flow Table rule is installed.
 */
#include "axdp.h"

struct flow_stats {
	__u64 packets;
	__u64 bytes;
	__u64 last_ts;       /* previous arrival, ns        */
	__u64 sum_iat;       /* sum of inter-arrival times  */
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct flow_key);
	__type(value, struct flow_stats);
	__uint(max_entries, 2000000);
} telemetry SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct flow_key k = {};

	if (parse_5tuple(data, data_end, &k) < 0)
		return XDP_PASS;

	/* COMPUTATION offload: precise ingress timestamp from the NIC. */
	__u64 ts = 0;
	if (bpf_xdp_metadata_rx_timestamp(ctx, &ts) != 0)
		ts = bpf_ktime_get_ns();   /* fallback: software clock */

	/* COMPUTATION offload: hardware byte count. */
	__u32 len = 0;
	if (bpf_xdp_axdp_rx_byte_count(ctx, &len) != 0)
		len = data_end - data;     /* fallback */

	struct flow_stats *s = bpf_map_lookup_elem(&telemetry, &k);
	if (!s) {
		struct flow_stats ns = {
			.packets = 1, .bytes = len, .last_ts = ts, .sum_iat = 0,
		};
		bpf_map_update_elem(&telemetry, &k, &ns, BPF_ANY);
		return XDP_PASS;
	}

	/* Per-packet update — runs for every packet, the whole point. */
	__u64 iat = ts - s->last_ts;
	s->packets += 1;
	s->bytes   += len;
	s->sum_iat += iat;
	s->last_ts  = ts;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
