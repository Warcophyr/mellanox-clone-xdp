/* SPDX-License-Identifier: GPL-2.0 */
/*
 * 6. Rate Policer — a token-bucket policer. PER-PACKET: the verdict changes on
 *    every packet, so it cannot be reduced to a stable Flow Table rule and the
 *    program must run on every packet.
 *
 * A-XDP still accelerates it via COMPUTATION offloads only:
 *   - the NIC hardware timestamp drives token refill (no software clock call),
 *   - the NIC byte count avoids re-deriving packet length,
 *   - flow_table_metadata supplies a per-flow id.
 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "axdp_ringbuf.h"
#include "axdp.h"

/* Custom return code routing the frame to the low-priority (rate-limited)
 * second XDP SQ. Mirrors XDP_TX_2 in mlx5 en/xdp.c. */
#ifndef XDP_TX2
#define XDP_TX2 5
#endif

struct bucket {
	__u64 tokens;       /* bytes available  */
	__u64 last_ts;      /* ns of last refill */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct flow_key);    
	__type(value, struct bucket);
	__uint(max_entries, 4096);
} buckets SEC(".maps");

#ifdef AXDP_TEST
/* --- A-XDP acceleration machinery (id/ft_metadata fast path) ----------------
 * Only needed when built with -DAXDP_TEST. Mirrors the maps/helpers defined in
 * axdp_telemetry.bpf.c, but conn_by_id stores the token bucket directly so the
 * fast path can refill/charge without a 5-tuple hash lookup. */

/* 1 MiB ring buffer; pinned by name so the daemon finds it at /sys/fs/bpf/axdp_rb. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} axdp_rb SEC(".maps");

/* Enqueue an ADD_RX rule matching the IPv4 5-tuple. With AXDP_RX_MARK the NIC
 * writes @mark into ft_metadata on subsequent packets. See axdp_emit_rx5 in
 * axdp_firewall.bpf.c for the full contract. */
static __always_inline int axdp_emit_rx5(__u32 sip, __u32 dip, __u8 proto,
					 __u16 sport, __u16 dport, __u8 action,
					 __u32 mark, __u8 *value, __u8 match_flags)
{
	struct axdp_rb_event *ev;

	ev = bpf_ringbuf_reserve(&axdp_rb, sizeof(*ev), 0);
	if (!ev)
		return -1;
	__builtin_memset(ev, 0, sizeof(*ev));
	ev->op = AXDP_OP_ADD_RX;
	ev->src_ip = sip;
	ev->dst_ip = dip;
	ev->src_port = sport;
	ev->dst_port = dport;
	ev->ip_proto = proto;
	ev->action = action;
	ev->match_flags = match_flags;
	ev->mark = mark;
	ev->value = (__u32)(0x0ffffffff & (__u64)value);
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

/* Number of conn_by_id slots; the id doubles as a dense array index, bounding
 * how many flows can be fast-path accelerated at once. */
#define AXDP_MAX_CONNS 65536

/* id -> token bucket, indexed directly by the id the NIC writes back into
 * ft_metadata. Fast-path recovery is a single bounded array load. Slot 0 is
 * unused (id 0 means "no mark"). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, AXDP_MAX_CONNS);
	__type(key, __u32);
	__type(value, struct bucket);
} conn_by_id SEC(".maps");

/* Monotonic id generator (single slot, bumped atomically). id 0 is reserved. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} id_gen SEC(".maps");

/* Hand out the next id in [1, AXDP_MAX_CONNS - 1], or 0 when the table is full. */
static __always_inline __u32 axdp_next_id(void)
{
	__u32 zero = 0;
	__u64 *ctr = bpf_map_lookup_elem(&id_gen, &zero);
	__u64 n;

	if (!ctr)
		return 0;
	n = __sync_fetch_and_add(ctr, 1);
	if (n >= AXDP_MAX_CONNS - 1)
		return 0;
	return (__u32)n + 1;
}
#endif /* AXDP_TEST */

#define RATE_BYTES_PER_NS 12ULL    /* ~100 Gbps */
#define BURST_BYTES       (1u << 20)

SEC("xdp")
int xdp_policer(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	//avoid inline header    
	if (stamp_metadata(ctx,0))
            return XDP_DROP;

	/* COMPUTATION offload: hardware timestamp for refill. */
	__u64 now = 0;
#ifdef AXDP_TEST
	now=meta_read_timestamp(ctx);            
	__u32 id = meta_read_ft_metadata(ctx);

	if (id) {
		bpf_printk("match FTE with id=%x",id);
		struct bucket *b = bpf_map_lookup_elem(&conn_by_id, &id);
		if (!b)
			return XDP_TX;
		__u32 len = data_end - data;
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
			return XDP_TX;
		}

		b->tokens = tokens;   /* not enough tokens — low prio */
		return XDP_TX2;
	}
#else
	now=bpf_ktime_get_ns();
#endif    

	__u32 len = data_end - data; 
	struct flow_key k = {};

	if (parse_5tuple(data, data_end, &k) < 0)
		return XDP_TX;

	struct bucket *b = bpf_map_lookup_elem(&buckets, &k);
	if (!b) {
		struct bucket nb = { .tokens = BURST_BYTES, .last_ts = now };
		bpf_map_update_elem(&buckets, &k, &nb, BPF_ANY);
#ifdef AXDP_TEST
		__u32 id = axdp_next_id();
		/* mark == id: the NIC writes it back into ft_metadata. value is
		 * unused for MARK. 
		 */
		bpf_map_update_elem(&conn_by_id, &id, &nb, BPF_ANY);
		axdp_emit_rx5(k.src_ip,k.dst_ip,k.src_port,k.dst_port,k.proto, AXDP_RX_MARK,
				      id /* mark */, NULL /* value */,
				      0);
#endif	
		return XDP_TX;
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
		return XDP_TX;
	}

	b->tokens = tokens;   /* not enough tokens — low prio */
	return XDP_TX2;
}

char _license[] SEC("license") = "GPL";
