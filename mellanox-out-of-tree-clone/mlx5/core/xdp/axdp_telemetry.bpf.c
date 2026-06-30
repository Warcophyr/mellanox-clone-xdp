// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * axdp_firewall.bpf.c -- BPF producer for the A-XDP flow-rule ring buffer.
 *
 * Declares the BPF_MAP_TYPE_RINGBUF that axdp_rule_daemon drains, plus small
 * helpers (axdp_emit*) that enqueue one add/del operation. The SEC("xdp")
 * program here is an example firewall producer: it only allows new TCP
 * connections originating inside 10.0.0.0/8 -- the initial SYN from any other
 * source is dropped -- and for each allowed new connection it installs an
 * ADD_RX MARK rule for that flow's 5-tuple. Real callers should drop the
 * axdp_emit*() helpers into their own datapath logic wherever a rule needs to
 * be installed or removed.
 *
 * Build:  clang -O2 -target bpf -c axdp_firewall.bpf.c -o axdp_firewall.bpf.o
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
#include "./axdp.h"

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif


struct flow_stats {
	__u64 packets;
	__u64 bytes;
	__u64 last_ts;       /* previous arrival, ns        */
	__u64 sum_iat;       /* sum of inter-arrival times  */
};


/* 1 MiB ring buffer; pinned by name so the daemon can find it at
 * /sys/fs/bpf/axdp_rb when loaded with `bpftool prog loadall ... pinmaps`. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} axdp_rb SEC(".maps");

/*
 * Enqueue one scalar operation that needs only @value: ADD_TX / DEL_TX /
 * DEL_RX / SET_PRIO_RATE, or a legacy ADD_RX carrying just the dst IPv4 in
 * @value. The whole record is zeroed so the 5-tuple fields stay clear --
 * otherwise stale ring memory would defeat the kernel's legacy-RX fallback.
 * The byte order of @value is op-specific (see the per-op wrappers below).
 */
static __always_inline int axdp_emit(__u32 op, __u32 value)
{
	struct axdp_rb_event *ev;

	ev = bpf_ringbuf_reserve(&axdp_rb, sizeof(*ev), 0);
	if (!ev)
		return -1;
	__builtin_memset(ev, 0, sizeof(*ev));
	ev->op = op;
	ev->value = value;
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

/*
 * Enqueue an ADD_RX rule matching the IPv4 5-tuple, with @action telling the
 * NIC what to do (AXDP_RX_DROP / AXDP_RX_PASS / AXDP_RX_MARK) and @value carrying
 * an action-specific operand (e.g. a redirect queue id; 0 if unused). When
 * @action is AXDP_RX_MARK, @mark is the 32-bit value written to REG_B. All
 * operands are in network byte order; any 5-tuple field left 0 is a wildcard on
 * the kernel side.
 */
static __always_inline int axdp_emit_rx5(__u32 sip, __u32 dip, __u8 proto,
					 __u16 sport, __u16 dport, __u8 action,
					 __u32 mark, __u8* value, __u8 match_flags)
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
	ev->value = (__u32) (0x0ffffffff & (__u64) value);
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

/*
 * Enqueue an ADD_VLAN rule: push the 12-bit C-VLAN id @vid (0-4095) on EGRESS
 * packets whose WQE metadata tag (reg_a) equals @value. @value is in the same
 * network byte order as an ADD_TX tag.
 */
static __always_inline int axdp_emit_vlan(__u32 value, __u16 vid)
{
	struct axdp_rb_event *ev;

	ev = bpf_ringbuf_reserve(&axdp_rb, sizeof(*ev), 0);
	if (!ev)
		return -1;
	__builtin_memset(ev, 0, sizeof(*ev));
	ev->op = AXDP_OP_ADD_VLAN;
	ev->value = value;
	ev->vid = vid;
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

/*
 * Named convenience wrappers mirroring the axdp_add_rule subcommands, so a
 * producer can install/remove the full set of rules with one self-documenting
 * call each. They all build on axdp_emit()/axdp_emit_rx5()/axdp_emit_vlan().
 */

/* tx <tag>: DROP egress packets whose WQE metadata tag (reg_a) == @tag.
 * @tag is in network byte order, like the axdp_add_rule "tx" argument. */
static __always_inline int axdp_emit_tx(__u32 tag)
{
	return axdp_emit(AXDP_OP_ADD_TX, tag);
}

/* del-tx <index>: remove the TX rule at @index (host byte order). */
static __always_inline int axdp_emit_del_tx(__u32 index)
{
	return axdp_emit(AXDP_OP_DEL_TX, index);
}

/* del-rx <index>: remove the RX rule at @index (host byte order). */
static __always_inline int axdp_emit_del_rx(__u32 index)
{
	return axdp_emit(AXDP_OP_DEL_RX, index);
}

/* prio-rate <kbps>: set the low-priority XDP SQ (sq_prio) rate limit to
 * @rate_kbps on every channel (host byte order; 0 disables the limiter). */
static __always_inline int axdp_emit_prio_rate(__u32 rate_kbps)
{
	return axdp_emit(AXDP_OP_SET_PRIO_RATE, rate_kbps);
}



/* Flow key used to de-duplicate connections we have already marked, so a SYN
 * retransmit (or a second SYN) doesn't re-emit a rule. All fields are in
 * network byte order, exactly as they appear on the wire. */
struct conn_key {
	__u32 sip;
	__u32 dip;
	__u16 sport;
	__u16 dport;
};

/* Per-connection state, looked up on the fast path by the 32-bit id the NIC
 * carries back in ft_metadata. This is the object whose "pointer" we want on
 * the fast path -- recovered safely via bpf_map_lookup_elem(&conn_by_id, &id),
 * never by smuggling an address through the 32-bit metadata word. */
struct conn_state {
	struct conn_key key;	/* 5-tuple, network order */
	__u64 packets;		/* fast-path hits for this flow */
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct flow_key);
	__type(value, struct flow_stats);
	__uint(max_entries, 2000000);
} telemetry SEC(".maps");

/* Number of conn_state slots. The id doubles as a dense array index, so this
 * also bounds how many flows can be fast-path accelerated at once. */
#define AXDP_MAX_CONNS 65536

/* id -> conn_state, as a dense ARRAY indexed directly by the id the NIC writes
 * back into ft_metadata. Fast-path recovery is a single bounded array load --
 * no hashing, no key compare. Slot 0 is unused (id 0 means "no mark"). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, AXDP_MAX_CONNS);
	__type(key, __u32);
	__type(value, struct conn_state);
} conn_by_id SEC(".maps");

/* Monotonic id generator (single slot, bumped atomically). id 0 is reserved
 * to mean "no mark", since ft_metadata == 0 is the unmarked case. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} id_gen SEC(".maps");

/* Hand out the next id in [1, AXDP_MAX_CONNS - 1], or 0 when the table is full.
 * The id is used verbatim as the conn_by_id array index. */
static __always_inline __u32 axdp_next_id(void)
{
	__u32 zero = 0;
	__u64 *ctr = bpf_map_lookup_elem(&id_gen, &zero);
	__u64 n;

	if (!ctr)
		return 0;
	n = __sync_fetch_and_add(ctr, 1);	/* 0-based ticket */
	if (n >= AXDP_MAX_CONNS - 1)
		return 0;			/* table exhausted */
	return (__u32)n + 1;			/* 1..AXDP_MAX_CONNS-1 */
}




/*
 * Example firewall producer. For TCP connection establishment (the initial
 * SYN), it allows the connection only if the source address is inside
 * 10.0.0.0/8; SYNs from any other source are dropped. For each allowed new
 * connection it installs an ADD_RX MARK rule for the flow's 5-tuple so the NIC tags subsequent packets with a flow id. The fast path uses that
 * id to recover the conn_state pointer and increment the per-flow packet counter.
 * Non-SYN and non-TCP/non-IPv4 traffic is passed through untouched.
 * The Makefile builds two objects from this 
 * single source: axdp_firewall.bpf.o (plain firewall, no -D) and
 * axdp_firewall_test.bpf.o (built with -DAXDP_TEST for the id/conn_state path).
 */

SEC("xdp")
int axdp_telemetry(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct flow_stats *s =NULL;
	/* read metadata */
	
	
    //avoid inline header    
	if (stamp_metadata(ctx,0))
            return XDP_DROP;

	/* Fast path: packets a rule already matched carry our id in ft_metadata.
	 * Recover the per-flow state by id carried by the NIC.
	 */
#ifdef AXDP_TEST
	__u64 ts=meta_read_timestamp(ctx);            
	__u32 id = meta_read_ft_metadata(ctx);

	if (id) {
		bpf_printk("match FTE with id=%x",id);
		s = bpf_map_lookup_elem(&conn_by_id, &id);
		if (!s)
			return XDP_TX;
		/* Per-packet update — runs for every packet, the whole point. */
		__u32 len = data_end - data;
		__u64 iat = ts - s->last_ts;
		s->packets += 1;
		s->bytes   += len;
		s->sum_iat += iat;
		s->last_ts  = ts;
		return XDP_TX;
	}
#else
	__u64 ts=bpf_ktime_get_ns();
#endif    

	struct flow_key k = {};

	if (parse_5tuple(data, data_end, &k) < 0)
		return XDP_TX;
	__u32 len = data_end - data;

	s = bpf_map_lookup_elem(&telemetry, &k);
	if (!s) {
		struct flow_stats ns = {
			.packets = 1, .bytes = len, .last_ts = ts, .sum_iat = 0,
		};
		bpf_map_update_elem(&telemetry, &k, &ns, BPF_ANY);
	
#ifdef AXDP_TEST
		__u32 id = axdp_next_id();
		/* mark == id: the NIC writes it back into ft_metadata. value is
		 * unused for MARK. 
		 */
		bpf_map_update_elem(&conn_by_id, &id, &ns, BPF_ANY);
		axdp_emit_rx5(k.src_ip,k.dst_ip,k.src_port,k.dst_port,k.proto, AXDP_RX_MARK,
				      id /* mark */, NULL /* value */,
				      0);
#endif	
		return XDP_TX;
	}
	
/* Per-packet update — runs for every packet, the whole point. */
	__u64 iat = ts - s->last_ts;
	s->packets += 1;
	s->bytes   += len;
	s->sum_iat += iat;
	s->last_ts  = ts;

	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
