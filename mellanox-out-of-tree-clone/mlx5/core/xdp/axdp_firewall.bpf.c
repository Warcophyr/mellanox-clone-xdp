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
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "axdp_ringbuf.h"
#include "./axdp.h"

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

/* Internal network the firewall trusts: 10.0.0.0/8. Network byte order so the
 * masked compare against iph->saddr needs no per-packet byte swap. */
#define INTERNAL_NET  bpf_htonl(0xAC107000)	/* 172.16.112.0 */
#define INTERNAL_MASK bpf_htonl(0xFFFFFF00)	/* /24         */

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

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

/* 5-tuple -> assigned id. LRU so eviction is automatic; doubles as the
 * "have we already marked this flow?" dedup set. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct conn_key);
	__type(value, __u32);
} conntrack SEC(".maps");

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

/* Reverse a flow key so we can test the opposite direction. */
static __always_inline void reverse_key(struct conn_key *k, struct conn_key *r)
{
	r->sip   = k->dip;
	r->dip   = k->sip;
	r->sport = k->dport;
	r->dport = k->sport;
	//r->proto    = k->proto;
}

#define XDP_TX_2 5

__always_inline int stamp_metadata(struct xdp_md *ctx, int value) {
        void  *data = (void *)(long)ctx->data;
        __u8  *data_meta  = (void *)(long)ctx->data_meta;
        __u32 *header = (void *)(long)ctx->data_meta;
        if ((void *)data_meta + 8 > data) {
            bpf_printk("no meta space\n");
            return -1;
        }
        header[0] = value;   // metadata value
        header[1] = 0; // inline_hdr_size=0
        return 0;
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
int axdp_rb_producer(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct conn_key key;
	struct tcphdr *tcph;
	struct iphdr *iph;

        /* read metadata */
        /*
	__u64 ts=meta_read_timestamp(ctx);            
        __u32 hash = meta_read_hash(ctx);            
        __u32 flow_tag= meta_read_flow_tag(ctx); 
        __u32 ft_metadata= meta_read_ft_metadata(ctx);

        bpf_printk("hash_result: 0x%x \n", hash);
        bpf_printk("timestamp: %llu\n", ts);
        bpf_printk("flow_tag: 0x%x\n", flow_tag);
        bpf_printk("ft_metadata: 0x%x\n", ft_metadata);
        */
	if (stamp_metadata(ctx,0))
            return XDP_DROP;

	/* Fast path: packets a rule already matched carry our id in ft_metadata.
	 * Recover the per-flow state by id carried by the NIC.
	 */
#ifdef AXDP_TEST
	__u32 id = meta_read_ft_metadata(ctx);

	if (id) {
		struct conn_state *cs = bpf_map_lookup_elem(&conn_by_id, &id);

		if (cs) {
			bpf_printk("match FTE con flusso TCP con %pI4, %pI4, %d , %d id=%d",&cs->key.sip,&cs->key.dip,bpf_ntohs(cs->key.sport),bpf_ntohs(cs->key.dport),id);
			__sync_fetch_and_add(&cs->packets, 1);
		}
		return XDP_TX;
	}
#endif

	// setup or tear-down or without AXDP
	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_DROP;
	if (iph->protocol != IPPROTO_TCP || iph->ihl < 5)
		return XDP_DROP;

	/* Skip IP options to reach the TCP header. */
	tcph = (void *)iph + iph->ihl * 4;
	if ((void *)(tcph + 1) > data_end)
		return XDP_DROP;

	__builtin_memset(&key, 0, sizeof(key));
	key.sip   = iph->saddr;
	key.dip   = iph->daddr;
	key.sport = tcph->source;
	key.dport = tcph->dest;

	struct conn_key rev = {};
	reverse_key(&key, &rev);

	/* Allowed new internal connection: assign an id, stash its state, and
	 * install a MARK rule that tags matching packets with that id. The id is
	 * what the fast path uses to recover the conn_state pointer. */
#ifdef AXDP_TEST
	if (!bpf_map_lookup_elem(&conntrack, &key)) {
		__u32 id = axdp_next_id();
		struct conn_state st = {};

		if (!id)
			return XDP_DROP;

		if ((key.sip & INTERNAL_MASK) == INTERNAL_NET) {
			st.key = key;
			bpf_map_update_elem(&conntrack, &key, &id, BPF_ANY);
			bpf_map_update_elem(&conntrack, &rev, &id, BPF_ANY);

			/* mark == id: the NIC writes it back into ft_metadata. value is
			 * unused for MARK. */
			bpf_map_update_elem(&conn_by_id, &id, &st, BPF_ANY);
			bpf_printk("installo FTE con flusso TCP con %pI4, %pI4, %d , %d id=%d",&key.sip,&key.dip,bpf_ntohs(key.sport),bpf_ntohs(key.dport),id);
			axdp_emit_rx5(key.sip, key.dip, IPPROTO_TCP,
				      key.sport, key.dport, AXDP_RX_MARK,
				      id /* mark */, NULL /* value */,
				      AXDP_RX_MATCH_NO_RST_FIN);
			axdp_emit_rx5(rev.sip, rev.dip, IPPROTO_TCP,
				      rev.sport, rev.dport, AXDP_RX_MARK,
				      id /* mark */, NULL /* value */,
				      AXDP_RX_MATCH_NO_RST_FIN);
		}
		else { 
			bpf_printk("drop flusso TCP con %pI4, %pI4, %d , %d",&key.sip,&key.dip,bpf_ntohs(key.sport),bpf_ntohs(key.dport));
			return XDP_DROP;
		}
	}

#else //no AXDP path: plain firewall, no id / no conn_state table
	if (!bpf_map_lookup_elem(&conntrack, &key)) {
		if ((key.sip & INTERNAL_MASK) == INTERNAL_NET) {
			__u32 seen = 1;	/* presence marker; value is unused here */
			bpf_map_update_elem(&conntrack, &key, &seen, BPF_ANY);
			bpf_map_update_elem(&conntrack, &rev, &seen, BPF_ANY);
			bpf_printk("installo flusso TCP con %pI4, %pI4, %d , %d",&key.sip,&key.dip,bpf_ntohs(key.sport),bpf_ntohs(key.dport));
			return XDP_TX;
		}
		else { 
			bpf_printk("drop flusso TCP con %pI4, %pI4, %d , %d",&key.sip,&key.dip,bpf_ntohs(key.sport),bpf_ntohs(key.dport));
			return XDP_DROP;
		}
	}
#endif
	bpf_printk("NOT match flusso TCP con %pI4, %pI4, %d , %d",&key.sip,&key.dip,bpf_ntohs(key.sport),bpf_ntohs(key.dport));
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
