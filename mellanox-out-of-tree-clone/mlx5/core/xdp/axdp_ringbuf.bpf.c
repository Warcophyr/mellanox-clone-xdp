// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * axdp_ringbuf.bpf.c -- BPF producer for the A-XDP flow-rule ring buffer.
 *
 * Declares the BPF_MAP_TYPE_RINGBUF that axdp_rule_daemon drains, plus a small
 * helper (axdp_emit) that enqueues one add/del operation. The SEC("xdp")
 * program here is only an example producer: it emits a single ADD_RX rule the
 * first time it runs. Real callers should drop axdp_emit() into their own
 * datapath logic wherever a rule needs to be installed or removed.
 *
 * Build:  clang -O2 -target bpf -c axdp_ringbuf.bpf.c -o axdp_ringbuf.bpf.o
 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "axdp_ringbuf.h"

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
 * Enqueue one scalar flow-rule operation (ADD_TX / DEL_TX / DEL_RX, or a legacy
 * ADD_RX carrying just the dst IPv4 in @value). The whole record is zeroed so
 * the 5-tuple fields stay clear -- otherwise stale ring memory would defeat the
 * kernel's legacy-RX fallback.
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
 * NIC what to do (AXDP_RX_DROP / AXDP_RX_PASS) and @value carrying an
 * action-specific operand (e.g. a redirect queue id; 0 if unused). All operands
 * are in network byte order; any 5-tuple field left 0 is a wildcard on the
 * kernel side.
 */
static __always_inline int axdp_emit_rx5(__u32 sip, __u32 dip, __u8 proto,
					 __u16 sport, __u16 dport, __u8 action,
					 __u32 value)
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
	ev->value = value;
	bpf_ringbuf_submit(ev, 0);
	return 0;
}



/* One-shot guard so the example only emits a single rule. */
int emitted = 0;

SEC("xdp")
int axdp_rb_producer(struct xdp_md *ctx)
{
	if (!emitted) {
		/* Example 5-tuple rule: DROP TCP traffic to dst IPv4
		 * 172.16.112.100 (network order 0x647010AC), TCP dst port 80
		 * (network order 0x5000). src IP / src port left 0 = wildcard. */
		axdp_emit_rx5(0 /* sip */, 0x647010AC /* dip */, IPPROTO_TCP,
			      0 /* sport */, bpf_htons(80) /* dport */,
			      AXDP_RX_DROP, 0 /* value */);
		emitted = 1;
	}
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
