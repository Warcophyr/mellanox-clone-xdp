// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * axdp_rule_daemon.c -- userspace daemon that drains A-XDP flow-rule
 * operations from a BPF ring buffer and replays them onto the driver's ioctl
 * device (/dev/mlx5_axdp).
 *
 * It is the streaming counterpart of axdp_add_rule: instead of taking one
 * rule from argv, it consumes a continuous stream of add/del operations that a
 * BPF program (see axdp_ringbuf.bpf.c) pushes into a BPF_MAP_TYPE_RINGBUF. Each
 * record is a struct axdp_rb_event encoding one of five operations:
 *   AXDP_OP_ADD_TX, AXDP_OP_ADD_RX, AXDP_OP_DEL_TX, AXDP_OP_DEL_RX,
 *   AXDP_OP_ADD_VLAN.
 *
 * Build:  cc -Wall -O2 -o axdp_rule_daemon axdp_rule_daemon.c -lbpf
 *
 * Usage:
 *   ./axdp_rule_daemon [pinned_ringbuf_path]   # default /sys/fs/bpf/axdp_rb
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "axdp_ringbuf.h"	/* shared ABI: struct axdp_rb_event, AXDP_OP_* */
#include "../en_ioctl.h"	/* shared ABI: struct axdp_ioctl_rule, AXDP_IOC_* */

#define DEV_PATH	"/dev/" AXDP_IOCTL_DEV_NAME
#define DEFAULT_PIN	"/sys/fs/bpf/axdp_rb"

static int dev_fd = -1;
static volatile sig_atomic_t exiting;

static void on_signal(int sig)
{
	(void)sig;
	exiting = 1;
}

static unsigned long op_to_ioctl(__u32 op)
{
	switch (op) {
	case AXDP_OP_ADD_TX:   return AXDP_IOC_ADD_TX_RULE;
	case AXDP_OP_ADD_RX:   return AXDP_IOC_ADD_RX_RULE;
	case AXDP_OP_DEL_TX:   return AXDP_IOC_DEL_TX_RULE;
	case AXDP_OP_DEL_RX:   return AXDP_IOC_DEL_RX_RULE;
	case AXDP_OP_ADD_VLAN: return AXDP_IOC_ADD_VLAN_RULE;
	default:               return 0;
	}
}

static const char *op_name(__u32 op)
{
	switch (op) {
	case AXDP_OP_ADD_TX:   return "add-tx";
	case AXDP_OP_ADD_RX:   return "add-rx";
	case AXDP_OP_DEL_TX:   return "del-tx";
	case AXDP_OP_DEL_RX:   return "del-rx";
	case AXDP_OP_ADD_VLAN: return "add-vlan";
	default:               return "unknown";
	}
}

static const char *action_name(__u8 action)
{
	switch (action) {
	case AXDP_RX_DROP:    return "DROP";
	case AXDP_RX_PASS:    return "PASS";
	case AXDP_RX_MOD_HDR: return "MOD_HDR";
	case AXDP_RX_MARK:    return "MARK";
	default:              return "?";
	}
}

/* ring_buffer callback: one record == one flow-rule operation. */
static int handle_event(void *ctx, void *data, size_t len)
{
	const struct axdp_rb_event *ev = data;
	struct axdp_ioctl_rule req = { 0 };
	unsigned long cmd;

	(void)ctx;

	if (len < sizeof(*ev)) {
		fprintf(stderr, "short ring-buffer record (%zu bytes), skipping\n",
			len);
		return 0;	/* keep draining */
	}

	cmd = op_to_ioctl(ev->op);
	if (!cmd) {
		fprintf(stderr, "unknown op %u, skipping\n", ev->op);
		return 0;
	}

	/* All operands are already in the byte order the kernel expects (the
	 * producer is responsible for that), so forward them verbatim. The
	 * 5-tuple/@mark fields only matter for ADD_RX and @vid only for ADD_VLAN;
	 * the kernel ignores the unused fields for the other ops. */
	req.value    = ev->value;
	req.src_ip   = ev->src_ip;
	req.dst_ip   = ev->dst_ip;
	req.src_port = ev->src_port;
	req.dst_port = ev->dst_port;
	req.ip_proto = ev->ip_proto;
	req.action   = ev->action;
	req.mark     = ev->mark;
	req.vid      = ev->vid;

	if (ioctl(dev_fd, cmd, &req) < 0) {
		fprintf(stderr, "ioctl(%s, value=0x%08x): %s\n",
			op_name(ev->op), ev->value, strerror(errno));
		return 0;	/* one bad rule shouldn't kill the daemon */
	}

	if (ev->op == AXDP_OP_ADD_RX)
		printf("%s sip=0x%08x dip=0x%08x proto=%u sport=%u dport=%u action=%s mark=0x%08x value=0x%08x -> rule index %u\n",
		       op_name(ev->op), ev->src_ip, ev->dst_ip, ev->ip_proto,
		       ntohs(ev->src_port), ntohs(ev->dst_port),
		       action_name(ev->action), ev->mark, ev->value,
		       req.index);
	else if (ev->op == AXDP_OP_ADD_TX)
		printf("%s value=0x%08x -> rule index %u\n",
		       op_name(ev->op), ev->value, req.index);
	else if (ev->op == AXDP_OP_ADD_VLAN)
		printf("%s value=0x%08x vid=%u -> rule index %u\n",
		       op_name(ev->op), ev->value, ev->vid, req.index);
	else
		printf("%s index %u -> removed\n", op_name(ev->op), ev->value);

	return 0;
}

int main(int argc, char **argv)
{
	const char *pin = (argc > 1) ? argv[1] : DEFAULT_PIN;
	struct ring_buffer *rb = NULL;
	int map_fd = -1, ret = 1;

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	/* Locate the ring-buffer map the BPF producer pinned. */
	map_fd = bpf_obj_get(pin);
	if (map_fd < 0) {
		fprintf(stderr, "bpf_obj_get(%s): %s\n", pin, strerror(errno));
		fprintf(stderr, "is the BPF producer loaded with its map pinned?\n");
		return 1;
	}

	dev_fd = open(DEV_PATH, O_RDWR);
	if (dev_fd < 0) {
		fprintf(stderr, "open(%s): %s\n", DEV_PATH, strerror(errno));
		goto out;
	}

	rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ring_buffer__new: %s\n", strerror(errno));
		goto out;
	}

	printf("axdp_rule_daemon: draining %s, issuing ioctls on %s\n",
	       pin, DEV_PATH);

	while (!exiting) {
		int n = ring_buffer__poll(rb, 200 /* ms */);

		if (n < 0 && n != -EINTR) {
			fprintf(stderr, "ring_buffer__poll: %s\n", strerror(-n));
			break;
		}
	}

	printf("axdp_rule_daemon: exiting\n");
	ret = 0;
out:
	ring_buffer__free(rb);
	if (dev_fd >= 0)
		close(dev_fd);
	if (map_fd >= 0)
		close(map_fd);
	return ret;
}
