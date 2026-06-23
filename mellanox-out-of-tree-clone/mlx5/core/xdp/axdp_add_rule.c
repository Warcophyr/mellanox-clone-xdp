// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * axdp_add_rule.c -- minimal userspace tool to add an A-XDP flow rule via the
 * driver's ioctl device (/dev/mlx5_axdp).
 *
 * Build:  cc -o axdp_add_rule axdp_add_rule.c
 *
 * Usage:
 *   ./axdp_add_rule tx <meta_tag_hex>    # DROP packets whose WQE reg_a == tag
 *   ./axdp_add_rule vlan <meta_tag_hex> <vid>  # push C-VLAN <vid> when reg_a == tag
 *   ./axdp_add_rule rx <dst_ipv4>        # legacy: DROP ingress packets to dst IP
 *   ./axdp_add_rule rx [5-tuple flags]   # DROP ingress packets matching the tuple
 *   ./axdp_add_rule del-tx <index>       # remove a TX rule by its index
 *   ./axdp_add_rule del-rx <index>       # remove an RX rule by its index
 *   ./axdp_add_rule prio-rate <kbps>     # rate-limit the low-prio XDP SQ (0=off)
 *
 * RX 5-tuple flags (any omitted field is a wildcard):
 *   --sip  <ipv4>          source IPv4
 *   --dip  <ipv4>          destination IPv4
 *   --proto <tcp|udp|N>    L4 protocol (name or number)
 *   --sport <port>         L4 source port      (requires tcp/udp)
 *   --dport <port>         L4 destination port (requires tcp/udp)
 *   --action <drop|pass|mark>  verdict for matching packets (default drop)
 *   --mark <hex32>         32-bit value written to REG_B (implies --action mark)
 *   --no-rst-fin           TCP only: match only segments with neither FIN nor
 *                          RST set (live-connection traffic; ignores teardown)
 *
 * Examples:
 *   ./axdp_add_rule tx 0x2a2a2a2a
 *   ./axdp_add_rule vlan 0x2a2a2a2a 100
 *   ./axdp_add_rule rx 204.71.200.129
 *   ./axdp_add_rule rx --dip 172.16.112.100 --proto tcp --dport 80
 *   ./axdp_add_rule rx --sip 10.0.0.1 --dip 10.0.0.2 --proto udp --sport 53 --dport 5353
 *   ./axdp_add_rule rx --dip 10.0.0.2 --proto tcp --dport 443 --action pass
 *   ./axdp_add_rule rx --dip 10.0.0.2 --proto tcp --dport 443 --mark 0xdeadbeef
 *   ./axdp_add_rule del-tx 0
 *   ./axdp_add_rule del-rx 0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "../en_ioctl.h"	/* shared ABI: struct axdp_ioctl_rule, AXDP_IOC_* */

#define DEV_PATH "/dev/" AXDP_IOCTL_DEV_NAME

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage:\n"
		"  %s tx <meta_tag_hex>\n"
		"  %s vlan <meta_tag_hex> <vid>\n"
		"  %s rx <dst_ipv4>\n"
		"  %s rx [--sip <ipv4>] [--dip <ipv4>] [--proto <tcp|udp|N>]"
		" [--sport <port>] [--dport <port>] [--action <drop|pass|mark>]"
		" [--mark <hex32>] [--no-rst-fin]\n"
		"  %s del-tx <index>\n"
		"  %s del-rx <index>\n"
		"  %s prio-rate <kbps>   (0 disables)\n",
		prog, prog, prog, prog, prog, prog, prog);
}

/* Parse a dotted-quad into network-order 32-bit. Returns 0 on success. */
static int parse_ipv4(const char *s, __u32 *out)
{
	struct in_addr ip;

	if (inet_pton(AF_INET, s, &ip) != 1) {
		fprintf(stderr, "invalid IPv4 address: %s\n", s);
		return -1;
	}
	*out = ip.s_addr;
	return 0;
}

/* Parse "tcp"/"udp" or a numeric protocol. Returns 0 on success. */
static int parse_proto(const char *s, __u8 *out)
{
	if (strcmp(s, "tcp") == 0)
		*out = IPPROTO_TCP;
	else if (strcmp(s, "udp") == 0)
		*out = IPPROTO_UDP;
	else
		*out = (__u8)strtoul(s, NULL, 0);
	return 0;
}

/* Parse a port (host decimal) into a network-order 16-bit. Returns 0 on ok. */
static int parse_port(const char *s, __u16 *out)
{
	unsigned long p = strtoul(s, NULL, 0);

	if (p > 0xffff) {
		fprintf(stderr, "invalid port: %s\n", s);
		return -1;
	}
	*out = htons((__u16)p);
	return 0;
}

/* Build an ADD_RX request from the --flag style 5-tuple arguments. */
static int parse_rx_tuple(int argc, char **argv, struct axdp_ioctl_rule *req)
{
	int i;

	for (i = 2; i < argc; i++) {
		/* Valueless flags first (no operand follows). */
		if (strcmp(argv[i], "--no-rst-fin") == 0) {
			req->match_flags |= AXDP_RX_MATCH_NO_RST_FIN;
			continue;
		}

		if (i + 1 >= argc) {
			fprintf(stderr, "missing value for %s\n", argv[i]);
			return -1;
		}
		if (strcmp(argv[i], "--sip") == 0) {
			if (parse_ipv4(argv[++i], &req->src_ip))
				return -1;
		} else if (strcmp(argv[i], "--dip") == 0) {
			if (parse_ipv4(argv[++i], &req->dst_ip))
				return -1;
		} else if (strcmp(argv[i], "--proto") == 0) {
			if (parse_proto(argv[++i], &req->ip_proto))
				return -1;
		} else if (strcmp(argv[i], "--sport") == 0) {
			if (parse_port(argv[++i], &req->src_port))
				return -1;
		} else if (strcmp(argv[i], "--dport") == 0) {
			if (parse_port(argv[++i], &req->dst_port))
				return -1;
		} else if (strcmp(argv[i], "--action") == 0) {
			const char *a = argv[++i];

			if (strcmp(a, "drop") == 0)
				req->action = AXDP_RX_DROP;
			else if (strcmp(a, "pass") == 0)
				req->action = AXDP_RX_PASS;
			else if (strcmp(a, "mark") == 0)
				req->action = AXDP_RX_MARK;
			else {
				fprintf(stderr,
					"invalid action '%s' (drop|pass|mark)\n", a);
				return -1;
			}
		} else if (strcmp(argv[i], "--mark") == 0) {
			req->mark = (__u32)strtoul(argv[++i], NULL, 0);
			req->action = AXDP_RX_MARK;
		} else {
			fprintf(stderr, "unknown rx option '%s'\n", argv[i]);
			return -1;
		}
	}

	if ((req->src_port || req->dst_port) &&
	    req->ip_proto != IPPROTO_TCP && req->ip_proto != IPPROTO_UDP) {
		fprintf(stderr, "--sport/--dport require --proto tcp or udp\n");
		return -1;
	}
	if ((req->match_flags & AXDP_RX_MATCH_NO_RST_FIN) &&
	    req->ip_proto != IPPROTO_TCP) {
		fprintf(stderr, "--no-rst-fin requires --proto tcp\n");
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct axdp_ioctl_rule req = { 0 };
	unsigned long cmd;
	int fd, ret;

	if (argc < 3) {
		usage(argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "tx") == 0) {
		if (argc != 3) {
			usage(argv[0]);
			return 1;
		}
		cmd = AXDP_IOC_ADD_TX_RULE;
		req.value = (unsigned int)strtoul(argv[2], NULL, 0);
		req.value = htonl(req.value); /* kernel expects network byte order */
	} else if (strcmp(argv[1], "vlan") == 0) {
		unsigned long vid;

		if (argc != 4) {
			usage(argv[0]);
			return 1;
		}
		cmd = AXDP_IOC_ADD_VLAN_RULE;
		req.value = (unsigned int)strtoul(argv[2], NULL, 0);
		req.value = htonl(req.value); /* same reg_a match as tx rules */

		vid = strtoul(argv[3], NULL, 0);
		if (vid > 0xfff) {
			fprintf(stderr, "invalid vlan id %lu (0-4095)\n", vid);
			return 1;
		}
		req.vid = (__u16)vid;
	} else if (strcmp(argv[1], "rx") == 0) {
		cmd = AXDP_IOC_ADD_RX_RULE;
		if (argc == 3 && strncmp(argv[2], "--", 2) != 0) {
			/* legacy form: rx <dst_ipv4>, forwarded via @value */
			if (parse_ipv4(argv[2], &req.value))
				return 1;
		} else if (parse_rx_tuple(argc, argv, &req)) {
			return 1;
		}
	} else if (strcmp(argv[1], "del-tx") == 0) {
		if (argc != 3) {
			usage(argv[0]);
			return 1;
		}
		cmd = AXDP_IOC_DEL_TX_RULE;
		req.value = (unsigned int)strtoul(argv[2], NULL, 0);
	} else if (strcmp(argv[1], "del-rx") == 0) {
		if (argc != 3) {
			usage(argv[0]);
			return 1;
		}
		cmd = AXDP_IOC_DEL_RX_RULE;
		req.value = (unsigned int)strtoul(argv[2], NULL, 0);
	} else if (strcmp(argv[1], "prio-rate") == 0) {
		if (argc != 3) {
			usage(argv[0]);
			return 1;
		}
		cmd = AXDP_IOC_SET_PRIO_RATE;
		/* rate in kbps, host byte order (kernel reads @value directly) */
		req.value = (unsigned int)strtoul(argv[2], NULL, 0);
	} else {
		fprintf(stderr,
			"unknown rule type '%s' (use tx, rx, vlan, del-tx, del-rx or prio-rate)\n",
			argv[1]);
		return 1;
	}

	fd = open(DEV_PATH, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "open(%s): %s\n", DEV_PATH, strerror(errno));
		return 1;
	}

	ret = ioctl(fd, cmd, &req);
	if (ret < 0) {
		fprintf(stderr, "ioctl: %s\n", strerror(errno));
		close(fd);
		return 1;
	}

	if (cmd == AXDP_IOC_DEL_TX_RULE || cmd == AXDP_IOC_DEL_RX_RULE)
		printf("rule at index %u removed\n", req.value);
	else if (cmd == AXDP_IOC_SET_PRIO_RATE)
		printf("sq_prio rate set to %u kbps%s\n", req.value,
		       req.value ? "" : " (disabled)");
	else
		printf("rule added at index %u\n", req.index);

	close(fd);
	return 0;
}
