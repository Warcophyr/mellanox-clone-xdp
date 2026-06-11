// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * axdp_add_rule.c -- minimal userspace tool to add an A-XDP flow rule via the
 * driver's ioctl device (/dev/mlx5_axdp).
 *
 * Build:  cc -o axdp_add_rule axdp_add_rule.c
 *
 * Usage:
 *   ./axdp_add_rule tx <meta_tag_hex>   # DROP packets whose WQE reg_a == tag
 *   ./axdp_add_rule rx <dst_ipv4>       # DROP ingress packets to this dst IP
 *   ./axdp_add_rule del-tx <index>      # remove a TX rule by its index
 *   ./axdp_add_rule del-rx <index>      # remove an RX rule by its index
 *
 * Examples:
 *   ./axdp_add_rule tx 0x2a2a2a2a
 *   ./axdp_add_rule rx 204.71.200.129
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

#include "../en_ioctl.h"	/* shared ABI: struct axdp_ioctl_rule, AXDP_IOC_* */

#define DEV_PATH "/dev/" AXDP_IOCTL_DEV_NAME

int main(int argc, char **argv)
{
	struct axdp_ioctl_rule req = { 0 };
	unsigned long cmd;
	int fd, ret;

	if (argc != 3) {
		fprintf(stderr,
			"usage: %s tx <meta_tag_hex> | rx <dst_ipv4> | "
			"del-tx <index> | del-rx <index>\n",
			argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "tx") == 0) {
		cmd = AXDP_IOC_ADD_TX_RULE;
		req.value = (unsigned int)strtoul(argv[2], NULL, 0);
		req.value = htonl(req.value); /* kernel expects network byte order */
	} else if (strcmp(argv[1], "rx") == 0) {
		struct in_addr ip;

		cmd = AXDP_IOC_ADD_RX_RULE;
		if (inet_pton(AF_INET, argv[2], &ip) != 1) {
			fprintf(stderr, "invalid IPv4 address: %s\n", argv[2]);
			return 1;
		}
		/* kernel matches the raw network-order 32-bit value */
		req.value = ip.s_addr;
	} else if (strcmp(argv[1], "del-tx") == 0) {
		cmd = AXDP_IOC_DEL_TX_RULE;
		req.value = (unsigned int)strtoul(argv[2], NULL, 0);
	} else if (strcmp(argv[1], "del-rx") == 0) {
		cmd = AXDP_IOC_DEL_RX_RULE;
		req.value = (unsigned int)strtoul(argv[2], NULL, 0);
	} else {
		fprintf(stderr,
			"unknown rule type '%s' (use tx, rx, del-tx or del-rx)\n",
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
	else
		printf("rule added at index %u\n", req.index);

	close(fd);
	return 0;
}
