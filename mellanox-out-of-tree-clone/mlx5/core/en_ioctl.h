/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * en_ioctl.h -- ABI + kernel hooks for the A-XDP flow-steering ioctl device.
 *
 * The driver exposes a misc char device (/dev/mlx5_axdp). Userspace opens it
 * and issues the ioctl()s below to add/remove flow-steering rules, which map
 * 1:1 onto the helpers in en_flowtable.c.
 *
 * This header is shared between kernel and userspace: the ABI section is
 * always visible, the kernel-only prototypes are guarded by __KERNEL__.
 */
#ifndef __MLX5_EN_IOCTL_H__
#define __MLX5_EN_IOCTL_H__

#include <linux/types.h>
#include <linux/ioctl.h>

/* Name of the device node created under /dev. */
#define AXDP_IOCTL_DEV_NAME	"mlx5_axdp"

/*
 * Action for an ADD_RX_RULE (axdp_ioctl_rule.action / axdp_rb_event.action).
 * Defaulting DROP to 0 keeps legacy callers (which zero the field) on the old
 * drop-only behaviour. Guarded so headers that also define it (axdp_ringbuf.h)
 * can be included together.
 */
#ifndef AXDP_RX_DROP
#define AXDP_RX_DROP	0	/* DROP the matching packets (default)        */
#define AXDP_RX_PASS	1	/* ALLOW: let the matching packets continue   */
#endif

/*
 * Request/response payload for every ioctl.
 *   - For ADD_TX_RULE: @value is the 32-bit WQE metadata tag (reg_a) to DROP.
 *   - For ADD_RX_RULE: the rule matches the IPv4 5-tuple in @src_ip, @dst_ip,
 *                      @ip_proto, @src_port, @dst_port (all in network byte
 *                      order, ports host-significant). Any field left 0 is a
 *                      wildcard. Legacy callers that only fill @value (and
 *                      leave the 5-tuple zeroed) still get the old behaviour:
 *                      @value is taken as the destination IPv4 to DROP.
 *   - For DEL_*_RULE:  @value is the rule index returned by a previous ADD.
 *   - On ADD, the kernel writes the assigned rule index back into @index.
 */
struct axdp_ioctl_rule {
	__u32 value;	/* IN:  meta tag / dst IPv4 (legacy) / index to delete */
	__u32 index;	/* OUT: index of the installed rule (ADD only) */

	/* ADD_RX_RULE 5-tuple (network byte order; 0 = wildcard). */
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8  ip_proto;
	__u8  action;	/* AXDP_RX_DROP (default) / AXDP_RX_PASS */
	__u8  _pad[2];
};

#define AXDP_IOC_MAGIC		'X'

#define AXDP_IOC_ADD_TX_RULE	_IOWR(AXDP_IOC_MAGIC, 1, struct axdp_ioctl_rule)
#define AXDP_IOC_ADD_RX_RULE	_IOWR(AXDP_IOC_MAGIC, 2, struct axdp_ioctl_rule)
#define AXDP_IOC_DEL_TX_RULE	_IOW(AXDP_IOC_MAGIC,  3, struct axdp_ioctl_rule)
#define AXDP_IOC_DEL_RX_RULE	_IOW(AXDP_IOC_MAGIC,  4, struct axdp_ioctl_rule)

#define AXDP_IOC_MAXNR		4

#ifdef __KERNEL__
struct mlx5e_priv;

/*
 * Register/unregister the ioctl device against a given priv. The device is a
 * single global misc node, so only one priv can be bound at a time -- which
 * matches the current single-NIC A-XDP usage. register() is meant to be called
 * once the flow tables exist (i.e. when the XDP program is installed), and
 * unregister() when they are torn down.
 */
int  mlx5e_axdp_ioctl_register(struct mlx5e_priv *priv);
void mlx5e_axdp_ioctl_unregister(struct mlx5e_priv *priv);
#endif /* __KERNEL__ */

#endif /* __MLX5_EN_IOCTL_H__ */
