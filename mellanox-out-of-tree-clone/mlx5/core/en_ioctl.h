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
 * Request/response payload for every ioctl.
 *   - For ADD_TX_RULE: @value is the 32-bit WQE metadata tag (reg_a) to DROP.
 *   - For ADD_RX_RULE: @value is the destination IPv4 (network byte order)
 *                      to DROP on ingress.
 *   - For DEL_*_RULE:  @value is the rule index returned by a previous ADD.
 *   - On ADD, the kernel writes the assigned rule index back into @index.
 */
struct axdp_ioctl_rule {
	__u32 value;	/* IN:  meta tag / dst IPv4 / index to delete */
	__u32 index;	/* OUT: index of the installed rule (ADD only) */
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
