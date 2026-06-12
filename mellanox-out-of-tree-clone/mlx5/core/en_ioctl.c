// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * en_ioctl.c -- userspace control of A-XDP flow-steering rules via ioctl.
 *
 * Exposes a misc char device (/dev/mlx5_axdp). Userspace adds/removes flow
 * steering rules through the ioctl()s defined in en_ioctl.h; each one is a thin
 * wrapper around the helpers in en_flowtable.c, operating on the per-priv flow
 * contexts (priv->tx_xdp_flow_ctx / priv->rx_xdp_flow_ctx).
 *
 * Kernel code, integrate under drivers/.../mellanox/mlx5/core/.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#include "en.h"
#include "en_flowtable.h"
#include "en_ioctl.h"

/*
 * The misc device is global, so we keep a single bound priv. Protected by
 * axdp_lock, which also serialises every flow-table mutation -- the mlx5 flow
 * steering helpers are not safe to call concurrently on the same context.
 */
static DEFINE_MUTEX(axdp_lock);
static struct mlx5e_priv *axdp_priv;

static long axdp_do_add_tx(struct mlx5e_priv *priv, struct axdp_ioctl_rule *req)
{
	int idx, err;

	/* add_meta_rule() installs at ctx->n_rules and bumps the counter. */
	idx = priv->tx_xdp_flow_ctx.n_rules;
	err = add_meta_rule(priv->mdev, &priv->tx_xdp_flow_ctx, req->value);
	if (err)
		return err;

	req->index = idx;
	return 0;
}

static long axdp_do_add_rx(struct mlx5e_priv *priv, struct axdp_ioctl_rule *req)
{
	__be32 dip = (__be32)req->dst_ip;
	int idx, err;

	/*
	 * Backward-compat: legacy callers fill only @value (dst IPv4) and leave
	 * the 5-tuple zeroed. Map @value onto the destination IP in that case.
	 */
	if (!req->src_ip && !req->dst_ip && !req->ip_proto)
		dip = (__be32)req->value;

	idx = priv->rx_xdp_flow_ctx.n_rules;
	err = add_rx_rule(priv->mdev, &priv->rx_xdp_flow_ctx,
			  (__be32)req->src_ip, dip, req->ip_proto,
			  (__be16)req->src_port, (__be16)req->dst_port,
			  req->action);
	if (err)
		return err;

	req->index = idx;
	return 0;
}

static long axdp_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	struct axdp_ioctl_rule req;
	struct mlx5e_priv *priv;
	long ret;

	/* Basic command sanity. */
	if (_IOC_TYPE(cmd) != AXDP_IOC_MAGIC || _IOC_NR(cmd) > AXDP_IOC_MAXNR)
		return -ENOTTY;

	if (copy_from_user(&req, uarg, sizeof(req)))
		return -EFAULT;
	req.index = 0;

	mutex_lock(&axdp_lock);

	priv = axdp_priv;
	if (!priv) {
		/* No XDP program / flow tables installed yet. */
		ret = -ENODEV;
		goto out;
	}

	switch (cmd) {
	case AXDP_IOC_ADD_TX_RULE:
		ret = axdp_do_add_tx(priv, &req);
		break;
	case AXDP_IOC_ADD_RX_RULE:
		ret = axdp_do_add_rx(priv, &req);
		break;
	case AXDP_IOC_DEL_TX_RULE:
		del_rule(&priv->tx_xdp_flow_ctx, req.value);
		ret = 0;
		break;
	case AXDP_IOC_DEL_RX_RULE:
		del_rule(&priv->rx_xdp_flow_ctx, req.value);
		ret = 0;
		break;
	default:
		ret = -ENOTTY;
		break;
	}

out:
	mutex_unlock(&axdp_lock);

	/* Report the assigned index (and anything else) back to userspace. */
	if (!ret && (_IOC_DIR(cmd) & _IOC_READ)) {
		if (copy_to_user(uarg, &req, sizeof(req)))
			return -EFAULT;
	}

	return ret;
}

static const struct file_operations axdp_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= axdp_ioctl,
	.compat_ioctl	= axdp_ioctl,
	.llseek		= no_llseek,
};

static struct miscdevice axdp_miscdev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= AXDP_IOCTL_DEV_NAME,
	.fops	= &axdp_fops,
	.mode	= 0600,
};

int mlx5e_axdp_ioctl_register(struct mlx5e_priv *priv)
{
	int err;

	mutex_lock(&axdp_lock);
	if (axdp_priv) {
		/* Already bound (e.g. another netdev). Keep the first one. */
		mutex_unlock(&axdp_lock);
		pr_warn("axdp: ioctl device already bound, ignoring\n");
		return -EBUSY;
	}

	err = misc_register(&axdp_miscdev);
	if (err) {
		mutex_unlock(&axdp_lock);
		pr_err("axdp: misc_register failed: %d\n", err);
		return err;
	}

	axdp_priv = priv;
	mutex_unlock(&axdp_lock);

	pr_info("axdp: ioctl device /dev/%s ready\n", AXDP_IOCTL_DEV_NAME);
	return 0;
}

void mlx5e_axdp_ioctl_unregister(struct mlx5e_priv *priv)
{
	mutex_lock(&axdp_lock);
	if (axdp_priv != priv) {
		mutex_unlock(&axdp_lock);
		return;
	}
	axdp_priv = NULL;
	mutex_unlock(&axdp_lock);

	misc_deregister(&axdp_miscdev);
	pr_info("axdp: ioctl device /dev/%s removed\n", AXDP_IOCTL_DEV_NAME);
}
