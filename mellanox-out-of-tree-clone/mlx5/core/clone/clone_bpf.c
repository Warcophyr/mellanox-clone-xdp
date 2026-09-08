// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* XDP packet duplication: the kfunc a BPF program calls to ask the driver for
 * copies of the packet it is looking at.
 *
 * This is the checked way to ask for copies, parallel to encoding the count in
 * the return value with XDP_CLONE_TX(n). Both work; what this one adds is that
 * the request is validated where it is made, so cases that would cost the
 * packet come back to the program as a value it can act on:
 *
 *   - asking for copies while already running on a copy (nested clone), which
 *     the RX path can only answer with XDP_ABORTED;
 *   - not enough headroom to store the copy metadata, same thing;
 *   - a count of 0, or one that has to be clamped.
 *
 * It also means the count no longer travels in the return value, so a program
 * that computes it at runtime is checked just as well as one that does not.
 *
 * The mechanism is the one bpf_redirect() uses for its ifindex: parameters are
 * left in a per-CPU slot and the RX path picks them up after the run. XDP runs
 * in NAPI context with preemption disabled, so the slot cannot be raced; it is
 * reset before every run, see mlx5e_xdp_clone_req_reset().
 */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <net/xdp.h>

#include "clone_bpf.h"

DEFINE_PER_CPU(struct mlx5e_xdp_clone_req, mlx5e_xdp_clone_req);

__bpf_kfunc_start_defs();

/* bpf_xdp_clone - ask the driver to duplicate this packet
 * @xdp: XDP context, pass the program's ctx
 * @n_copies: number of copies wanted, clamped to MLX5E_MAX_XDP_CLONES
 * @action: XDP_CLONE_PASS or XDP_CLONE_TX, what to do with the original
 * @flags: action to fall back to if the request is refused, in its low bits,
 *	   one of XDP_ABORTED, XDP_DROP, XDP_PASS, XDP_TX. Zero means
 *	   XDP_ABORTED. Same convention as bpf_redirect_map().
 *
 * Meant to be used as the return value of the program:
 *
 *	return bpf_xdp_clone(ctx, n, XDP_CLONE_TX, XDP_PASS);
 *
 * Return: @action if the request was recorded, otherwise the fallback action,
 * so the return value is always something the driver can act on.
 */
__bpf_kfunc int bpf_xdp_clone(struct xdp_buff *xdp, u32 n_copies, u32 action,
			      u64 flags)
{
	const u64 action_mask = XDP_ABORTED | XDP_DROP | XDP_PASS | XDP_TX;
	struct mlx5e_xdp_clone_req *req;

	/* Nothing but a fallback action fits in flags today. XDP_REDIRECT does
	 * not, it does not fit in those two bits, same as for redirect maps.
	 */
	if (unlikely(flags & ~action_mask))
		return XDP_ABORTED;

	if (unlikely(action != MLX5E_XDP_CLONE_PASS &&
		     action != MLX5E_XDP_CLONE_TX))
		return XDP_ABORTED;

	if (unlikely(!n_copies))
		return flags & action_mask;

	/* The driver puts MLX5E_XDP_CLONE_META_SIZE bytes of metadata in front
	 * of the data of every copy, so finding them means this is a copy and
	 * nested cloning is not allowed. Same rule the verifier enforces
	 * statically when the action is a constant in the return value.
	 */
	if ((char *)xdp->data - (char *)xdp->data_meta >=
	    MLX5E_XDP_CLONE_META_SIZE)
		return flags & action_mask;

	/* The RX path has to write that metadata in front of the data of every
	 * copy: without room for it the packet would be aborted after the fact,
	 * so refuse here while the program can still do something about it.
	 */
	if ((char *)xdp->data - (char *)xdp->data_hard_start <
	    MLX5E_XDP_CLONE_META_SIZE)
		return flags & action_mask;

	req = this_cpu_ptr(&mlx5e_xdp_clone_req);
	req->n_copies = min_t(u32, n_copies, MLX5E_MAX_XDP_CLONES);
	req->action = action;

	return action;
}

__bpf_kfunc_end_defs();

BTF_SET8_START(mlx5e_clone_kfunc_ids)
BTF_ID_FLAGS(func, bpf_xdp_clone)
BTF_SET8_END(mlx5e_clone_kfunc_ids)

static const struct btf_kfunc_id_set mlx5e_clone_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &mlx5e_clone_kfunc_ids,
};

/* Needs CONFIG_DEBUG_INFO_BTF_MODULES=y: without BTF for this module the
 * kfunc cannot be resolved and the registration fails.
 */
int mlx5e_clone_bpf_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
					 &mlx5e_clone_kfunc_set);
}
