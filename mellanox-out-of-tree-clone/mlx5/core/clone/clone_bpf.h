/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* XDP packet duplication: interface between the kfunc a BPF program calls to
 * ask for copies and the RX path that makes them.
 */

#ifndef __MLX5E_CLONE_BPF_H__
#define __MLX5E_CLONE_BPF_H__

#include <linux/minmax.h>
#include <linux/percpu.h>
#include <linux/types.h>

/* Upper bound on the copies XDP_CLONE_PASS / XDP_CLONE_TX can ask for.
 *
 * With the count encoded in the return value of the XDP program (act >> 5) it
 * is whatever the program says, up to 2^27. The per-copy bookkeeping lives on
 * the kernel stack, which is 16 KB, and the loop runs in NAPI context, so it
 * has to be capped: a wrong value would overflow the stack long before a page
 * allocation could fail.
 *
 * 64 copies cost 64 * (sizeof(struct xdp_buff) + 2 pointers), about 4.6 KB.
 * Same idea as MAX_TAIL_CALL_CNT: a fixed ceiling enforced at runtime.
 */
#define MLX5E_MAX_XDP_CLONES 64

/* Bytes of metadata the RX path stores in front of the data of every copy, so
 * that the program can tell a copy from the original packet. Must match what
 * en_rx.c writes, and XDP_CLONE_META_SIZE in the patched uapi headers.
 */
#define MLX5E_XDP_CLONE_META_SIZE ((long)sizeof(int))

/* The two duplication actions. Kept local so that this driver still builds
 * against a kernel without the XDP_CLONE_* uapi patch; must match the values
 * of enum xdp_action there, and the ones en_rx.c switches on.
 */
#define MLX5E_XDP_CLONE_PASS 5
#define MLX5E_XDP_CLONE_TX   6

/* Copy request left behind by bpf_xdp_clone().
 *
 * Modelled on struct bpf_redirect_info: the parameters of the request do not
 * travel in the return value of the program, they are recorded here and the RX
 * path reads them after the run. The program can still encode the count in the
 * return value instead, with XDP_CLONE_TX(n); then no request is recorded and
 * nothing has validated the count, so the RX path clamps it.
 */
struct mlx5e_xdp_clone_req {
	u32 n_copies;
	u32 action;
};

DECLARE_PER_CPU(struct mlx5e_xdp_clone_req, mlx5e_xdp_clone_req);

/* Call right before running an XDP program: a request only counts for the run
 * that made it, otherwise a request left by the original packet would still be
 * standing while the program runs on one of its copies.
 */
static inline void mlx5e_xdp_clone_req_reset(void)
{
	struct mlx5e_xdp_clone_req *req = this_cpu_ptr(&mlx5e_xdp_clone_req);

	req->n_copies = 0;
	req->action = 0;
}

/* The request the program made through the kfunc, n_copies == 0 if it made
 * none.
 */
static inline struct mlx5e_xdp_clone_req mlx5e_xdp_clone_req_get(void)
{
	return *this_cpu_ptr(&mlx5e_xdp_clone_req);
}

int mlx5e_clone_bpf_init(void);

#endif /* __MLX5E_CLONE_BPF_H__ */
