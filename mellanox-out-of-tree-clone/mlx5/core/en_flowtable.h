/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
#ifndef __MLX5_EN_FLOWTABLE_H__
#define __MLX5_EN_FLOWTABLE_H__

#include <linux/types.h>
#include <linux/mlx5/driver.h>

#define AXDP_MAX_RULES 1024

struct axdp_flow_ctx {
	struct mlx5_core_dev       *mdev;   /* owning core dev, for dealloc paths */
	struct mlx5_flow_namespace *ns;
	struct mlx5_flow_table     *ft;
	struct mlx5_flow_handle    *rules[AXDP_MAX_RULES];
	struct mlx5_modify_hdr     *mod_hdr[AXDP_MAX_RULES];  /* NULL if none */
	struct mlx5_pkt_reformat   *pkt_reformat[AXDP_MAX_RULES]; /* NULL if none */
	int                         n_rules;
};

int add_meta_table(struct mlx5_core_dev *mdev, struct axdp_flow_ctx *ctx);
int add_meta_rule(struct mlx5_core_dev *mdev, struct axdp_flow_ctx *ctx, u32 meta_tag);
int add_meta_vlan_rule(struct mlx5_core_dev *mdev, struct axdp_flow_ctx *ctx,
		       u32 meta_tag, u16 vid);

int add_rx_table(struct mlx5_core_dev *mdev, struct axdp_flow_ctx *ctx);
int add_rx_rule(struct mlx5_core_dev *mdev, struct axdp_flow_ctx *ctx,
		__be32 sip, __be32 dip, u8 ip_proto, __be16 sport, __be16 dport,
		u8 action, u32 mark);


int  add_meta_and_dip_rule(struct mlx5_core_dev *mdev, struct axdp_flow_ctx *ctx,
			   u32 meta_tag, __be32 dst_ip);
int add_meta_table_rule(struct mlx5_core_dev *mdev, struct axdp_flow_ctx *ctx, u32 meta_tag);

void del_table_rule(struct axdp_flow_ctx *ctx);
void del_rule(struct axdp_flow_ctx *ctx, u32 index);

#endif /* __MLX5_EN_FLOWTABLE_H__ */
