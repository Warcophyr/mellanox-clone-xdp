// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * axdp_meta_dip_rule.c  --  versione con auto-grouped flow table
 *
 * Installa una regola sul namespace EGRESS (NIC TX) che matcha:
 *   - WQE metadata (flow_table_metadata -> reg_a)  == meta_tag
 *   - dst IPv4                                       == dst_ip
 * e DROPPA i pacchetti corrispondenti.
 *
 * Usa mlx5_create_auto_grouped_flow_table(): il kernel crea e gestisce i
 * flow group da solo, quindi NON serve mlx5_create_flow_group() manuale
 * (era quella a dare CREATE_FLOW_GROUP bad parameter).
 *
 * Codice KERNEL, da integrare in drivers/.../mellanox/mlx5/core/.
 * Verifica i nomi dei campi (reg_a, lyr_2_4) contro la tua versione.
 */

#include <linux/mlx5/driver.h>
#include <linux/mlx5/fs.h>
#include <linux/mlx5/device.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/if_ether.h>
#include "en_flowtable.h"

int add_meta_and_dip_rule(struct mlx5_core_dev *mdev, struct axdp_flow_ctx *ctx,
			  u32 meta_tag, __be32 dst_ip)
{
	struct mlx5_flow_table_attr ft_attr = {};
	struct mlx5_flow_act flow_act = {};
	struct mlx5_flow_spec *spec = NULL;
	void *outer_c, *outer_v, *misc2_c, *misc2_v;
	int err = 0;

	/*
	 * EGRESS = pipeline TX della NIC. reg_a contiene il metadata
	 * caricato dalla WQE (mlx5_wqe_eth_seg.metadata), quindi e' qui
	 * che ha senso matcharlo per A-XDP.
	 */
	ctx->ns = mlx5_get_flow_namespace(mdev, MLX5_FLOW_NAMESPACE_EGRESS);
	if (!ctx->ns) {
		pr_err("axdp: namespace EGRESS non disponibile\n");
		return -ENODEV;
	}

	/*
	 * Auto-grouped flow table: il kernel partiziona la tabella in flow
	 * group automaticamente. I parametri chiave:
	 *   max_fte        -> dimensione totale
	 *   autogroup.max_num_groups -> quanti gruppi puo' creare il kernel
	 * Va usata mlx5_create_auto_grouped_flow_table(), NON la create
	 * normale, altrimenti dovremmo creare i gruppi a mano.
	 */
	ft_attr.max_fte = 1024;
	ft_attr.level   = 0;
	ft_attr.prio    = 0;
	ft_attr.autogroup.max_num_groups = 8;

	ctx->ft = mlx5_create_auto_grouped_flow_table(ctx->ns, &ft_attr);
	if (IS_ERR(ctx->ft)) {
		err = PTR_ERR(ctx->ft);
		pr_err("axdp: auto_grouped_flow_table err=%d\n", err);
		ctx->ft = NULL;
		return err;
	}

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec) {
		err = -ENOMEM;
		goto out_ft;
	}

	/*
	 * Con l'auto-grouped table NON costruiamo il flow group: impostiamo
	 * solo spec->match_criteria_enable e i campi nello spec. Il kernel
	 * deriva il gruppo dalla maschera in match_criteria.
	 */
	spec->match_criteria_enable =
		MLX5_MATCH_OUTER_HEADERS | MLX5_MATCH_MISC_PARAMETERS_2;
	
	/* ---- outer_headers: ethertype + ip_version + dst IPv4 ---- */
	outer_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
			       outer_headers);
	outer_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
			       outer_headers);

	MLX5_SET(fte_match_set_lyr_2_4, outer_c, ethertype, 0xffff);
	MLX5_SET(fte_match_set_lyr_2_4, outer_v, ethertype, ETH_P_IP);
	MLX5_SET(fte_match_set_lyr_2_4, outer_c, ip_version, 0xf);
	MLX5_SET(fte_match_set_lyr_2_4, outer_v, ip_version, 4);

	memset(MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_c,
			    dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
	       0xff, 4);
	memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_v,
			    dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
	       &dst_ip, 4); 
    
	/* ---- misc2: full 32 bit di metadata_reg_a ---- */
	misc2_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
			       misc_parameters_2);
	misc2_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
			       misc_parameters_2);
	MLX5_SET(fte_match_set_misc2, misc2_c, metadata_reg_a, 0xffffffff);
	MLX5_SET(fte_match_set_misc2, misc2_v, metadata_reg_a, meta_tag);

	/* ---- azione: DROP ---- */
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_DROP;

	
	ctx->rules[0] = mlx5_add_flow_rules(ctx->ft, spec, &flow_act, NULL, 0);
	if (IS_ERR(ctx->rules[0])) {
		err = PTR_ERR(ctx->rules[0]);
		pr_err("axdp: add_flow_rules err=%d\n", err);
		ctx->rules[0] = NULL;
		goto out_spec;
	}

	pr_info("axdp: regola EGRESS installata: reg_a=0x%x dst_ip=%pI4 -> DROP\n",
		meta_tag, &dst_ip);

	kvfree(spec);
	return 0;

out_spec:
	kvfree(spec);
out_ft:
	mlx5_destroy_flow_table(ctx->ft);
	ctx->ft = NULL;
	return err;
}

int add_meta_table_rule(struct mlx5_core_dev *mdev, struct axdp_flow_ctx *ctx, u32 meta_tag)
{
	struct mlx5_flow_table_attr ft_attr = {};
	struct mlx5_flow_act flow_act = {};
	struct mlx5_flow_spec *spec = NULL;
	void *misc2_c, *misc2_v;
	int err = 0;

	/*
	 * EGRESS = pipeline TX della NIC. reg_a contiene il metadata
	 * caricato dalla WQE (mlx5_wqe_eth_seg.metadata), quindi e' qui
	 * che ha senso matcharlo per A-XDP.
	 */
	ctx->ns = mlx5_get_flow_namespace(mdev, MLX5_FLOW_NAMESPACE_EGRESS);
	if (!ctx->ns) {
		pr_err("axdp: namespace EGRESS non disponibile\n");
		return -ENODEV;
	}

	/*
	 * Auto-grouped flow table: il kernel partiziona la tabella in flow
	 * group automaticamente. I parametri chiave:
	 *   max_fte        -> dimensione totale
	 *   autogroup.max_num_groups -> quanti gruppi puo' creare il kernel
	 * Va usata mlx5_create_auto_grouped_flow_table(), NON la create
	 * normale, altrimenti dovremmo creare i gruppi a mano.
	 */
	ft_attr.max_fte = 1024;
	ft_attr.level   = 0;
	ft_attr.prio    = 0;
	ft_attr.autogroup.max_num_groups = 8;

	ctx->ft = mlx5_create_auto_grouped_flow_table(ctx->ns, &ft_attr);
	if (IS_ERR(ctx->ft)) {
		err = PTR_ERR(ctx->ft);
		pr_err("axdp: auto_grouped_flow_table err=%d\n", err);
		ctx->ft = NULL;
		return err;
	}

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec) {
		err = -ENOMEM;
		goto out_ft;
	}

	/*
	 * Con l'auto-grouped table NON costruiamo il flow group: impostiamo
	 * solo spec->match_criteria_enable e i campi nello spec. Il kernel
	 * deriva il gruppo dalla maschera in match_criteria.
	 */
	spec->match_criteria_enable =
	    MLX5_MATCH_MISC_PARAMETERS_2;

	/* ---- misc2: full 32 bit di metadata_reg_a ---- */
	misc2_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
			       misc_parameters_2);
	misc2_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
			       misc_parameters_2);
	MLX5_SET(fte_match_set_misc2, misc2_c, metadata_reg_a, 0xffffffff);
	MLX5_SET(fte_match_set_misc2, misc2_v, metadata_reg_a, meta_tag);

	/* ---- azione: DROP ---- */
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_DROP;

	ctx->rules[0] = mlx5_add_flow_rules(ctx->ft, spec, &flow_act, NULL, 0);
	if (IS_ERR(ctx->rules[0])) {
		err = PTR_ERR(ctx->rules[0]);
		pr_err("axdp: add_flow_rules err=%d\n", err);
		ctx->rules[0] = NULL;
		goto out_spec;
	}

	pr_info("axdp: regola EGRESS installata: reg_a=0x%x -> DROP\n",
		meta_tag);

	kvfree(spec);
	return 0;

out_spec:
	kvfree(spec);
out_ft:
	mlx5_destroy_flow_table(ctx->ft);
	ctx->ft = NULL;
	return err;
}

int add_meta_table(struct mlx5_core_dev *mdev, struct axdp_flow_ctx *ctx)
{
	struct mlx5_flow_table_attr ft_attr = {};
	int err = 0;

	/*
	 * EGRESS = pipeline TX della NIC. reg_a contiene il metadata
	 * caricato dalla WQE (mlx5_wqe_eth_seg.metadata), quindi e' qui
	 * che ha senso matcharlo per A-XDP.
	 */
	ctx->ns = mlx5_get_flow_namespace(mdev, MLX5_FLOW_NAMESPACE_EGRESS);
	if (!ctx->ns) {
		pr_err("axdp: namespace EGRESS non disponibile\n");
		return -ENODEV;
	}

	/*
	 * Auto-grouped flow table: il kernel partiziona la tabella in flow
	 * group automaticamente. I parametri chiave:
	 *   max_fte        -> dimensione totale
	 *   autogroup.max_num_groups -> quanti gruppi puo' creare il kernel
	 * Va usata mlx5_create_auto_grouped_flow_table(), NON la create
	 * normale, altrimenti dovremmo creare i gruppi a mano.
	 */
	ft_attr.max_fte = 1024;
	ft_attr.level   = 0;
	ft_attr.prio    = 0;
	ft_attr.autogroup.max_num_groups = 8;

	ctx->ft = mlx5_create_auto_grouped_flow_table(ctx->ns, &ft_attr);
	if (IS_ERR(ctx->ft)) {
		err = PTR_ERR(ctx->ft);
		pr_err("axdp: auto_grouped_flow_table err=%d\n", err);
		ctx->ft = NULL;
		return err;
	}
	ctx->n_rules = 0;
	return 0;
}

int add_meta_rule(struct mlx5_core_dev *mdev, struct axdp_flow_ctx *ctx, u32 meta_tag) {
	struct mlx5_flow_act flow_act = {};
	struct mlx5_flow_spec *spec = NULL;
	void *misc2_c, *misc2_v;
	int err = 0;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec) {
		err = -ENOMEM;
		goto out_ft;
	}

	/*
	 * Con l'auto-grouped table NON costruiamo il flow group: impostiamo
	 * solo spec->match_criteria_enable e i campi nello spec. Il kernel
	 * deriva il gruppo dalla maschera in match_criteria.
	 */
	spec->match_criteria_enable =
	    MLX5_MATCH_MISC_PARAMETERS_2;

	/* ---- misc2: full 32 bit di metadata_reg_a ---- */
	misc2_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
			       misc_parameters_2);
	misc2_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
			       misc_parameters_2);
	MLX5_SET(fte_match_set_misc2, misc2_c, metadata_reg_a, 0xffffffff);
	MLX5_SET(fte_match_set_misc2, misc2_v, metadata_reg_a, meta_tag);

	/* ---- azione: DROP ---- */
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_DROP;
	
	ctx->rules[ctx->n_rules] = mlx5_add_flow_rules(ctx->ft, spec, &flow_act, NULL, 0);
	if (IS_ERR(ctx->rules[ctx->n_rules])) {
		err = PTR_ERR(ctx->rules[ctx->n_rules]);
		pr_err("axdp: add_flow_rules err=%d\n", err);
		ctx->rules[ctx->n_rules] = NULL;
		goto out_spec;
	}
	ctx->n_rules++;

	pr_info("axdp: regola EGRESS installata: reg_a=0x%x -> DROP\n",
		meta_tag);

	kvfree(spec);
	return 0;

out_spec:
	kvfree(spec);
out_ft:
	//mlx5_destroy_flow_table(ctx->ft);
	//ctx->ft = NULL;
	return err;
}


int add_rx_table(struct mlx5_core_dev *mdev, struct axdp_flow_ctx *ctx)
{
	struct mlx5_flow_table_attr ft_attr = {};
	int err = 0;

	/*
	 * INGRESS = pipeline RX della NIC. 
	 */
	ctx->ns = mlx5_get_flow_namespace(mdev, MLX5_FLOW_NAMESPACE_BYPASS);
	if (!ctx->ns) {
		pr_err("axdp: namespace BYPASS non disponibile\n");
		return -ENODEV;
	}

	/*
	 * Auto-grouped flow table: il kernel partiziona la tabella in flow
	 * group automaticamente. I parametri chiave:
	 *   max_fte        -> dimensione totale
	 *   autogroup.max_num_groups -> quanti gruppi puo' creare il kernel
	 * Va usata mlx5_create_auto_grouped_flow_table(), NON la create
	 * normale, altrimenti dovremmo creare i gruppi a mano.
	 */
	ft_attr.max_fte = 1024;
	ft_attr.level   = 0;
	ft_attr.prio    = 0;
	ft_attr.autogroup.max_num_groups = 8;

	ctx->ft = mlx5_create_auto_grouped_flow_table(ctx->ns, &ft_attr);
	if (IS_ERR(ctx->ft)) {
		err = PTR_ERR(ctx->ft);
		pr_err("axdp: auto_grouped_flow_table err=%d\n", err);
		ctx->ft = NULL;
		return err;
	}

	return 0;
}

int add_rx_rule(struct mlx5_core_dev *mdev, struct axdp_flow_ctx *ctx, __be32 dip) {
	struct mlx5_flow_act flow_act = {};
	struct mlx5_flow_spec *spec = NULL;
	void *outer_c, *outer_v;
	int err = 0;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec) {
		err = -ENOMEM;
		goto out_ft;
	}

	/*
	 * Con l'auto-grouped table NON costruiamo il flow group: impostiamo
	 * solo spec->match_criteria_enable e i campi nello spec. Il kernel
	 * deriva il gruppo dalla maschera in match_criteria.
	 */
	spec->match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;

	/* ---- outer_headers: ethertype + ip_version + dst IPv4 ---- */
	outer_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
			       outer_headers);
	outer_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
			       outer_headers);

	MLX5_SET(fte_match_set_lyr_2_4, outer_c, ethertype, 0xffff);
	MLX5_SET(fte_match_set_lyr_2_4, outer_v, ethertype, ETH_P_IP);
	MLX5_SET(fte_match_set_lyr_2_4, outer_c, ip_version, 0xf);
	MLX5_SET(fte_match_set_lyr_2_4, outer_v, ip_version, 4);

	memset(MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_c,
			    dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
	       0xff, 4);
	memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_v,
			    dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
	       &dip, 4);

	/* ---- azione: DROP ---- */
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_DROP;

	ctx->rules[ctx->n_rules] = mlx5_add_flow_rules(ctx->ft, spec, &flow_act, NULL, 0);
	if (IS_ERR(ctx->rules[ctx->n_rules])) {
		err = PTR_ERR(ctx->rules[ctx->n_rules]);
		pr_err("axdp: add_flow_rules err=%d\n", err);
		ctx->rules[ctx->n_rules] = NULL;
		goto out_spec;
	}
    ctx->n_rules++;
	pr_info("axdp: regola RX installata: dst_ip=%pI4 -> DROP\n", &dip);
	
	kvfree(spec);
	return 0;

out_spec:
	kvfree(spec);
out_ft:
	//mlx5_destroy_flow_table(ctx->ft);
	//ctx->ft = NULL;
	return err;
}


void del_rule(struct axdp_flow_ctx *ctx, u32 index)
{
	if (index >= AXDP_MAX_RULES)
		return;
	if (!ctx->rules[index])
		return;
	mlx5_del_flow_rules(ctx->rules[index]);
	ctx->rules[index] = NULL;
	if (ctx->n_rules)
		ctx->n_rules--;
}

void del_table_rule(struct axdp_flow_ctx *ctx)
{
	int i;
	for (i = 0; i < ctx->n_rules; i++)
		if (ctx->rules[i])
			mlx5_del_flow_rules(ctx->rules[i]);
	ctx->n_rules = 0;
	if (ctx->ft)
		mlx5_destroy_flow_table(ctx->ft);
	/* niente flow group da distruggere: gestito dall'auto-grouped table */
	memset(ctx, 0, sizeof(*ctx));
}