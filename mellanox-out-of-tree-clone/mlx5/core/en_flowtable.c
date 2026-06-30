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
#include <linux/mlx5/eswitch.h>	/* mlx5_eswitch_mode(), MLX5_ESWITCH_OFFLOADS */
#include <linux/mlx5/vport.h>	/* MLX5_VPORT_UPLINK */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include "en_flowtable.h"
#include "en_ioctl.h"	/* AXDP_RX_DROP / AXDP_RX_PASS */
#include "en.h"		/* struct mlx5e_priv, priv->rx_res */
#include "en/rx_res.h"	/* mlx5e_rx_res_get_tirn_direct() */
#include "lib/mlx5.h"	/* mlx5_uplink_netdev_get() */

int add_tx_and_dip_rule(struct mlx5_core_dev *mdev, struct axdp_flow_ctx *ctx,
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

int add_tx_table_rule(struct mlx5_core_dev *mdev, struct axdp_flow_ctx *ctx, u32 meta_tag)
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

int add_tx_table(struct mlx5_core_dev *mdev, struct axdp_flow_ctx *ctx)
{
	struct mlx5_flow_table_attr ft_attr = {};
	bool switchdev;
	int err = 0;

	/*
	 * In switchdev (eswitch OFFLOADS) mode the uplink egress steering lives
	 * in the FDB, not in the NIC TX EGRESS namespace. The FDB also supports
	 * the native VLAN_PUSH steering action, so add_tx_vlan_rule() can push
	 * a tag directly instead of faking it with a PACKET_REFORMAT/INSERT_HDR.
	 * In legacy mode we keep matching reg_a (the WQE metadata) on the NIC TX
	 * EGRESS namespace as before.
	 */
	switchdev = mlx5_eswitch_mode(mdev) == MLX5_ESWITCH_OFFLOADS;

	/*
	 * Use FDB_BYPASS, not the FDB root: the root's prio-0 major slot holds a
	 * sub-namespace (not tables), so a table created there is not in the
	 * traversed chain. FDB_BYPASS is the highest-priority FDB path, evaluated
	 * before the TC/slow-path forwarding the eswitch installs -- our rules
	 * must sit there to actually catch traffic.
	 */
	ctx->ns = mlx5_get_flow_namespace(mdev,
					  switchdev ? MLX5_FLOW_NAMESPACE_FDB_BYPASS
						    : MLX5_FLOW_NAMESPACE_EGRESS);
	if (!ctx->ns) {
		pr_err("axdp: namespace %s non disponibile\n",
		       switchdev ? "FDB_BYPASS" : "EGRESS");
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
	/*
	 * reformat_en: required so FTEs in this table may carry a
	 * PACKET_REFORMAT action (used by add_tx_vlan_rule() to INSERT_HDR a
	 * VLAN tag) on the legacy EGRESS path. In switchdev mode we use the
	 * native VLAN_PUSH action instead, so the flag is not needed.
	 */
	if (!switchdev)
		ft_attr.flags = MLX5_FLOW_TABLE_TUNNEL_EN_REFORMAT;

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

int add_tx_rule(struct mlx5_core_dev *mdev, struct axdp_flow_ctx *ctx, u32 meta_tag) {
	struct mlx5_flow_act flow_act = {};
	struct mlx5_flow_spec *spec = NULL;
	void *misc2_c, *misc2_v;
	bool switchdev;
	int err = 0;

	/*
	 * add_tx_table() built ctx->ft in the FDB when the eswitch is in
	 * OFFLOADS (switchdev) mode, or in the NIC TX EGRESS namespace otherwise.
	 * The rule below just installs into that table, so it follows whichever
	 * domain was chosen. NB: metadata_reg_a is a NIC-TX-domain register; in
	 * the FDB the WQE metadata is only matchable if it has been copied into a
	 * reg_c (reg_c_0/1 are reserved for vport metadata in switchdev).
	 */
	switchdev = mlx5_eswitch_mode(mdev) == MLX5_ESWITCH_OFFLOADS;

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

	/* del_rule()/del_table_rule() need mdev for dealloc paths. */
	ctx->mdev = mdev;

	ctx->rules[ctx->n_rules] = mlx5_add_flow_rules(ctx->ft, spec, &flow_act, NULL, 0);
	if (IS_ERR(ctx->rules[ctx->n_rules])) {
		err = PTR_ERR(ctx->rules[ctx->n_rules]);
		pr_err("axdp: add_flow_rules (%s) err=%d\n",
		       switchdev ? "fdb" : "egress", err);
		ctx->rules[ctx->n_rules] = NULL;
		goto out_spec;
	}
	ctx->n_rules++;

	pr_info("axdp: !! regola %s installata: reg_a=0x%x -> DROP\n",
		switchdev ? "FDB" : "EGRESS", meta_tag);

	kvfree(spec);
	return 0;

out_spec:
	kvfree(spec);
out_ft:
	//mlx5_destroy_flow_table(ctx->ft);
	//ctx->ft = NULL;
	return err;
}


/*
 * Switchdev (eswitch OFFLOADS) variant: the FDB supports the native VLAN_PUSH
 * steering action, so we push the C-VLAN tag directly and forward the packet
 * out the uplink vport (the wire). This mirrors the eswitch TC vlan-push path
 * (eswitch_offloads.c) and avoids the PACKET_REFORMAT/INSERT_HDR workaround the
 * NIC TX EGRESS namespace needs.
 */
static int add_tx_vlan_rule_switchdev(struct mlx5_core_dev *mdev,
					struct axdp_flow_ctx *ctx,
					u32 meta_tag, u16 vid)
{
	struct mlx5_flow_destination dest = {};
	struct mlx5_flow_act flow_act = {};
	struct mlx5_flow_spec *spec = NULL;
	void *misc2_c, *misc2_v;
	int err = 0;

	/* Device must support pushing a single VLAN tag in the FDB. */
	if (!MLX5_CAP_ESW_FLOWTABLE_FDB(mdev, push_vlan)) {
		pr_err("axdp: FDB VLAN_PUSH unsupported\n");
		return -EOPNOTSUPP;
	}

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec)
		return -ENOMEM;

	/* match sui 32 bit di metadata_reg_a (il tag caricato dalla WQE). */
	spec->match_criteria_enable = MLX5_MATCH_MISC_PARAMETERS_2;

	misc2_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
			       misc_parameters_2);
	misc2_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
			       misc_parameters_2);
	MLX5_SET(fte_match_set_misc2, misc2_c, metadata_reg_a, 0xffffffff);
	MLX5_SET(fte_match_set_misc2, misc2_v, metadata_reg_a, meta_tag);

	/*
	 * An FDB rule is programmed on both the RX (from-wire) and TX (to-wire)
	 * steering pipes. VLAN_PUSH on the RX pipe is unsupported on this HW
	 * (that is why the eswitch routes such rules through a termination
	 * table), so DR rejects the rule with -EINVAL. Our packets are host
	 * egress, i.e. they originate from the local vport -- mark the flow
	 * source accordingly so DR skips the RX pipe and only programs TX, where
	 * VLAN_PUSH is valid. See dr_rule_skip() / dr_rule_create_rule_fdb().
	 */
	spec->flow_context.flow_source = MLX5_FLOW_CONTEXT_FLOW_SOURCE_LOCAL_VPORT;

	/*
	 * Azione: VLAN_PUSH (insert del tag) + FWD_DEST verso l'uplink vport,
	 * cosi' il pacchetto esce sul filo con il tag 802.1Q. VLAN_PUSH non e'
	 * un verdetto terminante, quindi va accoppiato a una destinazione.
	 */
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_VLAN_PUSH |
			  MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	flow_act.vlan[0].ethtype = ETH_P_8021Q;
	flow_act.vlan[0].vid     = vid & VLAN_VID_MASK;
	flow_act.vlan[0].prio    = 0;

	dest.type      = MLX5_FLOW_DESTINATION_TYPE_VPORT;
	dest.vport.num = MLX5_VPORT_UPLINK;

	ctx->mdev = mdev;

	ctx->rules[ctx->n_rules] = mlx5_add_flow_rules(ctx->ft, spec, &flow_act,
						       &dest, 1);
	if (IS_ERR(ctx->rules[ctx->n_rules])) {
		err = PTR_ERR(ctx->rules[ctx->n_rules]);
		pr_err("axdp: add_flow_rules (fdb vlan push) err=%d\n", err);
		ctx->rules[ctx->n_rules] = NULL;
		goto out_spec;
	}
	ctx->n_rules++;

	pr_info("axdp: regola FDB installata: reg_a=0x%x -> VLAN_PUSH vid=%u -> UPLINK\n",
		meta_tag, vid);

out_spec:
	kvfree(spec);
	return err;
}

int add_tx_vlan_rule(struct mlx5_core_dev *mdev, struct axdp_flow_ctx *ctx,
		       u32 meta_tag, u16 vid)
{
	/*
	 * The NIC TX (EGRESS) namespace does not support the VLAN_PUSH steering
	 * action -- that is FDB/eswitch-only, so it returns -EINVAL here. Instead
	 * we push the C-VLAN tag with a PACKET_REFORMAT/INSERT_HDR action: insert
	 * a 4-byte 802.1Q header right after the MAC addresses (offset 12), which
	 * NIC TX *does* support when the device advertises reformat_insert. This
	 * mirrors the eswitch bridge VLAN-push path (esw/bridge.c).
	 */
	struct {
		__be16 h_vlan_proto;
		__be16 h_vlan_TCI;
	} vlan_hdr = { htons(ETH_P_8021Q), htons(vid & VLAN_VID_MASK) };
	struct mlx5_pkt_reformat_params reformat_params = {};
	struct mlx5_pkt_reformat *pkt_reformat;
	struct mlx5_flow_act flow_act = {};
	struct mlx5_flow_spec *spec = NULL;
	void *misc2_c, *misc2_v;
	int err = 0;

	/*
	 * In switchdev mode add_tx_table() built the table in the FDB, where
	 * the native VLAN_PUSH action is available -- use it instead of the
	 * EGRESS reformat workaround below.
	 */
	if (mlx5_eswitch_mode(mdev) == MLX5_ESWITCH_OFFLOADS)
		return add_tx_vlan_rule_switchdev(mdev, ctx, meta_tag, vid);

	/* Device must support inserting a VLAN-sized header at the MAC offset. */
	if (!MLX5_CAP_FLOWTABLE_NIC_TX(mdev, reformat_insert) ||
	    MLX5_CAP_GEN_2(mdev, max_reformat_insert_size) < sizeof(vlan_hdr) ||
	    MLX5_CAP_GEN_2(mdev, max_reformat_insert_offset) <
	    offsetof(struct vlan_ethhdr, h_vlan_proto)) {
		pr_err("axdp: NIC TX reformat INSERT_HDR (vlan push) unsupported\n");
		return -EOPNOTSUPP;
	}

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec)
		return -ENOMEM;

	/*
	 * Stessa logica di add_tx_rule(): match sui 32 bit di metadata_reg_a
	 * (il tag caricato dalla WQE) sulla tabella EGRESS gia' creata.
	 */
	spec->match_criteria_enable = MLX5_MATCH_MISC_PARAMETERS_2;

	misc2_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
			       misc_parameters_2);
	misc2_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
			       misc_parameters_2);
	MLX5_SET(fte_match_set_misc2, misc2_c, metadata_reg_a, 0xffffffff);
	MLX5_SET(fte_match_set_misc2, misc2_v, metadata_reg_a, meta_tag);

	/*
	 * Build the reformat: insert {0x8100, TCI} starting at the MAC header,
	 * at the byte offset of the ethertype (12) -- i.e. between SMAC and the
	 * original ethertype, which is exactly an 802.1Q tag.
	 */
	reformat_params.type    = MLX5_REFORMAT_TYPE_INSERT_HDR;
	reformat_params.param_0 = MLX5_REFORMAT_CONTEXT_ANCHOR_MAC_START;
	reformat_params.param_1 = offsetof(struct vlan_ethhdr, h_vlan_proto);
	reformat_params.size    = sizeof(vlan_hdr);
	reformat_params.data    = &vlan_hdr;

	pkt_reformat = mlx5_packet_reformat_alloc(mdev, &reformat_params,
						  MLX5_FLOW_NAMESPACE_EGRESS);
	if (IS_ERR(pkt_reformat)) {
		err = PTR_ERR(pkt_reformat);
		pr_err("axdp: packet_reformat_alloc (vlan push) err=%d\n", err);
		goto out_spec;
	}

	/*
	 * Azione: reformat (insert del tag) + ALLOW, cosi' il pacchetto prosegue
	 * verso il filo dopo l'inserimento. REFORMAT non e' un verdetto
	 * terminante, quindi va accoppiato ad ALLOW.
	 */
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_PACKET_REFORMAT |
			  MLX5_FLOW_CONTEXT_ACTION_ALLOW;
	flow_act.pkt_reformat = pkt_reformat;

	/* del_rule() needs mdev to free the reformat context. */
	ctx->mdev = mdev;

	ctx->rules[ctx->n_rules] = mlx5_add_flow_rules(ctx->ft, spec, &flow_act,
						       NULL, 0);
	if (IS_ERR(ctx->rules[ctx->n_rules])) {
		err = PTR_ERR(ctx->rules[ctx->n_rules]);
		pr_err("axdp: add_flow_rules (vlan push) err=%d\n", err);
		ctx->rules[ctx->n_rules] = NULL;
		mlx5_packet_reformat_dealloc(mdev, pkt_reformat);
		goto out_spec;
	}
	ctx->pkt_reformat[ctx->n_rules] = pkt_reformat;
	ctx->n_rules++;

	pr_info("axdp: regola EGRESS installata: reg_a=0x%x -> VLAN_PUSH vid=%u\n",
		meta_tag, vid);

	kvfree(spec);
	return 0;

out_spec:
	kvfree(spec);
	return err;
}

int add_rx_table(struct mlx5_core_dev *mdev, struct axdp_flow_ctx *ctx)
{
	struct mlx5_flow_table_attr ft_attr = {};
	bool switchdev;
	int err = 0;

	/*
	 * In switchdev (eswitch OFFLOADS) mode RX traffic from the wire is
	 * steered by the FDB (it enters at the uplink vport), so the RX rules
	 * must live there too -- add_rx_rule() then delivers matched packets to
	 * the host PF vport instead of to a NIC-RX TIR. In legacy mode we keep
	 * the NIC RX BYPASS namespace and forward to a TIR as before.
	 */
	switchdev = mlx5_eswitch_mode(mdev) == MLX5_ESWITCH_OFFLOADS;

	/*
	 * Use FDB_BYPASS, not the FDB root: the root's prio-0 major slot holds a
	 * sub-namespace (not tables), so a table created there is not in the
	 * traversed chain. FDB_BYPASS is the highest-priority FDB path, evaluated
	 * before the TC/slow-path forwarding the eswitch installs -- our rules
	 * must sit there to actually catch traffic.
	 */
	ctx->ns = mlx5_get_flow_namespace(mdev,
					  switchdev ? MLX5_FLOW_NAMESPACE_FDB_BYPASS
						    : MLX5_FLOW_NAMESPACE_BYPASS);
	if (!ctx->ns) {
		pr_err("axdp: namespace %s non disponibile\n",
		       switchdev ? "FDB_BYPASS" : "BYPASS");
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
	/*
	 * In switchdev both the RX and TX tables share the FDB_BYPASS namespace,
	 * whose prios hold a single level each. The TX table (add_tx_table)
	 * uses prio 0, so the RX table must use a different prio or its creation
	 * collides with the TX table. In legacy mode the two live in separate
	 * namespaces, so prio 0 is fine.
	 */
	ft_attr.prio    = switchdev ? 1 : 0;
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

enum arfs_type {
	ARFS_IPV4_TCP,
	ARFS_IPV6_TCP,
	ARFS_IPV4_UDP,
	ARFS_IPV6_UDP,
	ARFS_NUM_TYPES,
};

/*
 * Build a termination table whose single rule forwards everything to the
 * uplink vport (the wire). A direct FWD_DEST from an uplink-sourced FTE back to
 * the uplink is dropped by the eswitch loopback prevention; routing it through a
 * termination table is how mlx5's own TC hairpin offload works (see
 * mlx5_eswitch_add_termtbl_rule()). The caller then points its FTE at the
 * returned table (DESTINATION_TYPE_FLOW_TABLE) with FLOW_ACT_IGNORE_FLOW_LEVEL.
 *
 * On success returns the table and stores the inner rule in *term_rule; both
 * must be torn down by the caller (rule first, then table).
 */
static struct mlx5_flow_table *
axdp_create_hairpin_termtbl(struct mlx5_core_dev *mdev,
			    struct mlx5_flow_handle **term_rule)
{
	struct mlx5_flow_table_attr ft_attr = {};
	struct mlx5_flow_destination dest = {};
	struct mlx5_flow_act act = {};
	struct mlx5_flow_namespace *ns;
	struct mlx5_flow_table *tt;
	struct mlx5_flow_handle *r;
	int err;

	ns = mlx5_get_flow_namespace(mdev, MLX5_FLOW_NAMESPACE_FDB);
	if (!ns)
		return ERR_PTR(-EOPNOTSUPP);

	/* Terminating, unmanaged table -- same shape the eswitch uses. */
	ft_attr.flags   = MLX5_FLOW_TABLE_TERMINATION |
			  MLX5_FLOW_TABLE_UNMANAGED;
	ft_attr.prio    = FDB_TC_OFFLOAD;
	ft_attr.level   = 1;
	ft_attr.max_fte = 1;
	ft_attr.autogroup.max_num_groups = 1;

	tt = mlx5_create_auto_grouped_flow_table(ns, &ft_attr);
	if (IS_ERR(tt)) {
		pr_err("axdp: hairpin termtbl create err=%pe\n", tt);
		return tt;
	}

	/* Match-all rule inside the termtbl: forward to the wire. */
	act.action     = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	dest.type      = MLX5_FLOW_DESTINATION_TYPE_VPORT;
	dest.vport.num = MLX5_VPORT_UPLINK;

	r = mlx5_add_flow_rules(tt, NULL, &act, &dest, 1);
	if (IS_ERR(r)) {
		err = PTR_ERR(r);
		pr_err("axdp: hairpin termtbl rule err=%d\n", err);
		mlx5_destroy_flow_table(tt);
		return ERR_PTR(err);
	}

	*term_rule = r;
	return tt;
}

int add_rx_rule(struct mlx5_core_dev *mdev, struct axdp_flow_ctx *ctx,
		__be32 sip, __be32 dip, u8 ip_proto, __be16 sport, __be16 dport,
		u8 action, u32 mark, u8 match_flags) {
	struct mlx5_flow_act flow_act = {};
	struct mlx5_flow_spec *spec = NULL;
	void *outer_c, *outer_v;
	bool switchdev;
	int err = 0;

	/*
	 * add_rx_table() put ctx->ft in the FDB when the eswitch is in OFFLOADS
	 * (switchdev) mode, or in the NIC RX BYPASS namespace otherwise. The
	 * destination and modify-header domain differ between the two, so branch
	 * on the mode below.
	 */
	switchdev = mlx5_eswitch_mode(mdev) == MLX5_ESWITCH_OFFLOADS;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec) {
		err = -ENOMEM;
		goto out_ft;
	}

	/*
	 * Con l'auto-grouped table NON costruiamo il flow group: impostiamo
	 * solo spec->match_criteria_enable e i campi nello spec. Il kernel
	 * deriva il gruppo dalla maschera in match_criteria.
	 *
	 * La quintupla (src IP, dst IP, protocollo L4, src port, dst port) sta
	 * tutta in outer_headers (fte_match_set_lyr_2_4), quindi basta abilitare
	 * MLX5_MATCH_OUTER_HEADERS. Ogni campo passato a 0 viene trattato come
	 * wildcard: non si imposta la sua maschera e non entra nel match.
	 */
	spec->match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;

	/* ---- outer_headers: ethertype + ip_version (sempre, solo IPv4) ---- */
	outer_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
			       outer_headers);
	outer_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
			       outer_headers);

	MLX5_SET(fte_match_set_lyr_2_4, outer_c, ethertype, 0xffff);
	MLX5_SET(fte_match_set_lyr_2_4, outer_v, ethertype, ETH_P_IP);
	MLX5_SET(fte_match_set_lyr_2_4, outer_c, ip_version, 0xf);
	MLX5_SET(fte_match_set_lyr_2_4, outer_v, ip_version, 4);

	/* ---- src IPv4 (0 = wildcard) ---- */
	if (sip) {
		memset(MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_c,
				    src_ipv4_src_ipv6.ipv4_layout.ipv4),
		       0xff, 4);
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_v,
				    src_ipv4_src_ipv6.ipv4_layout.ipv4),
		       &sip, 4);
	}

	/* ---- dst IPv4 (0 = wildcard) ---- */
	if (dip) {
		memset(MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_c,
				    dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
		       0xff, 4);
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_v,
				    dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
		       &dip, 4);
	}

	/* ---- protocollo L4 + porte TCP/UDP (0 = wildcard) ---- */
	if (ip_proto) {
		MLX5_SET(fte_match_set_lyr_2_4, outer_c, ip_protocol, 0xff);
		MLX5_SET(fte_match_set_lyr_2_4, outer_v, ip_protocol, ip_proto);

		if (ip_proto == IPPROTO_TCP) {
			if (sport) {
				MLX5_SET(fte_match_set_lyr_2_4, outer_c, tcp_sport, 0xffff);
				MLX5_SET(fte_match_set_lyr_2_4, outer_v, tcp_sport,
					 be16_to_cpu(sport));
			}
			if (dport) {
				MLX5_SET(fte_match_set_lyr_2_4, outer_c, tcp_dport, 0xffff);
				MLX5_SET(fte_match_set_lyr_2_4, outer_v, tcp_dport,
					 be16_to_cpu(dport));
			}

			/*
			 * Opt-in (AXDP_RX_MATCH_NO_RST_FIN): match only segments
			 * with neither FIN nor RST set, so the rule covers
			 * live-connection traffic and ignores teardown and reset
			 * packets. tcp_flags bit layout (see dr_ste.h): FIN = bit0
			 * (0x01), RST = bit2 (0x04); mask both, require 0.
			 */
			if (match_flags & AXDP_RX_MATCH_NO_RST_FIN) {
				MLX5_SET(fte_match_set_lyr_2_4, outer_c, tcp_flags, 0x05);
				MLX5_SET(fte_match_set_lyr_2_4, outer_v, tcp_flags, 0x00);
			}
		} else if (ip_proto == IPPROTO_UDP) {
			if (sport) {
				MLX5_SET(fte_match_set_lyr_2_4, outer_c, udp_sport, 0xffff);
				MLX5_SET(fte_match_set_lyr_2_4, outer_v, udp_sport,
					 be16_to_cpu(sport));
			}
			if (dport) {
				MLX5_SET(fte_match_set_lyr_2_4, outer_c, udp_dport, 0xffff);
				MLX5_SET(fte_match_set_lyr_2_4, outer_v, udp_dport,
					 be16_to_cpu(dport));
			}
		}
	}

	/* ---- azione: PASS (ALLOW), MOD_HDR, FWD (hairpin to wire), DROP ---- */
	pr_info("axdp: action %d\n",action);

	/*
	 * AXDP_RX_FWD is a hairpin: match from-wire traffic and send it straight
	 * back out the wire (TX) without ever reaching the host. That requires
	 * forwarding to the uplink vport, which only exists in the FDB/eswitch
	 * (switchdev) pipe -- the NIC RX BYPASS namespace can only reach TIRs
	 * (host). Reject the action up front when not in switchdev mode.
	 */
	if (action == AXDP_RX_FWD && !switchdev) {
		pr_err("axdp: RX_FWD (hairpin to wire) requires switchdev mode\n");
		err = -EOPNOTSUPP;
		goto out_spec;
	}

	/*
	 * MOD_HDR only rewrites metadata; it is not a verdict. MARK/MOD_HDR must
	 * therefore also forward the packet to a destination, otherwise the rule
	 * has no terminating action and mlx5 rejects it with -EINVAL. Mark and
	 * deliver up the normal RX path (same TIR as PASS). FWD just forwards to
	 * the uplink vport (no header rewrite).
	 */
	flow_act.action = (action == AXDP_RX_PASS ||
			   action == AXDP_RX_FWD)     ? MLX5_FLOW_CONTEXT_ACTION_FWD_DEST  :
					  (action == AXDP_RX_MOD_HDR ||
					   action == AXDP_RX_MARK)    ? (MLX5_FLOW_CONTEXT_ACTION_MOD_HDR |
									 MLX5_FLOW_CONTEXT_ACTION_FWD_DEST) :
					  MLX5_FLOW_CONTEXT_ACTION_DROP;
	//sal
	struct mlx5_flow_destination *dst = NULL;

	/*
	 * An FDB table programs a rule on both the RX (from-wire, source ==
	 * uplink) and TX (to-wire, source == local vport) steering pipes.
	 *
	 * Forwarding to the PF vport (PASS/MARK below) only makes sense for
	 * wire->host traffic, so for those actions we flag the flow source as
	 * UPLINK and DR programs the RX pipe only (see dr_rule_skip()). A DROP
	 * has no such constraint: leave the flow source unset so it lands on
	 * both pipes and drops the matched 5-tuple regardless of direction.
	 */
	if (switchdev && action != AXDP_RX_DROP)
		spec->flow_context.flow_source =
			MLX5_FLOW_CONTEXT_FLOW_SOURCE_UPLINK;

	if (action == AXDP_RX_FWD) {
		/*
		 * Hairpin: forward the matched from-wire packet back out the
		 * uplink (wire/TX), bypassing the host entirely. switchdev was
		 * asserted above, so the FDB pipe and uplink vport are valid.
		 *
		 * A direct FWD_DEST to the uplink would be dropped by the
		 * eswitch loopback prevention (packet ingressed on the uplink),
		 * so route it through a termination table and point the FTE at
		 * that table with IGNORE_FLOW_LEVEL -- the same trick the
		 * eswitch's own TC hairpin offload uses.
		 */
		ctx->term_ft[ctx->n_rules] =
			axdp_create_hairpin_termtbl(mdev,
						    &ctx->term_rule[ctx->n_rules]);
		if (IS_ERR(ctx->term_ft[ctx->n_rules])) {
			err = PTR_ERR(ctx->term_ft[ctx->n_rules]);
			ctx->term_ft[ctx->n_rules] = NULL;
			goto out_spec;
		}

		dst = kzalloc(sizeof(*dst), GFP_KERNEL);
		if (!dst) {
			err = -ENOMEM;
			goto out_spec;
		}
		dst->type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
		dst->ft   = ctx->term_ft[ctx->n_rules];
		flow_act.flags |= FLOW_ACT_IGNORE_FLOW_LEVEL;
	} else if (action == AXDP_RX_PASS || action == AXDP_RX_MARK ||
	    action == AXDP_RX_MOD_HDR) {
		dst = kzalloc(sizeof(*dst), GFP_KERNEL);
		if (!dst) {
			err = -ENOMEM;
			goto out_spec;
		}

		if (switchdev) {
			/*
			 * FDB has no TIR destinations; deliver matched packets to
			 * the host by forwarding to the PF vport, which then runs
			 * the PF's own NIC RX steering (RSS/TIR).
			 */
			dst->type      = MLX5_FLOW_DESTINATION_TYPE_VPORT;
			dst->vport.num = MLX5_VPORT_PF;
		} else {
			struct net_device *netdev = mlx5_uplink_netdev_get(mdev);
			struct mlx5e_priv *priv;

			if (!netdev) {
				err = -ENODEV;
				goto out_spec;
			}
			priv = netdev_priv(netdev);

			dst->tir_num = mlx5e_rx_res_get_tirn_direct(priv->rx_res, 0);
			//enum mlx5_traffic_types tt;
			//tt = arfs_get_tt(ARFS_IPV4_TCP);
		    //dst->tir_num = mlx5e_rx_res_get_tirn_rss(rx_res, tt);
			dst->type = MLX5_FLOW_DESTINATION_TYPE_TIR; //MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE
		}
	}

	if (action == AXDP_RX_MOD_HDR || action == AXDP_RX_MARK) {
		u8 flow_action[MLX5_UN_SZ_BYTES(set_add_copy_action_in_auto)] = {};
		/* MARK carries a user-supplied value; MOD_HDR keeps the legacy tag. */
		u32 mark_val = (action == AXDP_RX_MARK) ? mark : 0xbebabeba;
		/*
		 * Legacy NIC RX writes reg_B (surfaces in the CQE flow_table
		 * metadata the driver reads). The FDB has no reg_B; reg_C_0/1 are
		 * reserved for vport/source-port metadata in switchdev, so use
		 * reg_C_2 there and alloc the context in the FDB namespace.
		 */
		u8 field = switchdev ? MLX5_ACTION_IN_FIELD_METADATA_REG_C_2
				     : MLX5_ACTION_IN_FIELD_METADATA_REG_B;
		enum mlx5_flow_namespace_type mh_ns =
			switchdev ? MLX5_FLOW_NAMESPACE_FDB
				  : MLX5_FLOW_NAMESPACE_KERNEL;
		/* Build one SET instruction: reg = mark (32 bits) */
		MLX5_SET(set_action_in, flow_action, action_type, MLX5_ACTION_TYPE_SET);
		MLX5_SET(set_action_in, flow_action, field,       field);
		MLX5_SET(set_action_in, flow_action, offset,      0);
		MLX5_SET(set_action_in, flow_action, length,      32);   /* 0 also means full field */
		MLX5_SET(set_action_in, flow_action, data,        mark_val);
		/* Allocate the modify-header context (a firmware command). */
		struct mlx5_modify_hdr *mh = mlx5_modify_header_alloc(mdev,
					mh_ns,
					1,                            /* num_actions  */
					flow_action);
		if (IS_ERR(mh)) {
			err = PTR_ERR(mh);
			pr_err("axdp: modify_header_alloc err=%d\n", err);
			goto out_spec;
		}
		flow_act.modify_hdr = mh;
		/* Remember it so del_rule() can free it (stored below). */
		ctx->mod_hdr[ctx->n_rules] = mh;
	}

	/* del_rule()/del_table_rule() need mdev to free modify-header contexts. */
	ctx->mdev = mdev;

	ctx->rules[ctx->n_rules] = mlx5_add_flow_rules(ctx->ft, spec, &flow_act, dst, dst ? 1 : 0);
	if (IS_ERR(ctx->rules[ctx->n_rules])) {
		err = PTR_ERR(ctx->rules[ctx->n_rules]);
		pr_err("axdp: add_flow_rules err=%d\n", err);
		ctx->rules[ctx->n_rules] = NULL;
		/* n_rules not bumped yet: free the modify-header here. */
		if (ctx->mod_hdr[ctx->n_rules]) {
			mlx5_modify_header_dealloc(mdev, ctx->mod_hdr[ctx->n_rules]);
			ctx->mod_hdr[ctx->n_rules] = NULL;
		}
		goto out_spec;
	}
    ctx->n_rules++;
	pr_info("axdp: regola RX installata: src=%pI4 dst=%pI4 proto=%u sport=%u dport=%u -> %s (mark=0x%08x)\n",
		&sip, &dip, ip_proto, be16_to_cpu(sport), be16_to_cpu(dport),
		(action == AXDP_RX_PASS) ? "PASS" :
		(action == AXDP_RX_MARK) ? "MARK" :
		(action == AXDP_RX_MOD_HDR) ? "MOD_HDR" :
		(action == AXDP_RX_FWD) ? "FWD(hairpin->wire)" : "DROP",
		(action == AXDP_RX_MARK) ? mark : 0);

	if (dst)
		kfree(dst);
	kvfree(spec);
	return 0;

out_spec:
	/*
	 * n_rules has not been bumped on any error path, so a hairpin termtbl
	 * created above for this (failed) rule is still parked at [n_rules].
	 * Tear it down (rule first, then table) before returning.
	 */
	if (ctx->term_ft[ctx->n_rules]) {
		if (ctx->term_rule[ctx->n_rules]) {
			mlx5_del_flow_rules(ctx->term_rule[ctx->n_rules]);
			ctx->term_rule[ctx->n_rules] = NULL;
		}
		mlx5_destroy_flow_table(ctx->term_ft[ctx->n_rules]);
		ctx->term_ft[ctx->n_rules] = NULL;
	}
	if (dst)
		kfree(dst);
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
	if (ctx->mod_hdr[index]) {
		mlx5_modify_header_dealloc(ctx->mdev, ctx->mod_hdr[index]);
		ctx->mod_hdr[index] = NULL;
	}
	if (ctx->pkt_reformat[index]) {
		mlx5_packet_reformat_dealloc(ctx->mdev, ctx->pkt_reformat[index]);
		ctx->pkt_reformat[index] = NULL;
	}
	/* AXDP_RX_FWD hairpin termtbl: tear down rule first, then the table. */
	if (ctx->term_rule[index]) {
		mlx5_del_flow_rules(ctx->term_rule[index]);
		ctx->term_rule[index] = NULL;
	}
	if (ctx->term_ft[index]) {
		mlx5_destroy_flow_table(ctx->term_ft[index]);
		ctx->term_ft[index] = NULL;
	}
	if (ctx->n_rules)
		ctx->n_rules--;
}

void del_table_rule(struct axdp_flow_ctx *ctx)
{
	int i;
	for (i = 0; i < ctx->n_rules; i++) {
		/* Drop the main FTE first; it references the termtbl below. */
		if (ctx->rules[i])
			mlx5_del_flow_rules(ctx->rules[i]);
		if (ctx->mod_hdr[i]) {
			mlx5_modify_header_dealloc(ctx->mdev, ctx->mod_hdr[i]);
			ctx->mod_hdr[i] = NULL;
		}
		if (ctx->pkt_reformat[i]) {
			mlx5_packet_reformat_dealloc(ctx->mdev, ctx->pkt_reformat[i]);
			ctx->pkt_reformat[i] = NULL;
		}
		/* AXDP_RX_FWD hairpin termtbl: rule first, then table. */
		if (ctx->term_rule[i]) {
			mlx5_del_flow_rules(ctx->term_rule[i]);
			ctx->term_rule[i] = NULL;
		}
		if (ctx->term_ft[i]) {
			mlx5_destroy_flow_table(ctx->term_ft[i]);
			ctx->term_ft[i] = NULL;
		}
	}
	ctx->n_rules = 0;
	if (ctx->ft)
		mlx5_destroy_flow_table(ctx->ft);
	/* niente flow group da distruggere: gestito dall'auto-grouped table */
	memset(ctx, 0, sizeof(*ctx));
}