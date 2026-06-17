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
#include <linux/if_vlan.h>
#include <linux/in.h>
#include "en_flowtable.h"
#include "en_ioctl.h"	/* AXDP_RX_DROP / AXDP_RX_PASS */
#include "en.h"		/* struct mlx5e_priv, priv->rx_res */
#include "en/rx_res.h"	/* mlx5e_rx_res_get_tirn_direct() */
#include "lib/mlx5.h"	/* mlx5_uplink_netdev_get() */

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
	/*
	 * reformat_en: required so FTEs in this table may carry a
	 * PACKET_REFORMAT action (used by add_meta_vlan_rule() to INSERT_HDR a
	 * VLAN tag). Without it the firmware rejects the reformat action.
	 */
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


int add_meta_vlan_rule(struct mlx5_core_dev *mdev, struct axdp_flow_ctx *ctx,
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
	 * Stessa logica di add_meta_rule(): match sui 32 bit di metadata_reg_a
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

enum arfs_type {
	ARFS_IPV4_TCP,
	ARFS_IPV6_TCP,
	ARFS_IPV4_UDP,
	ARFS_IPV6_UDP,
	ARFS_NUM_TYPES,
};

static enum mlx5_traffic_types arfs_get_tt(enum arfs_type type)
{
	switch (type) {
	case ARFS_IPV4_TCP:
		return MLX5_TT_IPV4_TCP;
	case ARFS_IPV4_UDP:
		return MLX5_TT_IPV4_UDP;
	case ARFS_IPV6_TCP:
		return MLX5_TT_IPV6_TCP;
	case ARFS_IPV6_UDP:
		return MLX5_TT_IPV6_UDP;
	default:
		return -EINVAL;
	}
}

int add_rx_rule(struct mlx5_core_dev *mdev, struct axdp_flow_ctx *ctx,
		__be32 sip, __be32 dip, u8 ip_proto, __be16 sport, __be16 dport,
		u8 action, u32 mark) {
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

	/* ---- azione: PASS (ALLOW), MOD_HDR, DROP ---- */
	pr_info("axdp: action %d\n",action);
	
	/*
	 * MOD_HDR only rewrites metadata; it is not a verdict. MARK/MOD_HDR must
	 * therefore also forward the packet to a destination, otherwise the rule
	 * has no terminating action and mlx5 rejects it with -EINVAL. Mark and
	 * deliver up the normal RX path (same TIR as PASS).
	 */
	flow_act.action = (action == AXDP_RX_PASS)    ? MLX5_FLOW_CONTEXT_ACTION_FWD_DEST  :
					  (action == AXDP_RX_MOD_HDR ||
					   action == AXDP_RX_MARK)    ? (MLX5_FLOW_CONTEXT_ACTION_MOD_HDR |
									 MLX5_FLOW_CONTEXT_ACTION_FWD_DEST) :
					  MLX5_FLOW_CONTEXT_ACTION_DROP;
	//sal
	struct mlx5_flow_destination *dst = NULL;

	if (action == AXDP_RX_PASS || action == AXDP_RX_MARK ||
	    action == AXDP_RX_MOD_HDR) {
		struct net_device *netdev = mlx5_uplink_netdev_get(mdev);
		struct mlx5e_priv *priv;

		if (!netdev) {
			err = -ENODEV;
			goto out_spec;
		}
		priv = netdev_priv(netdev);

		dst = kzalloc(sizeof(*dst), GFP_KERNEL);
		if (!dst) {
			err = -ENOMEM;
			goto out_spec;
		}
		dst->tir_num = mlx5e_rx_res_get_tirn_direct(priv->rx_res, 0);
		//enum mlx5_traffic_types tt;
		//tt = arfs_get_tt(ARFS_IPV4_TCP);
	    //dst->tir_num = mlx5e_rx_res_get_tirn_rss(rx_res, tt);
		dst->type = MLX5_FLOW_DESTINATION_TYPE_TIR; //MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE
	}
		
	if (action == AXDP_RX_MOD_HDR || action == AXDP_RX_MARK) {
		u8 flow_action[MLX5_UN_SZ_BYTES(set_add_copy_action_in_auto)] = {};
		/* MARK carries a user-supplied value; MOD_HDR keeps the legacy tag. */
		u32 reg_b = (action == AXDP_RX_MARK) ? mark : 0xbebabeba;
		/* Build one SET instruction: reg_B = mark (32 bits) */
		MLX5_SET(set_action_in, flow_action, action_type, MLX5_ACTION_TYPE_SET);
		MLX5_SET(set_action_in, flow_action, field,       MLX5_ACTION_IN_FIELD_METADATA_REG_B);
		MLX5_SET(set_action_in, flow_action, offset,      0);
		MLX5_SET(set_action_in, flow_action, length,      32);   /* 0 also means full field */
		MLX5_SET(set_action_in, flow_action, data,        reg_b);
		/* Allocate the modify-header context (a firmware command). */
		struct mlx5_modify_hdr *mh = mlx5_modify_header_alloc(mdev,
					MLX5_FLOW_NAMESPACE_KERNEL,  /* RX namespace */
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
		(action == AXDP_RX_MOD_HDR) ? "MOD_HDR" : "DROP",
		(action == AXDP_RX_MARK) ? mark : 0);

	if (dst)
		kfree(dst);
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
	if (ctx->mod_hdr[index]) {
		mlx5_modify_header_dealloc(ctx->mdev, ctx->mod_hdr[index]);
		ctx->mod_hdr[index] = NULL;
	}
	if (ctx->pkt_reformat[index]) {
		mlx5_packet_reformat_dealloc(ctx->mdev, ctx->pkt_reformat[index]);
		ctx->pkt_reformat[index] = NULL;
	}
	if (ctx->n_rules)
		ctx->n_rules--;
}

void del_table_rule(struct axdp_flow_ctx *ctx)
{
	int i;
	for (i = 0; i < ctx->n_rules; i++) {
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
	}
	ctx->n_rules = 0;
	if (ctx->ft)
		mlx5_destroy_flow_table(ctx->ft);
	/* niente flow group da distruggere: gestito dall'auto-grouped table */
	memset(ctx, 0, sizeof(*ctx));
}