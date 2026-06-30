/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * axdp_ringbuf.h -- shared ABI between the BPF producer (axdp_ringbuf.bpf.c)
 * and the userspace daemon (axdp_rule_daemon.c).
 *
 * The BPF side pushes one record per flow-rule operation into a BPF_MAP_TYPE_
 * RINGBUF; the daemon drains the ring buffer and replays each operation onto
 * /dev/mlx5_axdp via the AXDP_IOC_* ioctls (see en_ioctl.h).
 *
 * The op codes match the in-driver convention already used in en_rx.c and
 * tx_metadata_flow.bpf.c (header[0] = 1..4) and the AXDP_IOC_* numbering.
 */
#ifndef __AXDP_RINGBUF_H__
#define __AXDP_RINGBUF_H__

#include <linux/types.h>

/*
 * Action for an ADD_RX record. Mirrors the AXDP_RX_* values in en_ioctl.h;
 * guarded so both headers can be included together (e.g. by the daemon).
 */
#ifndef AXDP_RX_DROP
#define AXDP_RX_DROP	0	/* DROP the matching packets (default)        */
#define AXDP_RX_PASS	1	/* ALLOW: let the matching packets continue   */
#define AXDP_RX_MOD_HDR 2	/* Modify headers                             */
#define AXDP_RX_MARK	3	/* MARK: set metadata REG_B to @mark (32 bit) */
#define AXDP_RX_FWD	4	/* HAIRPIN: forward back out the wire (TX)    */
#endif

/* ADD_RX match qualifiers; mirrors AXDP_RX_MATCH_* in en_ioctl.h. */
#ifndef AXDP_RX_MATCH_NO_RST_FIN
#define AXDP_RX_MATCH_NO_RST_FIN 0x01	/* TCP only: match only segments with
					 * neither FIN nor RST set */
#endif

/* Operation encoded in each ring-buffer record. */
enum axdp_op {
	AXDP_OP_ADD_TX = 1,	/* @value = WQE metadata tag (reg_a), network order */
	AXDP_OP_ADD_RX = 2,	/* IPv4 5-tuple in @src_ip..@ip_proto (or legacy @value) */
	AXDP_OP_DEL_TX = 3,	/* @value = TX rule index to remove                 */
	AXDP_OP_DEL_RX = 4,	/* @value = RX rule index to remove                 */
	AXDP_OP_ADD_VLAN = 5,	/* @value = WQE metadata tag (reg_a); push @vid     */
	AXDP_OP_SET_PRIO_RATE = 6, /* @value = sq_prio rate in kbps (host order; 0=off) */
};

/*
 * One ring-buffer record. The fields mirror struct axdp_ioctl_rule so the
 * daemon can forward them 1:1:
 *   - @value is passed verbatim to axdp_ioctl_rule.value (TX tag, DEL index,
 *     or legacy RX dst IPv4). The producer must store it in the byte order the
 *     kernel expects: network order for the TX tag and the RX IPv4, host order
 *     for the DEL index.
 *   - For AXDP_OP_ADD_RX the rule matches the IPv4 5-tuple in @src_ip, @dst_ip,
 *     @src_port, @dst_port, @ip_proto (all network byte order; 0 = wildcard).
 *     A producer that fills only @value and leaves the 5-tuple zeroed keeps the
 *     old behaviour (@value taken as the dst IPv4 to DROP).
 *   - For AXDP_OP_ADD_RX with @action == AXDP_RX_MARK, @mark is the 32-bit value
 *     written to REG_B.
 *   - For AXDP_OP_ADD_VLAN, @value selects the WQE metadata tag (reg_a) to match
 *     (like ADD_TX) and @vid is the 12-bit C-VLAN id (0-4095) to push.
 */
struct axdp_rb_event {
	__u32 op;	/* enum axdp_op */
	__u32 value;	/* operand, per-op meaning above */

	/* ADD_RX 5-tuple (network byte order; 0 = wildcard). */
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8  ip_proto;
	__u8  action;	/* AXDP_RX_DROP (default) / AXDP_RX_PASS / AXDP_RX_MARK */
	__u8  match_flags; /* ADD_RX: OR of AXDP_RX_MATCH_* (0 = plain 5-tuple) */
	__u8  _pad[1];

	__u32 mark;	/* ADD_RX, action AXDP_RX_MARK: 32-bit REG_B value */
	__u16 vid;	/* ADD_VLAN: 12-bit C-VLAN id to push              */
	__u8  _pad2[2];
};

#endif /* __AXDP_RINGBUF_H__ */
