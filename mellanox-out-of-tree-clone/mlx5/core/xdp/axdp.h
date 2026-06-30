/* ------------------------------------------------------------------ */
/* (1) RX computation offloads — read NIC-computed CQE fields          */
/* ------------------------------------------------------------------ */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AXDP_PASS 0x1
#define METADATA_LEN 20
#define XDP_TX_2 5

struct flow_key {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	__u8   proto;
	__u8   pad[3];
};



static __always_inline int stamp_metadata(struct xdp_md *ctx, int value) {
        void  *data = (void *)(long)ctx->data;
        __u8  *data_meta  = (void *)(long)ctx->data_meta;
        __u32 *header = (void *)(long)ctx->data_meta;
        if ((void *)data_meta + 8 > data) {
            bpf_printk("no meta space\n");
            return -1;
        }
        header[0] = value;   // metadata value
        header[1] = 0; // inline_hdr_size=0
        return 0;
}
/* Returns 0 on success with *ts filled, -1 on error. */
static __always_inline __u64 meta_read_timestamp(struct xdp_md *ctx)
{
	__u8 *data_meta = (void *)(long)ctx->data_meta;
	void *data      = (void *)(long)ctx->data;
    __u64 ts=0;
	if ((void *)data_meta + METADATA_LEN > data) {
		bpf_printk("ts fallback: using bpf_ktime_get_ns\n");
		return bpf_ktime_get_ns();
	}
	__u32 *m = (__u32 *)data_meta;
	ts = ((__u64)m[1] << 32) | m[2];
	return ts;
}

/* Returns 0 on success with *hash filled, -1 on error. */
static __always_inline __u32 meta_read_hash(struct xdp_md *ctx)
{
	__u8 *data_meta = (void *)(long)ctx->data_meta;
	void *data      = (void *)(long)ctx->data;
	if ((void *)data_meta + METADATA_LEN > data) {
		/* No meta space — FNV-1a over IPv4 TCP/UDP 5-tuple, else 0 */
		__u8 *pkt      = data;
		void *data_end = (void *)(long)ctx->data_end;

		/* Eth(14) + IP hdr up to dst(20) + ports(4) = 38 bytes minimum;
		 * only hash TCP (6) and UDP (17) over IPv4 (ethertype 0x0800). */
		if ((void *)(pkt + 38) > data_end ||
		    pkt[12] != 0x08 || pkt[13] != 0x00 ||
		    (pkt[23] != 6 && pkt[23] != 17)) {
			bpf_printk("hash fallback: not IPv4 TCP/UDP, hash=0\n");
			return 0;
		}
		bpf_printk("hash fallback: computing 5-tuple FNV-1a\n");

		__u32 h = 2166136261u; /* FNV offset basis */
#define FNV(b) do { h ^= (b); h *= 16777619u; } while (0)
		FNV(pkt[26]); FNV(pkt[27]); FNV(pkt[28]); FNV(pkt[29]); /* src IP  */
		FNV(pkt[30]); FNV(pkt[31]); FNV(pkt[32]); FNV(pkt[33]); /* dst IP  */
		FNV(pkt[23]);                                             /* proto   */
		FNV(pkt[34]); FNV(pkt[35]);                              /* src port*/
		FNV(pkt[36]); FNV(pkt[37]);                              /* dst port*/
#undef FNV
		return h;
	}
	__u32 *m = (__u32 *)data_meta;
	return m[0];
}



	/* RX computation offload: skip software parse if NIC already
	 * classified the inner protocol.
	 * CQE_L4_HDR_TYPE_NONE			= 0x0,
	 * CQE_L4_HDR_TYPE_TCP_NO_ACK	= 0x1,
	 * CQE_L4_HDR_TYPE_UDP			= 0x2,
	 * CQE_L4_HDR_TYPE_TCP_ACK_NO_DATA	= 0x3,
	 * CQE_L4_HDR_TYPE_TCP_ACK_AND_DATA	= 0x4
    */

/* Software fallback for meta_read_l4type(): parse the packet to classify L4,
 * matching the CQE_L4_HDR_TYPE_* codes the NIC would have provided. */
static __always_inline __u32 l4type_fallback(struct xdp_md *ctx)
{
	__u8 *pkt      = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	/* Need Eth(14) + IPv4 hdr(20) to read the protocol byte (offset 23);
	 * only classify IPv4 (ethertype 0x0800). */
	if ((void *)(pkt + 34) > data_end ||
	    pkt[12] != 0x08 || pkt[13] != 0x00) {
		bpf_printk("l4 fallback: not IPv4, type=NONE\n");
		return 0; /* CQE_L4_HDR_TYPE_NONE */
	}

	if (pkt[23] == 17) {
		bpf_printk("l4 fallback: UDP\n");
		return 2; /* CQE_L4_HDR_TYPE_UDP */
	}

	if (pkt[23] == 6) {
		/* TCP: header starts at offset 34. Data offset (header len in
		 * 32-bit words) is the high nibble of byte 46; flags are in
		 * byte 47 (ACK = 0x10). */
		if ((void *)(pkt + 48) > data_end) {
			bpf_printk("l4 fallback: TCP (truncated), no ack\n");
			return 1; /* CQE_L4_HDR_TYPE_TCP_NO_ACK */
		}

		__u32 ihl     = (pkt[14] & 0x0f) * 4;       /* IPv4 header len   */
		__u32 tcp_off = 14 + ihl;                   /* start of TCP hdr  */
		__u32 thl     = (pkt[tcp_off + 12] >> 4) * 4; /* TCP header len  */
		__u8  flags   = pkt[tcp_off + 13];
		void *payload = (void *)(pkt + tcp_off + thl);

		if (!(flags & 0x10)) {
			bpf_printk("l4 fallback: TCP no ack\n");
			return 1; /* CQE_L4_HDR_TYPE_TCP_NO_ACK */
		}
		if (payload < data_end) {
			bpf_printk("l4 fallback: TCP ack and data\n");
			return 4; /* CQE_L4_HDR_TYPE_TCP_ACK_AND_DATA */
		}
		bpf_printk("l4 fallback: TCP ack no data\n");
		return 3; /* CQE_L4_HDR_TYPE_TCP_ACK_NO_DATA */
	}

	bpf_printk("l4 fallback: other proto, type=NONE\n");
	return 0; /* CQE_L4_HDR_TYPE_NONE */
}


/* Returns Flow Metadata */
static __always_inline __u32 meta_read_ft_metadata(struct xdp_md *ctx)
{
	__u8 *data_meta = (void *)(long)ctx->data_meta;
	void *data      = (void *)(long)ctx->data;
	if ((void *)data_meta + METADATA_LEN > data) {
		bpf_printk("ft_metadata fallback\n");
		return 0;
	}
    __u32 *m = (__u32 *)data_meta;

	return bpf_ntohl(m[3]);
}

/* Returns L4 type. */
static __always_inline __u32 meta_read_l4type(struct xdp_md *ctx)
{
	__u8 *data_meta = (void *)(long)ctx->data_meta;
	void *data      = (void *)(long)ctx->data;
	if ((void *)data_meta + METADATA_LEN > data) {
		bpf_printk("l4 fallback: not IPv4, type=NONE\n");
		return l4type_fallback(ctx);
	}
    __u32 *m = (__u32 *)data_meta;

	return (0x0ff & m[4]);
}

/* Returns Flow Tag. */
static __always_inline __u32 meta_read_flow_tag(struct xdp_md *ctx)
{
	__u8 *data_meta = (void *)(long)ctx->data_meta;
	void *data      = (void *)(long)ctx->data;
	if ((void *)data_meta + METADATA_LEN > data) {
		bpf_printk("flow_Tag fallback\n");
		return 0;
	}
    __u32 *m = (__u32 *)data_meta;

	return (0x0fff & (m[4]>>8));
}


/* ------------------------------------------------------------------ */
/* small parse helper used by every program                            */
/* ------------------------------------------------------------------ */
static __always_inline int
parse_5tuple(void *data, void *data_end, struct flow_key *k)
{
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return -1;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return -1;

	struct iphdr *iph = (void *)(eth + 1);

	if ((void *)(iph + 1) > data_end)
		return -1;

	k->src_ip = iph->saddr;
	k->dst_ip = iph->daddr;
	k->proto  = iph->protocol;

	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *th = (void *)iph + iph->ihl * 4;

		if ((void *)(th + 1) > data_end)
			return -1;
		k->src_port = th->source;
		k->dst_port = th->dest;
	} else if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *uh = (void *)iph + iph->ihl * 4;

		if ((void *)(uh + 1) > data_end)
			return -1;
		k->src_port = uh->source;
		k->dst_port = uh->dest;
	} else {
		k->src_port = 0;
		k->dst_port = 0;
	}
	return 0;
}