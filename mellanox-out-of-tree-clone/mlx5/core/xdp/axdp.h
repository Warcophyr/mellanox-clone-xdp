/* ------------------------------------------------------------------ */
/* (1) RX computation offloads — read NIC-computed CQE fields          */
/* ------------------------------------------------------------------ */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


/* Returns 0 on success with *ts filled, -1 on error. */
static __always_inline __u64 meta_read_timestamp(struct xdp_md *ctx)
{
	__u8 *data_meta = (void *)(long)ctx->data_meta;
	void *data      = (void *)(long)ctx->data;
    __u64 ts=0;
	if ((void *)data_meta + 16 > data) {
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
	if ((void *)data_meta + 16 > data) {
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