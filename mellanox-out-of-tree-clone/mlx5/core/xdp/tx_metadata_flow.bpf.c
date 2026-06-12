#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "./axdp.h"

#define META_MAX 64

/* test for header push/replace usign WQE inline header 
* with bpf_xdp_adjust_head(ctx,...); can replace instead of pushing
*  tc qdisc add dev enp7s0np0 clsact
*  tc filter add dev enp7s0np0 egress protocol all flower ct_mark 42 skip_sw action drop
*/



__always_inline int stamp_metadata(struct xdp_md *ctx, int value) {
        void  *data = (void *)(long)ctx->data;
        __u8  *data_meta  = (void *)(long)ctx->data_meta;
        __u32 *header = (void *)(long)ctx->data_meta;
        if ((void *)data_meta + META_MAX+8 > data) {
            bpf_printk("no meta space\n");
            return -1;
        }
        header[0] = value;   // metadata value
        return 0;
}

__always_inline int inline_header(struct xdp_md *ctx, __u8* buff) {
        void  *data = (void *)(long)ctx->data;
        __u8  *data_meta  = (void *)(long)ctx->data_meta;
        __u32 *header = (void *)(long)ctx->data_meta;
        if ((void *)data_meta + META_MAX+8 > data) {
            bpf_printk("no meta space\n");
            return -1;
        }
        /* here we populate the inline header*/
        header[1] = META_MAX;   // inline header len
        #pragma unroll
        for (int i = 0; i < META_MAX; i++) {
            data_meta[i+8] = buff[i];
        }
    return 0;
}

int flag=0;

SEC("xdp")
int xdptx_metadata_flow(struct xdp_md *ctx)
{
    //int size = (bpf_get_prandom_u32() & 7) << 2;   /* {0,4,...,28} */

        __u8 buff[64]; 
        /* read metadata */
        __u64 ts=meta_read_timestamp(ctx);            
        __u32 hash = meta_read_hash(ctx);            

        bpf_printk("hash_result: 0x%x \n", hash);
        bpf_printk("timestamp: %llu\n", ts);

        /* write metadata*/
        if (bpf_xdp_adjust_meta(ctx, -(META_MAX+8))) {
            bpf_printk("error adj\n");
            return XDP_DROP;
        }

        void  *data = (void *)(long)ctx->data;
        __u8  *data_meta  = (void *)(long)ctx->data_meta;
        __u32 *header = (void *)(long)ctx->data_meta;
        if ((void *)data_meta + META_MAX+8 > data) {
            bpf_printk("no meta space\n");
            return XDP_DROP;
        }

        //header[0] = 0x2a2a2a2b; // flow_metadata
        if (stamp_metadata(ctx,0x2a2a2a2b))
            return XDP_DROP;
        
        
        /* here we populate the inline header*/
        #pragma unroll
        for (int i = 0; i < 64; i++) {
            buff[i] = 'a'+i;
        }
        if (inline_header(ctx,buff)) 
            return XDP_DROP;
        
        /*
        header[1] = META_MAX;   // inline header len
        
        #pragma unroll
        for (int i = 16; i < META_MAX+16; i++) {
            data_meta[i] = 'a'+i;
        }

        //bpf_xdp_adjust_head(ctx,META_MAX+8);
        */
        return XDP_TX;
}

char _license[] SEC("license") = "GPL";
