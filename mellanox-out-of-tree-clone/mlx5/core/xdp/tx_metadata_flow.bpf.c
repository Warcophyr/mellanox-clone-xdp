#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "./axdp.h"


/* test for metadata insertion in TX table
*/

#define XDP_TX_2 5

__always_inline int stamp_metadata(struct xdp_md *ctx, int value) {
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


int flag=0;

SEC("xdp")
int xdptx_metadata_flow(struct xdp_md *ctx)
{
    
        /* read metadata */
        __u64 ts=meta_read_timestamp(ctx);            
        __u32 hash = meta_read_hash(ctx);            
        __u32 flow_tag= meta_read_flow_tag(ctx); 
        __u32 ft_metadata= meta_read_ft_metadata(ctx);

        bpf_printk("hash_result: 0x%x \n", hash);
        bpf_printk("timestamp: %llu\n", ts);
        bpf_printk("flow_tag: 0x%x\n", flow_tag);
        bpf_printk("ft_metadata: 0x%x\n", ft_metadata);

        /* write metadata*/
        if (bpf_xdp_adjust_meta(ctx, -8)) {
            bpf_printk("error adj\n");
            return XDP_DROP;
        }

        void  *data = (void *)(long)ctx->data;
        __u8  *data_meta  = (void *)(long)ctx->data_meta;
        __u32 *header = (void *)(long)ctx->data_meta;
        if ((void *)data_meta + 8 > data) {
            bpf_printk("no meta space\n");
            return XDP_DROP;
        }

        //header[0] = 0x2a2a2a2b; // flow_metadata
        if (stamp_metadata(ctx,0x0a0a0a0a))
            return XDP_DROP;
        
        //return XDP_TX;
        return XDP_TX_2;
}

char _license[] SEC("license") = "GPL";
