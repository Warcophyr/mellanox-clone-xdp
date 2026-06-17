#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define META_MIN 16
#define META_MAX 64

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

/* test for header push/replace usign WQE inline header 
* with bpf_xdp_adjust_head(ctx,...); can replace instead of pushing
*/

SEC("xdp")
int xdptx_header(struct xdp_md *ctx)
{
    //int size = (bpf_get_prandom_u32() & 7) << 2;   /* {0,4,...,28} */
    __u8 buff[64]; 

    if ((bpf_get_prandom_u32() % 2) ==0) {
        if (bpf_xdp_adjust_meta(ctx, -META_MAX)) {
            bpf_printk("error adj\n");
            return XDP_DROP;
        }

        void *data      = (void *)(long)ctx->data;
        __u8 *data_meta = (void *)(long)ctx->data_meta;

        if ((void *)data_meta + META_MAX > data) {
            bpf_printk("no meta space\n");
            return XDP_DROP;
        }

        /* here we populate the header*/
        #pragma unroll
        for (int i = 0; i < META_MAX; i++) {
            data_meta[i] = 'A'+i;
        }

        bpf_xdp_adjust_head(ctx,META_MAX);
        return XDP_TX;
    }
    else {
        if (bpf_xdp_adjust_meta(ctx, -META_MIN)) {
            bpf_printk("error adj\n");
            return XDP_DROP;
        }

        void *data      = (void *)(long)ctx->data;
        __u8 *data_meta = (void *)(long)ctx->data_meta;

        if ((void *)data_meta + META_MIN > data) {
            bpf_printk("no meta space\n");
            return XDP_DROP;
        }

        /* here we populate the inline header*/
        #pragma unroll
        for (int i = 0; i < 64; i++) {
            buff[i] = 'a'+i;
        }
        if (inline_header(ctx,buff)) 
            return XDP_DROP;
        
        
        bpf_xdp_adjust_head(ctx,META_MIN);
        return XDP_TX;
    }
}

char _license[] SEC("license") = "GPL";
