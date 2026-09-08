// do not change the order of the include
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

/* Values of the two duplication actions, defined here so that this example
 * builds against stock headers too.
 */
#define ACT_CLONE_PASS 5
#define ACT_CLONE_TX 6

/* Registered by the patched mlx5_core, see mlx5/core/clone/clone_bpf.c. The
 * module has to be loaded for libbpf to resolve this from its BTF.
 *
 * Returns @action if the request was accepted, or the fallback action in the
 * low bits of @flags if it was refused: already running on a copy, no headroom
 * for the copy metadata, or n_copies == 0.
 */
extern int bpf_xdp_clone(struct xdp_md *ctx, __u32 n_copies, __u32 action,
                         __u64 flags) __ksym;

__u64 n_clone = 4;

SEC("xdp")
int xdp_clone_kfunc(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  struct iphdr *iph;
  struct udphdr *udph;
  __u32 ip_hdr_len;

  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return XDP_PASS;

  iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return XDP_PASS;

  if (iph->protocol != IPPROTO_UDP)
    return XDP_PASS;

  ip_hdr_len = iph->ihl * 4;
  udph = (void *)iph + ip_hdr_len;
  if ((void *)(udph + 1) > data_end)
    return XDP_PASS;

  if (bpf_ntohs(udph->dest) != 8901)
    return XDP_PASS;

  /* A copy carries its index in the four bytes in front of the data, so this
   * branch is where the copies are modified, one by one. The original packet
   * sees no metadata and falls through to the request below.
   *
   * Note the sizeof(): the comparison has to be done in 64-bit arithmetic, or
   * clang truncates the pointer to 32 bits and the verifier rejects the
   * program.
   */
  if (ctx->data_meta + sizeof(__u32) <= ctx->data) {
    __u32 idx;

    __builtin_memcpy(&idx, (void *)(long)ctx->data_meta, sizeof(idx));

    /* Copies are numbered from 1. Give each one a different destination
     * address, the checksum is left to the reader.
     */
    iph->daddr = bpf_htonl(bpf_ntohl(iph->daddr) + idx);
    udph->check = 0;

    return XDP_TX;
  }

  /* One call does all the checking: that this is not itself a copy, that there
   * is room for the copy metadata, and that the count is sane. If it refuses
   * we get XDP_PASS back and the packet goes up the stack instead of being
   * dropped by the driver.
   *
   * The other way to ask, still supported, is to encode the count in the
   * return value: return (n_clone << 5) | ACT_CLONE_TX. Nothing validates it,
   * see ../clone-tx.
   */
  return bpf_xdp_clone(ctx, n_clone, ACT_CLONE_TX, XDP_PASS);
}

char LICENSE[] SEC("license") = "GPL";
