// do not change the order of the include
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/if_xdp.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#ifdef DEBUG
#define bpf_printk(fmt, ...)                                                   \
  ({                                                                           \
    char ____fmt[] = fmt;                                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                 \
  })
#else
#define bpf_printk(fmt, ...) ({})
#endif

#define __XDP_CLONE_PASS 5
#define __XDP_CLONE_TX 6
#define XDP_CLONE_PASS(num_copy)                                               \
  (((int)(num_copy) << 5) | (int)__XDP_CLONE_PASS)
#define XDP_CLONE_TX(num_copy) (((int)(num_copy) << 5) | (int)__XDP_CLONE_TX)

__u64 n_clone = 4;

static __always_inline __u16 ip_checksum(struct iphdr *ip) {
  __u32 sum = 0;
  __u16 *data = (__u16 *)ip;

// IP header is guaranteed to be at least 20 bytes, so 10 16-bit words
#pragma unroll
  for (int i = 0; i < 10; i++) {
    if (i == 5)
      continue; // Skip checksum field
    sum += bpf_ntohs(data[i]);
  }

  // Add carry
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return bpf_htons(~sum);
}

SEC("xdp")
int xdp_clone(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  void *data_meta = (void *)(long)ctx->data_meta;

  // Basic packet validation
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    bpf_printk("XDP: Ethernet header validation failed\n");
    return XDP_PASS;
  }

  // Only process IP packets
  if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
    // bpf_printk("XDP: Non-IP packet, passing through");
    return XDP_PASS;
  }

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end) {
    bpf_printk("XDP: IP header validation failed\n");
    return XDP_PASS;
  }

  // Only process UDP packets
  if (iph->protocol != IPPROTO_UDP) {
    return XDP_PASS;
  }

  __u32 ip_hdr_len = iph->ihl * 4;
  struct udphdr *udph = (void *)iph + ip_hdr_len;
  if ((void *)(udph + 1) > data_end) {
    bpf_printk("XDP: UDP header validation failed\n");
    return XDP_PASS;
  }
  if (bpf_ntohs(udph->dest) != 8901) {
    return XDP_PASS;
  }

  if (ctx->data_meta + sizeof(__u32) <= ctx->data) {
    int num_copy = 0;
    // bpf_printk("ip: %lu", bpf_ntohl(iph->saddr));
    __builtin_memcpy(&num_copy, data_meta, sizeof(num_copy));
    // bpf_printk("num_copy: %d", num_copy);
    if (num_copy == 0) {
      unsigned char tmp[ETH_ALEN];
      __builtin_memcpy(tmp, eth->h_dest, ETH_ALEN);
      __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
      __builtin_memcpy(eth->h_source, tmp, ETH_ALEN);

      // bpf_printk("TX");
      //  return XDP_TX;
    } else if (num_copy > 0) {
      __u32 daddr = iph->daddr;
      __u32 new_daddr = bpf_ntohl(daddr) + num_copy;
      iph->daddr = bpf_htonl(new_daddr);
      udph->check = 0;
      iph->check = ip_checksum(iph);
      return XDP_TX;
    }
    return XDP_PASS;
  }

  // bpf_printk("XDP: Packet too small for metadata, passing through\n");
  return XDP_CLONE_TX(n_clone);
}

char LICENSE[] SEC("license") = "GPL";
