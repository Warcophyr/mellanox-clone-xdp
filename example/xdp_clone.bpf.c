// do not change the order of the include
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/if_xdp.h>

#define __XDP_CLONE_PASS 5
#define __XDP_CLONE_TX 6
#define XDP_CLONE_PASS(num_copy)                                               \
  (((int)(num_copy) << 5) | (int)__XDP_CLONE_PASS)
#define XDP_CLONE_TX(num_copy) (((int)(num_copy) << 5) | (int)__XDP_CLONE_TX)

static __always_inline __u16 ip_checksum_xdp(struct iphdr *ip) {
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
    // bpf_printk("XDP: Ethernet header validation failed\n");
    return XDP_PASS;
  }

  // Only process IP packets
  if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
    // bpf_printk("XDP: Non-IP packet, passing through\n");
    return XDP_PASS;
  }

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end) {
    // bpf_printk("XDP: IP header validation failed\n");
    return XDP_PASS;
  }

  // Only process UDP packets
  if (iph->protocol != IPPROTO_UDP) {
    return XDP_PASS;
  }

  __u32 ip_hdr_len = iph->ihl * 4;
  struct udphdr *udph = (void *)iph + ip_hdr_len;
  if ((void *)(udph + 1) > data_end) {
    // bpf_printk("XDP: UDP header validation failed\n");
    return XDP_PASS;
  }
  // __u8 src_mac[ETH_ALEN];
  // __u8 dst_mac[ETH_ALEN];
  // __builtin_memcpy(src_mac, eth->h_source, ETH_ALEN);
  // __builtin_memcpy(dst_mac, eth->h_dest, ETH_ALEN);
  // __builtin_memcpy(eth->h_source, dst_mac, ETH_ALEN);
  // __builtin_memcpy(eth->h_dest, src_mac, ETH_ALEN);
  // // bpf_printk("ETH: src=%02x:%02x:%02x:%02x:%02x:%02x "
  // //            "dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
  // //            eth->h_source[0], eth->h_source[1], eth->h_source[2],
  // //            eth->h_source[3], eth->h_source[4], eth->h_source[5],
  // //            eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
  // //            eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

  // __u32 saddr = iph->saddr;
  // __u32 daddr = iph->daddr;
  // __sum16 check = iph->check;
  // __be16 id = iph->id;
  // __be16 frag_off = iph->frag_off;
  // __sum16 check_udp = udph->check;

  // // bpf_printk("Received Source IP: 0x%x", bpf_ntohl(iph->saddr));
  // // bpf_printk("Received Destination IP: 0x%x",
  // // bpf_ntohl(iph->daddr));
  // // bpf_printk("IP checksum: 0x%04x\n", __builtin_bswap16(check));
  // // bpf_printk("IP ID: %u, Fragment offset + flags: 0x%x\n", id,
  // // frag_off);

  // __u32 new_daddr = bpf_ntohl(saddr);
  // __u32 new_saddr = bpf_ntohl(daddr);
  // iph->saddr = bpf_htonl(new_saddr);
  // iph->daddr = bpf_htonl(new_daddr);
  // // bpf_printk("Received Source IP: 0x%x", bpf_ntohl(iph->saddr));
  // // bpf_printk("Received Destination IP: 0x%x",
  // // bpf_ntohl(iph->daddr);

  // // bpf_printk("UDP: sport=%d dport=%d len=%d\n",
  // // bpf_ntohs(udph->source),
  // //            bpf_ntohs(udph->dest), bpf_ntohs(udph->len));
  // udph->dest = bpf_htons(5000);
  // // udph->dest = 12346;
  // // udph->check = 0;

  // // iph->check = ip_checksum_xdp(iph);
  // // bpf_printk("UDP: sport=%d dport=%d len=%d\n",
  // // bpf_ntohs(udph->source),
  // //            bpf_ntohs(udph->dest), bpf_ntohs(udph->len));

  // udph->check = 0;
  // iph->check = ip_checksum_xdp(iph);

  // int claim = ctx->data_meta + sizeof(__u32) <= ctx->data;
  // bpf_printk("data_meta: %d data: %d", ctx->data_meta, ctx->data);
  if (ctx->data_meta + sizeof(__u32) <= ctx->data) {
    int num_copy = 0;
    bpf_printk("ip: %lu", bpf_ntohl(iph->saddr));
    __builtin_memcpy(&num_copy, data_meta, sizeof(num_copy));
    bpf_printk("num_copy: %d", num_copy);
    if (num_copy == 0) {
      return XDP_CLONE_PASS(4);
    } else if (num_copy > 0) {
      __u32 daddr = iph->daddr;
      __u32 new_daddr = bpf_ntohl(daddr) + 1;
      iph->daddr = bpf_htonl(new_daddr);

      udph->check = 0;
      iph->check = ip_checksum_xdp(iph);
      return XDP_TX;
    }
    return XDP_PASS;
  }
  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";