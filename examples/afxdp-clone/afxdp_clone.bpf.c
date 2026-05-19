// BPF program per clonazione pacchetti con redirezione a AF_XDP
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

/* BPF map per gli AF_XDP sockets
 * Contiene i riferimenti ai socket AF_XDP
 * L'indice del map corrisponde al queue_id
 */
struct {
  __uint(type, BPF_MAP_TYPE_XSKMAP);
  __uint(max_entries, 64);
} xsk_map SEC(".maps");

/* BPF map per configurazione (quante copie, dove inoltrarle, ecc.)
 * Key: 0 = configurazione globale
 * Value: configurazione
 */
struct config {
  __u32 num_copies;      // numero di copie da fare
  __u32 afxdp_queue;     // queue ID per AF_XDP redirect
  __u32 enable_afxdp;    // abilita redirezione a AF_XDP
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct config);
} config_map SEC(".maps");

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
int afxdp_clone(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  void *data_meta = (void *)(long)ctx->data_meta;

  // Leggi configurazione
  __u32 cfg_key = 0;
  struct config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
  if (!cfg) {
    bpf_printk("XDP: Config non trovata\n");
    return XDP_PASS;
  }

  // Basic packet validation
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    bpf_printk("XDP: Ethernet header validation failed\n");
    return XDP_PASS;
  }

  // Only process IP packets
  if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
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

  // Solo processa pacchetti UDP destinati alla porta 8901
  if (bpf_ntohs(udph->dest) != 8901) {
    return XDP_PASS;
  }

  // Leggi metadata (numero di copia attuale)
  if (ctx->data_meta + sizeof(__u32) <= ctx->data) {
    int num_copy = 0;
    __builtin_memcpy(&num_copy, data_meta, sizeof(num_copy));

    bpf_printk("XDP: Pacchetto ricevuto, num_copy=%d\n", num_copy);

    if (num_copy == 0) {
      // Prima copia - decisione di clonazione

      if (cfg->enable_afxdp) {
        // Modalità con AF_XDP: clona e manda alcune a AF_XDP
        bpf_printk("XDP: CLONE_TX con %u copie (AF_XDP enabled)\n", cfg->num_copies);
        return XDP_CLONE_TX(cfg->num_copies);
      } else {
        // Modalità tradizionale: clona e manda tutte a TX
        bpf_printk("XDP: CLONE_TX con %u copie\n", cfg->num_copies);
        return XDP_CLONE_TX(cfg->num_copies);
      }
    } else if (num_copy > 0) {
      // Copie successive - decide dove mandare questa copia
      
      bpf_printk("XDP: Elaborando copia %d\n", num_copy);

      // Scambia MAC source/dest
      unsigned char tmp[ETH_ALEN];
      __builtin_memcpy(tmp, eth->h_dest, ETH_ALEN);
      __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
      __builtin_memcpy(eth->h_source, tmp, ETH_ALEN);

      // Modifica IP destination per differenziare le copie
      __u32 daddr = iph->daddr;
      __u32 new_daddr = bpf_ntohl(daddr) + num_copy;
      iph->daddr = bpf_htonl(new_daddr);
      udph->check = 0;
      iph->check = ip_checksum(iph);

      // Decide destinazione della copia
      if (cfg->enable_afxdp && num_copy % 2 == 0) {
        // Copie pari: manda a AF_XDP via redirect
        // 
        // bpf_redirect_map() prende l'indice nel map come parametro
        // Usa la queue configurata
        bpf_printk("XDP: Copia %d -> AF_XDP queue %u\n", num_copy, cfg->afxdp_queue);
        
        return bpf_redirect_map(&xsk_map, cfg->afxdp_queue, 0);
      } else {
        // Copie dispari: trasmetti via TX
        bpf_printk("XDP: Copia %d -> TX\n", num_copy);
        return XDP_TX;
      }
    }

    return XDP_PASS;
  }

  // Se non c'è spazio per metadata, ritorna PASS
  bpf_printk("XDP: Packet too small for metadata, passing through\n");
  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
