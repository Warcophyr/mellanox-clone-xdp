/* Ricevitore AF_XDP per pacchetti clonati
 * 
 * Riceve i pacchetti dal BPF XDP che sono stati inviati tramite
 * bpf_redirect_map() ai socket AF_XDP
 */

#include <xdp/libxdp.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <poll.h>

#define NUM_FRAMES 4096
#define FRAME_SIZE 4096
#define BATCH_SIZE 64

struct {
  void *buffer;
  uint64_t size;
} umem_area;

static volatile int keep_running = 1;

static void sig_int(int signo) {
  keep_running = 0;
}

/* Crea UMEM per AF_XDP */
static struct xsk_umem *configure_umem(void *buffer, uint64_t size) {
  struct xsk_umem_config umem_config = {
      .fill_size = NUM_FRAMES,
      .comp_size = NUM_FRAMES,
      .frame_size = FRAME_SIZE,
      .frame_headroom = 0,
      .flags = 0,
  };

  struct xsk_umem *umem = NULL;
  int ret = xsk_umem__create(&umem, buffer, size, &(xsk_ring_prod){}, 
                             &(xsk_ring_cons){}, &umem_config);

  if (ret) {
    fprintf(stderr, "Error: xsk_umem__create failed\n");
    return NULL;
  }

  return umem;
}

/* Crea socket AF_XDP e lo lega alla queue */
static struct xsk_socket *create_xsk_socket(const char *ifname,
                                           __u32 queue_id,
                                           struct xsk_umem *umem) {
  struct xsk_socket_config xsk_config = {
      .rx_size = NUM_FRAMES,
      .tx_size = NUM_FRAMES,
      .libbpf_flags = 0,
      .xdp_flags = XDP_FLAGS_DRV_MODE,
      .bind_flags = 0,
  };

  struct xsk_socket *xsk = NULL;
  int ret = xsk_socket__create(&xsk, ifname, queue_id, umem,
                               &(xsk_ring_cons){}, &(xsk_ring_prod){},
                               &(xsk_ring_cons){}, &(xsk_ring_prod){},
                               &xsk_config);

  if (ret) {
    fprintf(stderr, "Error: xsk_socket__create failed: %s\n", strerror(-ret));
    return NULL;
  }

  return xsk;
}

/* Stampa informazioni del pacchetto */
static void print_packet_info(const void *pkt_data, size_t pkt_len) {
  struct ethhdr *eth = (struct ethhdr *)pkt_data;
  
  if (pkt_len < sizeof(*eth)) {
    printf("  Pacchetto troppo piccolo (%zu bytes)\n", pkt_len);
    return;
  }

  printf("  Ethernet: %02x:%02x:%02x:%02x:%02x:%02x -> ",
         eth->h_source[0], eth->h_source[1], eth->h_source[2],
         eth->h_source[3], eth->h_source[4], eth->h_source[5]);
  printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
         eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
         eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

  if (ntohs(eth->h_proto) == ETH_P_IP) {
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > (pkt_data + pkt_len)) {
      printf("  IP header truncato\n");
      return;
    }

    printf("  IP: %s -> ", inet_ntoa(*(struct in_addr *)&iph->saddr));
    printf("%s\n", inet_ntoa(*(struct in_addr *)&iph->daddr));
    printf("  Protocol: %d, TTL: %d\n", iph->protocol, iph->ttl);

    if (iph->protocol == IPPROTO_UDP) {
      __u32 ip_hdr_len = iph->ihl * 4;
      struct udphdr *udph = (struct udphdr *)((void *)iph + ip_hdr_len);

      if ((void *)(udph + 1) > (pkt_data + pkt_len)) {
        printf("  UDP header truncato\n");
        return;
      }

      printf("  UDP: port %d -> %d\n", ntohs(udph->source), 
             ntohs(udph->dest));
    }
  } else {
    printf("  EtherType: 0x%04x\n", ntohs(eth->h_proto));
  }
}

/* Elabora i pacchetti ricevuti */
static void handle_rx_packets(struct xsk_socket *xsk, 
                            struct xsk_umem *umem) {
  struct xsk_ring_cons *rx = xsk_socket__rx_ring(xsk);
  struct xsk_ring_prod *fq = xsk_umem__fill_ring(umem);

  unsigned int rcvd, i;
  unsigned int idx_rx = 0, idx_fq = 0;
  uint64_t addr = 0;

  rcvd = xsk_ring_cons__peek(rx, BATCH_SIZE, &idx_rx);
  if (!rcvd)
    return;

  printf("Ricevuti %u pacchetti:\n", rcvd);

  for (i = 0; i < rcvd; i++) {
    const struct xdp_desc *desc = xsk_ring_cons__rx_descriptor(rx, idx_rx + i);
    addr = desc->addr;
    uint32_t len = desc->len;

    void *pkt_data = xsk_umem__get_data(umem_area.buffer, addr);

    printf("\nPacchetto %u: %u bytes\n", i + 1, len);
    print_packet_info(pkt_data, len);
  }

  xsk_ring_cons__release(rx, rcvd);

  /* Rinnova i frame nel fill ring per ricevere altri pacchetti */
  unsigned int idx = 0;
  while (xsk_ring_prod__reserve(fq, rcvd, &idx)) {
    for (i = 0; i < rcvd; i++) {
      addr = (uint64_t)i * FRAME_SIZE;
      *xsk_ring_prod__fill_addr(fq, idx + i) = addr;
    }
    xsk_ring_prod__submit(fq, rcvd);
  }
}

int main(int argc, char **argv) {
  const char *ifname = "eth0";
  __u32 queue_id = 0;
  int ifindex;
  struct xsk_umem *umem = NULL;
  struct xsk_socket *xsk = NULL;
  struct pollfd fds;
  int ret;

  // Verifica argomenti
  if (argc > 3) {
    fprintf(stderr, "Usage: %s [interface] [queue_id]\n", argv[0]);
    return 1;
  }

  if (argc > 1) {
    ifname = argv[1];
  }
  if (argc > 2) {
    queue_id = strtoul(argv[2], NULL, 0);
  }

  // Ottieni ifindex
  ifindex = if_nametoindex(ifname);
  if (!ifindex) {
    fprintf(stderr, "Error: Unknown interface %s\n", ifname);
    return 1;
  }

  printf("AF_XDP Ricevitore\n");
  printf("Interface: %s (ifindex=%d)\n", ifname, ifindex);
  printf("Queue: %u\n\n", queue_id);

  // Alloca memoria per UMEM
  umem_area.size = NUM_FRAMES * FRAME_SIZE;
  ret = posix_memalign(&umem_area.buffer, getpagesize(), umem_area.size);
  if (ret) {
    fprintf(stderr, "Error: posix_memalign failed\n");
    return 1;
  }

  memset(umem_area.buffer, 0, umem_area.size);

  // Configura UMEM
  umem = configure_umem(umem_area.buffer, umem_area.size);
  if (!umem) {
    free(umem_area.buffer);
    return 1;
  }

  printf("UMEM configurato: %zu bytes\n", umem_area.size);

  // Crea socket AF_XDP
  xsk = create_xsk_socket(ifname, queue_id, umem);
  if (!xsk) {
    xsk_umem__delete(umem);
    free(umem_area.buffer);
    return 1;
  }

  printf("Socket AF_XDP creato e legato\n\n");

  // Setup segnali
  signal(SIGINT, sig_int);
  signal(SIGTERM, sig_int);

  printf("In ascolto di pacchetti clonati (Ctrl+C per uscire)...\n\n");

  // Prepara poll
  fds.fd = xsk_socket__fd(xsk);
  fds.events = POLLIN;

  // Loop principale
  int packets_received = 0;
  while (keep_running) {
    ret = poll(&fds, 1, 1000);
    
    if (ret < 0) {
      if (errno == EINTR)
        continue;
      fprintf(stderr, "poll error: %s\n", strerror(errno));
      break;
    }

    if (ret > 0 && (fds.revents & POLLIN)) {
      handle_rx_packets(xsk, umem);
      packets_received++;
    }
  }

  printf("\nUscita... (%d batch ricevuti)\n", packets_received);

  // Pulizia
  xsk_socket__delete(xsk);
  xsk_umem__delete(umem);
  free(umem_area.buffer);

  printf("Done!\n");
  return 0;
}
