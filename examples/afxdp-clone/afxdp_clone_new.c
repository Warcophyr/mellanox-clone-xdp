/* SPDX-License-Identifier: GPL-2.0
 * XDP Clone → AF_XDP Unified Loader
 * 
 * Basato su xdp-tutorial approach
 * https://github.com/xdp-project/xdp-tutorial/blob/main/advanced03-AF_XDP/af_xdp_user.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <poll.h>
#include <sys/resource.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "afxdp_clone.bpf.skel.h"

#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE 64
#define INVALID_UMEM_FRAME UINT64_MAX

static volatile int keep_running = 1;
static __u64 packets_received = 0;

/* UMEM info structure */
struct xsk_umem_info {
  struct xsk_ring_prod fq;
  struct xsk_ring_cons cq;
  struct xsk_umem *umem;
  void *buffer;
};

/* Socket info structure */
struct xsk_socket_info {
  struct xsk_ring_cons rx;
  struct xsk_ring_prod tx;
  struct xsk_umem_info *umem;
  struct xsk_socket *xsk;
  
  uint64_t umem_frame_addr[NUM_FRAMES];
  uint32_t umem_frame_free;
  uint32_t outstanding_tx;
};

struct config {
  __u32 num_copies;
  __u32 afxdp_queue;
  __u32 enable_afxdp;
};

static void sig_int(int signo) {
  keep_running = 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, 
                           const char *format, va_list args) {
  return vfprintf(stderr, format, args);
}

static int increase_rlimit_memlock(void) {
  struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
  if (setrlimit(RLIMIT_MEMLOCK, &r)) {
    perror("setrlimit(RLIMIT_MEMLOCK)");
    return -1;
  }
  return 0;
}

/* Configure UMEM following xdp-tutorial style */
static struct xsk_umem_info *configure_umem(void *buffer, uint64_t size) {
  struct xsk_umem_info *umem;
  int ret;

  umem = calloc(1, sizeof(*umem));
  if (!umem)
    return NULL;

  ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, NULL);
  if (ret) {
    errno = -ret;
    fprintf(stderr, "Error: xsk_umem__create failed: %s\n", strerror(-ret));
    free(umem);
    return NULL;
  }

  umem->buffer = buffer;
  printf("✓ UMEM configurato: %zu bytes\n", size);
  return umem;
}

/* Allocate frame from pool */
static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk) {
  uint64_t frame;
  if (xsk->umem_frame_free == 0)
    return INVALID_UMEM_FRAME;

  frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
  xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
  return frame;
}

/* Free frame back to pool */
static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame) {
  if (xsk->umem_frame_free < NUM_FRAMES)
    xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

/* Get free frames count */
static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk) {
  return xsk->umem_frame_free;
}

/* Configure socket following xdp-tutorial style */
static struct xsk_socket_info *configure_socket(const char *ifname,
                                                 __u32 queue_id,
                                                 struct xsk_umem_info *umem) {
  struct xsk_socket_config xsk_cfg;
  struct xsk_socket_info *xsk_info;
  uint32_t idx;
  int i, ret;

  xsk_info = calloc(1, sizeof(*xsk_info));
  if (!xsk_info)
    return NULL;

  xsk_info->umem = umem;

  memset(&xsk_cfg, 0, sizeof(xsk_cfg));
  xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
  xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
  xsk_cfg.xdp_flags = XDP_FLAGS_DRV_MODE;
  xsk_cfg.bind_flags = 0;

  ret = xsk_socket__create(&xsk_info->xsk, ifname, queue_id, umem->umem,
                           &xsk_info->rx, &xsk_info->tx, &xsk_cfg);
  if (ret) {
    fprintf(stderr, "Error: xsk_socket__create failed: %s\n", strerror(-ret));
    free(xsk_info);
    return NULL;
  }

  printf("✓ Socket AF_XDP creato su queue %u\n", queue_id);

  /* Initialize frame allocation */
  for (i = 0; i < NUM_FRAMES; i++)
    xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;
  xsk_info->umem_frame_free = NUM_FRAMES;

  /* Fill RX ring with frames */
  ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
                               XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
  if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
    fprintf(stderr, "Error: Could not fill RX ring\n");
    xsk_socket__delete(xsk_info->xsk);
    free(xsk_info);
    return NULL;
  }

  for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
    *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
        xsk_alloc_umem_frame(xsk_info);

  xsk_ring_prod__submit(&xsk_info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

  return xsk_info;
}

/* Print packet info */
static void print_packet_info(void *pkt_data, uint32_t len) {
  struct ethhdr *eth = (struct ethhdr *)pkt_data;

  if (len < sizeof(*eth))
    return;

  printf("  MAC: %02x:%02x:%02x:%02x:%02x:%02x -> "
         "%02x:%02x:%02x:%02x:%02x:%02x\n",
         eth->h_source[0], eth->h_source[1], eth->h_source[2],
         eth->h_source[3], eth->h_source[4], eth->h_source[5],
         eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
         eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

  if (ntohs(eth->h_proto) == ETH_P_IP &&
      len >= sizeof(*eth) + sizeof(struct iphdr)) {
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    printf("  IP: %s -> %s (Protocol: %u)\n",
           inet_ntoa(*(struct in_addr *)&iph->saddr),
           inet_ntoa(*(struct in_addr *)&iph->daddr), iph->protocol);
  }
}

/* Handle received packets */
static void handle_rx_packets(struct xsk_socket_info *xsk) {
  unsigned int rcvd, stock_frames, i;
  uint32_t idx_rx = 0, idx_fq = 0;
  int ret;

  rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
  if (!rcvd)
    return;

  /* Refill RX ring */
  stock_frames =
      xsk_prod_nb_free(&xsk->umem->fq, xsk_umem_free_frames(xsk));

  if (stock_frames > 0) {
    ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames, &idx_fq);

    while (ret != stock_frames)
      ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames, &idx_fq);

    for (i = 0; i < stock_frames; i++)
      *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
          xsk_alloc_umem_frame(xsk);

    xsk_ring_prod__submit(&xsk->umem->fq, stock_frames);
  }

  /* Process packets */
  for (i = 0; i < rcvd; i++) {
    uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
    uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;
    void *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

    packets_received++;
    printf("\n[%llu] Pacchetto %u bytes (0x%lx)\n", packets_received, len,
           addr);
    print_packet_info(pkt, len);
  }

  xsk_ring_cons__release(&xsk->rx, rcvd);
}

int main(int argc, char **argv) {
  const char *ifname = "eth0";
  __u32 ifindex;
  struct afxdp_clone_bpf *skel = NULL;
  struct xsk_umem_info *umem = NULL;
  struct xsk_socket_info *xsk_sockets[4];
  struct pollfd fds[4];
  void *packet_buffer;
  uint64_t packet_buffer_size;
  int ret, i;

  if (argc > 2) {
    fprintf(stderr, "Usage: %s [interface]\n", argv[0]);
    return 1;
  }

  if (argc == 2)
    ifname = argv[1];

  printf("═══════════════════════════════════════════════════\n");
  printf("  XDP Clone → AF_XDP (Unified Loader)\n");
  printf("═══════════════════════════════════════════════════\n\n");

  ifindex = if_nametoindex(ifname);
  if (!ifindex) {
    fprintf(stderr, "Error: Unknown interface %s\n", ifname);
    return 1;
  }

  printf("Interface: %s (ifindex: %u)\n", ifname, ifindex);

  libbpf_set_print(libbpf_print_fn);

  if (increase_rlimit_memlock() < 0)
    return 1;

  printf("\n[1] Caricamento programma BPF...\n");

  skel = afxdp_clone_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  ret = afxdp_clone_bpf__attach(skel);
  if (ret) {
    fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(-ret));
    afxdp_clone_bpf__destroy(skel);
    return 1;
  }

  printf("✓ Programma BPF caricato e attaccato\n");

  printf("\n[2] Allocazione buffer e creazione socket...\n");

  /* Allocate packet buffer */
  packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
  ret = posix_memalign(&packet_buffer, getpagesize(), packet_buffer_size);
  if (ret) {
    fprintf(stderr, "Error: posix_memalign failed\n");
    afxdp_clone_bpf__destroy(skel);
    return 1;
  }

  memset(packet_buffer, 0, packet_buffer_size);

  /* Configure UMEM */
  umem = configure_umem(packet_buffer, packet_buffer_size);
  if (!umem) {
    free(packet_buffer);
    afxdp_clone_bpf__destroy(skel);
    return 1;
  }

  /* Create sockets for multiple queues */
  memset(xsk_sockets, 0, sizeof(xsk_sockets));

  for (i = 0; i < 4; i++) {
    xsk_sockets[i] = configure_socket(ifname, i, umem);
    if (!xsk_sockets[i]) {
      fprintf(stderr, "Failed to create socket for queue %d\n", i);
      goto cleanup;
    }

    fds[i].fd = xsk_socket__fd(xsk_sockets[i]->xsk);
    fds[i].events = POLLIN;
  }

  printf("\n[3] Configurazione BPF map...\n");

  struct config cfg = {
      .num_copies = 4,
      .afxdp_queue = 0,
      .enable_afxdp = 1,
  };

  __u32 key = 0;
  ret = bpf_map_update_elem(bpf_map__fd(skel->maps.config_map), &key, &cfg, 0);
  if (ret) {
    fprintf(stderr, "Failed to update config_map\n");
    goto cleanup;
  }

  printf("✓ Configurazione:\n");
  printf("  - num_copies: %u\n", cfg.num_copies);
  printf("  - afxdp_queue: %u\n", cfg.afxdp_queue);
  printf("  - enable_afxdp: %u\n", cfg.enable_afxdp);

  signal(SIGINT, sig_int);
  signal(SIGTERM, sig_int);

  printf("\n[4] In ascolto di pacchetti clonati...\n");
  printf("────────────────────────────────────────────────────\n");
  printf("Premi Ctrl+C per uscire\n");
  printf("────────────────────────────────────────────────────\n\n");

  /* Main loop */
  while (keep_running) {
    ret = poll(fds, 4, 1000);

    if (ret < 0) {
      if (errno == EINTR)
        continue;
      fprintf(stderr, "poll error: %s\n", strerror(errno));
      break;
    }

    if (ret > 0) {
      for (i = 0; i < 4; i++) {
        if (fds[i].revents & POLLIN) {
          handle_rx_packets(xsk_sockets[i]);
        }
      }
    }
  }

cleanup:
  printf("\n────────────────────────────────────────────────────\n");
  printf("Pulizia...\n");

  for (i = 0; i < 4; i++) {
    if (xsk_sockets[i]) {
      xsk_socket__delete(xsk_sockets[i]->xsk);
      free(xsk_sockets[i]);
    }
  }

  if (umem) {
    xsk_umem__delete(umem->umem);
    free(umem);
  }

  if (packet_buffer)
    free(packet_buffer);

  afxdp_clone_bpf__destroy(skel);

  printf("✓ Pacchetti ricevuti totali: %llu\n", packets_received);
  printf("Done!\n");

  return 0;
}
