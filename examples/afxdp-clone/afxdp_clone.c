/* Programma completo: XDP Clone → AF_XDP (LOADER UNIFICATO)
 * 
 * Questo programma integrato effettua:
 * 1. Carica il programma BPF XDP
 * 2. Crea socket AF_XDP (configurabile)
 * 3. Configura il BPF map per la redirezione
 * 4. Riceve e stampa i pacchetti clonati
 */

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <xdp/libxdp.h>
#include <xdp/xsk.h>

#include "afxdp_clone.bpf.skel.h"

#define NUM_FRAMES 4096
#define FRAME_SIZE 4096
#define BATCH_SIZE 64
#define NUM_SOCKETS 4

static volatile int keep_running = 1;
static __u64 packets_received = 0;

struct {
  void *buffer;
  uint64_t size;
} umem_area;

struct xsk_socket_info {
  struct xsk_umem *umem;
  struct xsk_socket *socket;
  int xsk_map_fd;
  __u32 idx;
};

static void sig_int(int signo) {
  keep_running = 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
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

static struct xsk_umem *configure_umem(void *buffer, uint64_t size) {
  struct xsk_umem_config umem_config = {
      .fill_size = NUM_FRAMES,
      .comp_size = NUM_FRAMES,
      .frame_size = FRAME_SIZE,
      .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
      .flags = XSK_UMEM__DEFAULT_FLAGS,
  };
  struct xsk_socket_config xsk_cfg;
  struct xsk_socket_info *xsk_info;
  struct xsk_umem *umem;
  
  int ret = xsk_umem__create(&umem, buffer, size, &fq, &cq, &umem_config);
  if (ret) {
    fprintf(stderr, "Error: xsk_umem__create failed: %s\n", strerror(-ret));
    return NULL;
  }
  return umem;
}

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

  struct xsk_ring_cons rx, cq;
  struct xsk_ring_prod tx, fq;
  struct xsk_socket *xsk;
  
  int ret = xsk_socket__create(&xsk, ifname, queue_id, umem,
                               &rx, &tx, &xsk_config);
  if (ret) {
    fprintf(stderr, "Error: xsk_socket__create on queue %u failed: %s\n",
            queue_id, strerror(-ret));
    return NULL;
  }
  printf("✓ Socket AF_XDP creato su queue %u\n", queue_id);
  return xsk;
}

static int register_xsk_to_map(int xsk_map_fd, __u32 queue_id,
                              struct xsk_socket *xsk) {
  int fd = xsk_socket__fd(xsk);
  int ret = bpf_map_update_elem(xsk_map_fd, &queue_id, &fd, 0);
  if (ret) {
    fprintf(stderr, "Error: Failed to register XSK socket in map\n");
    return -1;
  }
  printf("✓ Socket AF_XDP registrato nel xsk_map[%u]\n", queue_id);
  return 0;
}

static void handle_rx_packets(struct xsk_socket_info *xsk_info) {
  struct xsk_socket *xsk = xsk_info->socket;
  struct xsk_umem *umem = xsk_info->umem;
  struct xsk_ring_cons *rx = xsk_socket__rx_ring(xsk);
  struct xsk_ring_prod *fq = xsk_umem__fill_ring(umem);

  unsigned int rcvd, i;
  unsigned int idx_rx = 0, idx_fq = 0;

  rcvd = xsk_ring_cons__peek(rx, BATCH_SIZE, &idx_rx);
  if (!rcvd)
    return;

  for (i = 0; i < rcvd; i++) {
    const struct xdp_desc *desc = xsk_ring_cons__rx_descriptor(rx, idx_rx + i);
    char *pkt = xsk_umem__get_data(umem_area.buffer, desc->addr);
    struct ethhdr *eth = (struct ethhdr *)pkt;

    packets_received++;
    printf("\n[%llu] Socket %u - Pacchetto %u bytes (0x%lx)\n",
           packets_received, xsk_info->idx, desc->len, desc->addr);

    if (desc->len >= sizeof(*eth)) {
      printf("  MAC: %02x:%02x:%02x:%02x:%02x:%02x -> "
             "%02x:%02x:%02x:%02x:%02x:%02x\n",
             eth->h_source[0], eth->h_source[1], eth->h_source[2],
             eth->h_source[3], eth->h_source[4], eth->h_source[5],
             eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
             eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

      if (ntohs(eth->h_proto) == ETH_P_IP && 
          desc->len >= sizeof(*eth) + sizeof(struct iphdr)) {
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        printf("  IP: %s -> %s (Protocol: %u)\n",
               inet_ntoa(*(struct in_addr *)&iph->saddr),
               inet_ntoa(*(struct in_addr *)&iph->daddr),
               iph->protocol);
      }
    }
  }

  xsk_ring_cons__release(rx, rcvd);

  while (xsk_ring_prod__reserve(fq, rcvd, &idx_fq)) {
    for (i = 0; i < rcvd; i++) {
      *xsk_ring_prod__fill_addr(fq, idx_fq + i) =
          (i * FRAME_SIZE) + umem_area.size / 2;
    }
    xsk_ring_prod__submit(fq, rcvd);
  }
}

struct config {
  __u32 num_copies;
  __u32 afxdp_queue;
  __u32 enable_afxdp;
};

int main(int argc, char **argv) {
  const char *ifname = "eth0";
  __u32 ifindex;
  struct afxdp_clone_bpf *skel = NULL;
  int xsk_map_fd = -1;
  struct xsk_socket_info xsk_sockets[NUM_SOCKETS];
  struct pollfd fds[NUM_SOCKETS];
  int ret;
  __u32 i;

  if (argc > 2) {
    fprintf(stderr, "Usage: %s [interface]\n", argv[0]);
    return 1;
  }

  if (argc == 2) {
    ifname = argv[1];
  }

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

  printf("\n[2] Creazione UMEM e socket AF_XDP...\n");

  umem_area.size = NUM_FRAMES * FRAME_SIZE * 2;
  ret = posix_memalign(&umem_area.buffer, getpagesize(), umem_area.size);
  if (ret) {
    fprintf(stderr, "Error: posix_memalign failed\n");
    afxdp_clone_bpf__destroy(skel);
    return 1;
  }

  memset(umem_area.buffer, 0, umem_area.size);
  printf("✓ UMEM allocato: %zu bytes\n", umem_area.size);

  struct xsk_umem *umem = configure_umem(umem_area.buffer, umem_area.size);
  if (!umem) {
    free(umem_area.buffer);
    afxdp_clone_bpf__destroy(skel);
    return 1;
  }

  printf("✓ UMEM configurato\n");

  memset(xsk_sockets, 0, sizeof(xsk_sockets));

  for (i = 0; i < NUM_SOCKETS; i++) {
    xsk_sockets[i].socket = create_xsk_socket(ifname, i, umem);
    if (!xsk_sockets[i].socket) {
      fprintf(stderr, "Failed to create XSK socket for queue %u\n", i);
      goto cleanup;
    }

    xsk_sockets[i].umem = umem;
    xsk_sockets[i].xsk_map_fd = xsk_map_fd;
    xsk_sockets[i].idx = i;

    if (register_xsk_to_map(xsk_map_fd, i, xsk_sockets[i].socket) < 0)
      goto cleanup;

    fds[i].fd = xsk_socket__fd(xsk_sockets[i].socket);
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

  while (keep_running) {
    ret = poll(fds, NUM_SOCKETS, 1000);

    if (ret < 0) {
      if (errno == EINTR)
        continue;
      fprintf(stderr, "poll error: %s\n", strerror(errno));
      break;
    }

    if (ret > 0) {
      for (i = 0; i < NUM_SOCKETS; i++) {
        if (fds[i].revents & POLLIN) {
          handle_rx_packets(&xsk_sockets[i]);
        }
      }
    }
  }

cleanup:
  printf("\n────────────────────────────────────────────────────\n");
  printf("Pulizia...\n");

  for (i = 0; i < NUM_SOCKETS; i++) {
    if (xsk_sockets[i].socket) {
      xsk_socket__delete(xsk_sockets[i].socket);
    }
  }

  if (umem) {
    xsk_umem__delete(umem);
  }

  if (umem_area.buffer) {
    free(umem_area.buffer);
  }

  afxdp_clone_bpf__destroy(skel);

  printf("✓ Pacchetti ricevuti totali: %llu\n", packets_received);
  printf("Done!\n");

  return 0;
}
