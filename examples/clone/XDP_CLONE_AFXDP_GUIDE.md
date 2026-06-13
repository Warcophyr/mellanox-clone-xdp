# Clonazione XDP con Redirezione a AF_XDP

## 📋 Panoramica

Questo esempio dimostra come clonare pacchetti in XDP e indirizzarli simultaneamente a:
- **AF_XDP sockets** (user-space) per applicazioni custom
- **TX hardware** (trasmissione via scheda)
- **Network stack kernel** (via PASS)

## 🔄 Flusso di Elaborazione

```
┌─────────────────────────────┐
│   Pacchetto Hardware (HW)   │
└──────────────┬──────────────┘
               │
               ▼
       ┌───────────────┐
       │  BPF XDP      │
       │  Program      │
       └───────┬───────┘
               │
        ┌──────┴──────┐
        │ CLONE_TX    │
        │ (4 copie)   │
        └──────┬──────┘
        ┌──────┴────────────────────────┐
        │ Copia 1, 2, 3, 4 elaborate    │
        └──────────────────────────────┬┘
        ┌──────────────────────────────┘
        │
    ┌───┴──────────┬──────────────┬─────────────┐
    │              │              │             │
    ▼              ▼              ▼             ▼
  Copia 1      Copia 2        Copia 3      Copia 4
  (pari)       (dispari)      (pari)       (dispari)
    │              │            │             │
    ▼              ▼            ▼             ▼
 AF_XDP         TX HW        AF_XDP        TX HW
 Queue 0        Trasmetti     Queue 0       Trasmetti
 User-space   Ritorno        User-space     Ritorno
```

## 🔑 Concetti Chiave

### 1. **XDP_CLONE_TX(num_copy)**
```c
#define __XDP_CLONE_TX 6
#define XDP_CLONE_TX(num_copy) (((int)(num_copy) << 5) | (int)__XDP_CLONE_TX)
```
- Ritorna un valore speciale che indica:
  - Action: 6 (XDP_CLONE_TX)
  - Numero di copie: num_copy (negli upper 5 bit)

- Esempio: `XDP_CLONE_TX(4)` = `0x84` (4 << 5 | 6 = 132)

### 2. **BPF Map per AF_XDP**
```c
struct {
  __uint(type, BPF_MAP_TYPE_XSKMAP);
  __uint(max_entries, 64);
} xsk_map SEC(".maps");
```
- Mappa i socket AF_XDP agli indici
- L'indice corrisponde al queue_id della NIC
- Massimo 64 socket AF_XDP

### 3. **Redirezione a AF_XDP**
```c
return bpf_redirect_map(&xsk_map, cfg->afxdp_queue, 0);
```
- Carica il socket AF_XDP dalla mappa
- Invia il pacchetto agli RX ring del socket
- User-space riceve dal ring buffer

## 📊 Elaborazione Kernel

Nel kernel (mlx5e_skb_from_cqe_linear), per ogni copia:

```c
for (int i = 0; i < num_copy; i++) {
    // ... elabora copia i
    
    // Esegui il BPF program sulla copia
    actcpy = bpf_prog_run_xdp(prog, &copy_xdp[i]);
    
    // Decidi destinazione in base al risultato
    switch (actcpy) {
        case XDP_PASS:
            // Stack kernel
            napi_gro_receive(rq->cq.napi, skbcpy);
            break;
            
        case XDP_TX:
            // Trasmetti via hardware
            mlx5e_xmit_xdp_buff(rq->xdpsq, rq, &copy_xdp[i]);
            break;
            
        case XDP_REDIRECT:
            // Redirect a AF_XDP o altra interfaccia
            xdp_do_redirect(rq->netdev, xdp, prog);
            break;
    }
}
```

## 💾 BPF Map Configurazione

La mappa `config_map` permette di configurare da user-space:

```c
struct config {
  __u32 num_copies;      // Quante copie creare
  __u32 afxdp_queue;     // Quale queue per AF_XDP
  __u32 enable_afxdp;    // Abilitare redirezione?
};
```

User-space aggiorna:
```c
struct config cfg = {
    .num_copies = 4,
    .afxdp_queue = 0,
    .enable_afxdp = 1,
};
bpf_map_update_elem(config_map_fd, &key, &cfg, 0);
```

## 🎯 Decisione per Copia

Nel BPF program, per ogni copia (identificata da `num_copy`):

```c
if (cfg->enable_afxdp && num_copy % 2 == 0) {
    // Copie pari → AF_XDP
    return bpf_redirect_map(&xsk_map, cfg->afxdp_queue, 0);
} else {
    // Copie dispari → TX Hardware
    return XDP_TX;
}
```

**Schema decisionale:**
- Copia 1 (dispari): TX → Trasmetti hardware
- Copia 2 (pari): AF_XDP → User-space
- Copia 3 (dispari): TX → Trasmetti hardware
- Copia 4 (pari): AF_XDP → User-space

## 🚀 User-Space: Ricevere Pacchetti da AF_XDP

Dopo aver creato il socket AF_XDP, ricevi i pacchetti dall'RX ring:

```c
#include <xdp/xsk.h>

// Crea socket AF_XDP
struct xsk_socket *xsk = xsk_socket__create(ifname, queue_id, umem, rx_ring, 
                                            tx_ring, NULL);

// Poll sull'RX ring
struct xsk_ring_cons *rx = &xsk->rx;
while (1) {
    unsigned int idx_rx = 0, idx_fq = 0;
    
    // Leggi pacchetti disponibili
    unsigned int rcvd = xsk_ring_cons__peek(rx, BATCH_SIZE, &idx_rx);
    if (!rcvd)
        continue;
        
    // Elabora ogni pacchetto
    for (unsigned int i = 0; i < rcvd; i++) {
        uint64_t addr = xsk_ring_cons__rx_descriptor(rx, idx_rx++)->addr;
        char *pkt_data = xsk_umem__get_data(umem_buffer, addr);
        
        // Elabora pacchetto...
    }
    
    // Libera spazio nel ring
    xsk_ring_cons__release(rx, rcvd);
}
```

## ⚙️ Metadata nel Pacchetto

Il kernel passa il numero di copia nel metadata XDP:

```c
// Nel kernel (una volta per pacchetto originale):
__builtin_memcpy(&num_copy, &num_copy, sizeof(num_copy));
mxbuf.xdp.data_meta = xdp->data - sizeof(num_copy);

// Nel BPF (per ogni copia):
__builtin_memcpy(&num_copy, data_meta, sizeof(num_copy));
// num_copy ora contiene il numero della copia (1, 2, 3, 4...)
```

## 📈 Vantaggi della Clonazione con AF_XDP

| Aspetto | Beneficio |
|---------|----------|
| **Zero-copy** | I dati rimangono in memoria kernel, user-space accede tramite mmap |
| **Bassa latenza** | Nessuna copia dei dati |
| **Scalabilità** | Supporta fino a 64 socket AF_XDP in parallelo |
| **Flessibilità** | Ogni copia può andare a destinazione diversa |
| **Performance** | Usa ring buffers instead di syscall |

## 🔧 Compilazione

```bash
# Compilare il programma BPF
clang -O2 -target bpf \
  -c xdp_clone_to_afxdp.bpf.c \
  -o xdp_clone_to_afxdp.bpf.o

# Generare lo skeleton
gen_object_skels.py xdp_clone_to_afxdp.bpf.o
# Oppure manualmente
llvm-objdump -S xdp_clone_to_afxdp.bpf.o > skeleton_content
# E creare xdp_clone_to_afxdp.skel.h

# Compilare il programma user-space
gcc -o xdp_clone_to_afxdp xdp_clone_to_afxdp.c \
  -lbpf -lxdp -I/usr/include/bpf
```

## 🧪 Test

```bash
# Carica il programma (richiede root)
sudo ./xdp_clone_to_afxdp eth0

# In un altro terminale, genera traffico UDP
# verso porta 8901
socat - UDP:localhost:8901

# Monitora i pacchetti ricevuti in AF_XDP:
# (Implementa un ricevitore AF_XDP personalizzato)
```

## 📝 Note Importanti

1. **Requisiti kernel**: XDP_CLONE supportato solo in kernel 5.8+
2. **Driver**: Deve supportare XDP (Mellanox MLX5, Intel i40e, ecc.)
3. **Permissions**: Richiede CAP_SYS_ADMIN per caricare BPF
4. **Map sincronizzazione**: Aggiornare `config_map` da user-space è thread-safe
5. **Memory pool**: AF_XDP usa UMEM (user memory) separato, non condiviso con kernel

## 🎓 Riferimenti

- [XDP specification](https://www.kernel.org/doc/html/latest/networking/xdp-rx-metadata.html)
- [AF_XDP socket](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
- [BPF and XDP Documentation](https://docs.kernel.org/bpf/)
