# 📋 Sommario Implementazione: XDP Clone → AF_XDP

## ✅ File Creati

```
examples/clone/
├── xdp_clone_to_afxdp.bpf.c        [BPF Kernel] Programma XDP che clona i pacchetti
├── xdp_clone_to_afxdp.c            [User-space] Loader semplice del BPF
├── xdp_afxdp_receiver.c            [User-space] Ricevitore AF_XDP standalone
├── xdp_clone_integrated.c          [User-space] Soluzione integrata completa
├── Makefile.afxdp                  [Build] Makefile per compilare
├── XDP_CLONE_AFXDP_GUIDE.md        [Documentazione] Guida tecnica dettagliata
├── README_AFXDP.md                 [Documentazione] Guida pratica e troubleshooting
└── IMPLEMENTATION_SUMMARY.md       [Questo file] Sommario
```

## 🎯 Architettura Completata

```
┌─────────────────────────────────────────────────────────┐
│                  Hardware (NIC)                         │
│         Riceve traffico UDP su porta 8901               │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
         ┌────────────────────────┐
         │   Kernel XDP Layer     │
         │                        │
         │  xdp_clone_to_afxdp    │
         │  (xdp_clone_to_afxdp   │
         │   .bpf.c)              │
         │                        │
         │  1. Riceve pacchetto   │
         │  2. Esegue BPF prog    │
         │  3. Clona 4 volte      │
         │  4. Smista copie:      │
         │     - Copie pari       │
         │       → AF_XDP (user)  │
         │     - Copie dispari    │
         │       → TX (hardware)  │
         └────────────┬───────────┘
                      │
        ┌─────────────┴──────────────┐
        │                            │
        ▼                            ▼
   [TX Hardware]            [AF_XDP Ring Buffers]
   Trasmissione             ↓
   Hardware-accelerated  [User-space]
   (Low latency)
   
        ↓
   [User-space Socket]
   
   3 opzioni per ricevere:
   1. xdp_clone_to_afxdp.c
      └─ Loader semplice
   
   2. xdp_afxdp_receiver.c
      └─ Ricevitore standalone
   
   3. xdp_clone_integrated.c
      └─ Soluzione completa integrata
```

## 🚀 Utilizzo Rapido

### Scenario 1: Solo BPF Loading (Minimalista)

```bash
cd examples/clone
make -f Makefile.afxdp xdp_clone_to_afxdp
sudo ./xdp_clone_to_afxdp eth0
```

**Pro**: Semplice, minimale  
**Contro**: Non riceve i dati, solo configura il kernel

---

### Scenario 2: BPF + Ricevitore Standalone

Terminal 1:
```bash
sudo ./xdp_clone_to_afxdp eth0
```

Terminal 2:
```bash
make -f Makefile.afxdp xdp_afxdp_receiver
sudo ./xdp_afxdp_receiver eth0 0
```

**Pro**: Separazione tra loader e ricevitore  
**Contro**: Necessita due programmi separati

---

### Scenario 3: Soluzione Integrata (Consigliata)

```bash
make -f Makefile.afxdp xdp_clone_integrated
sudo ./xdp_clone_integrated eth0
```

**Pro**: Tutto in uno, completo, multipli socket AF_XDP  
**Contro**: Più codice C

---

## 🔍 Flusso Dettagliato

### Fase 1: Kernel (XDP BPF Program)

```c
// In xdp_clone_to_afxdp.bpf.c

int xdp_clone_to_afxdp(struct xdp_md *ctx) {
    // 1. Valida pacchetto
    // 2. Filtra solo UDP:8901
    
    if (num_copy == 0) {
        // Pacchetto originale: decide di clonare
        return XDP_CLONE_TX(4);  // Crea 4 copie
    } else if (num_copy > 0) {
        // Copia successiva
        if (num_copy % 2 == 0) {
            // Pari → AF_XDP
            return bpf_redirect_map(&xsk_map, 0, 0);
        } else {
            // Dispari → TX
            return XDP_TX;
        }
    }
}
```

**Risultato**:
- Copia 1 (dispari) → TX (trasmissione hardware)
- Copia 2 (pari) → AF_XDP (user-space)
- Copia 3 (dispari) → TX (trasmissione hardware)
- Copia 4 (pari) → AF_XDP (user-space)

---

### Fase 2: Kernel (Driver MLX5)

Nel `mellanox-clone-xdp/mellanox-out-of-tree-clone/mlx5/core/en_rx.c`:

```c
// Per ogni copia (in case XDP_CLONE_TX):
for (int i = 0; i < num_copy; i++) {
    // Alloca buffer
    page[i] = page_pool_dev_alloc_pages(rq->page_pool);
    
    // Copia dati
    __builtin_memcpy(copy_va[i], va, rx_headroom + cqe_bcnt);
    
    // Esegui BPF program sulla copia
    actcpy = bpf_prog_run_xdp(prog, &copy_xdp[i]);
    
    // Smista in base al risultato
    switch (actcpy) {
        case XDP_TX:
            mlx5e_xmit_xdp_buff(rq->xdpsq, rq, &copy_xdp[i]);
            break;
        case XDP_REDIRECT:
            xdp_do_redirect(rq->netdev, xdp, prog);
            break;
        // ...
    }
}
```

---

### Fase 3: User-space (Ricevitore AF_XDP)

In `xdp_afxdp_receiver.c` o `xdp_clone_integrated.c`:

```c
// 1. Crea UMEM (User Memory)
umem = configure_umem(buffer, size);

// 2. Crea socket AF_XDP legato a queue
xsk = xsk_socket__create(ifname, queue_id, umem, ...);

// 3. Registra nel BPF xsk_map
bpf_map_update_elem(xsk_map_fd, &queue_id, &xsk_fd, 0);

// 4. Poll e ricevi pacchetti
while (1) {
    rcvd = xsk_ring_cons__peek(rx, BATCH_SIZE, &idx);
    for (i = 0; i < rcvd; i++) {
        pkt = xsk_umem__get_data(umem, desc[i].addr);
        // Elabora pacchetto
    }
}
```

---

## 📊 Confronto tra le Implementazioni

| Aspetto | xdp_clone_to_afxdp.c | xdp_afxdp_receiver.c | xdp_clone_integrated.c |
|---------|----------------------|----------------------|------------------------|
| Linee di codice | ~120 | ~230 | ~380 |
| BPF caricamento | ✅ | ❌ | ✅ |
| Riceve pacchetti | ❌ | ✅ | ✅ |
| Multi-socket | ❌ | ❌ | ✅ (4 socket) |
| Complexità | Bassa | Media | Alta |
| Scopo | Test setup | Ricevitore standalone | Produzione |
| Learning curve | Facile | Medio | Complesso |

---

## 🔧 Personalizzazione

### Cambiare numero di copie

**File**: `xdp_clone_to_afxdp.bpf.c`

```c
// Linea ~130:
int xdp_clone_to_afxdp(struct xdp_md *ctx) {
    // ...
    if (num_copy == 0) {
        // Cambia 4 → numero di copie desiderato
        return XDP_CLONE_TX(6);  // 6 copie invece di 4
    }
}
```

**Oppure da user-space**:

```c
struct config cfg = {
    .num_copies = 8,  // 8 copie
    .afxdp_queue = 0,
    .enable_afxdp = 1,
};
bpf_map_update_elem(config_map_fd, &key, &cfg, 0);
```

### Cambiare logica di smistamento

Nel BPF program, modifica la decisione per copia:

```c
// Attuale: pari → AF_XDP, dispari → TX
if (num_copy % 2 == 0) {
    return bpf_redirect_map(&xsk_map, cfg->afxdp_queue, 0);
}

// Alternativa 1: Prime 2 → AF_XDP, resto → TX
if (num_copy <= 2) {
    return bpf_redirect_map(&xsk_map, cfg->afxdp_queue, 0);
}

// Alternativa 2: Base su IP destination
if (iph->daddr & 0x00000001) {  // IP destination pari
    return bpf_redirect_map(&xsk_map, cfg->afxdp_queue, 0);
}

// Alternativa 3: Base su porta UDP
if (bpf_ntohs(udph->dest) == 8901) {
    return bpf_redirect_map(&xsk_map, cfg->afxdp_queue, 0);
}
```

### Aggiungere filtri packet

Nel BPF program, aggiungi filtri prima della clonazione:

```c
// Solo per source IP specifico
if (iph->saddr != htonl(0x7f000001)) {  // 127.0.0.1
    return XDP_PASS;
}

// Solo per range di porte
__u32 sport = bpf_ntohs(udph->source);
if (sport < 10000 || sport > 20000) {
    return XDP_PASS;
}

// Solo per specifico tipo di payload
if (pkt_len < MIN_PAYLOAD_SIZE) {
    return XDP_PASS;
}
```

---

## 📈 Performance Considerations

### Memoria
- UMEM: `NUM_FRAMES * FRAME_SIZE * 2` = 32 MB (default)
- Ridurre per sistemi embedded
- Aumentare per throughput elevato

### CPU
- AF_XDP è single-thread per queue
- Usare multiple queue per parallelismo
- Legare a CPU core specifica con `taskset`

### Latenza
```bash
# Misura latenza di ricezione
sudo ./xdp_clone_integrated eth0 2>&1 | grep -o "\[.*\]"
```

### Throughput
```bash
# Generate traffico massivo
iperf3 -c localhost -u -b 10G -p 8901
```

---

## 🐛 Debugging

### 1. Verifica caricamento BPF

```bash
sudo ip link show dev eth0 | grep xdp
# Output: xdp/id:123

sudo bpftool prog list | grep xdp_clone
```

### 2. Monitora kernel logs

```bash
sudo tail -f /sys/kernel/debug/tracing/trace_pipe | grep "xdp_clone"
```

### 3. Visualizza map

```bash
# xsk_map
sudo bpftool map dump name xsk_map

# config_map
sudo bpftool map dump name config_map
```

### 4. Test con tcpdump

```bash
sudo tcpdump -i eth0 -nn udp port 8901 -v
```

---

## 📚 Prossimi Passi

1. **Produttività**: Usa `xdp_clone_integrated.c` come base
2. **Performance**: Tuning di FRAME_SIZE e NUM_FRAMES
3. **Scalabilità**: Aggiungi support per multiple interfacce
4. **Reliability**: Implementa error handling
5. **Monitoring**: Aggiungi statistiche e metriche

---

## 🎓 Concetti Approfonditi

### XDP_CLONE Encoding

```c
XDP_CLONE_TX(num_copy) = (num_copy << 5) | 6

// Esempio:
XDP_CLONE_TX(4) = (4 << 5) | 6 = 128 + 6 = 134

// Nel driver:
int __num_copy = act >> 5;       // Estrai numero copie
int __xdp_action = act & 0x1F;   // Estrai azione (6)
```

### Metadata XDP

```c
// Nel kernel (mlx5e_skb_from_cqe_linear):
mxbuf.xdp.data_meta = xdp->data - sizeof(num_copy);
__builtin_memcpy(mxbuf.xdp.data_meta, &num_copy, sizeof(num_copy));

// Nel BPF program:
if (ctx->data_meta + sizeof(__u32) <= ctx->data) {
    __u32 num_copy = 0;
    __builtin_memcpy(&num_copy, data_meta, sizeof(num_copy));
    // num_copy contiene il numero della copia (0, 1, 2, 3...)
}
```

---

## 📖 Riferimenti Utili

- [Kernel XDP Documentation](https://www.kernel.org/doc/html/latest/networking/xdp-rx-metadata.html)
- [AF_XDP Socket](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
- [libbpf API](https://libbpf.readthedocs.io/)
- [libxdp](https://github.com/xdp-project/xdp-tools)
- [MLX5 XDP Support](https://github.com/torvalds/linux/tree/master/drivers/net/ethernet/mellanox/mlx5)

---

**Creato**: Aprile 2026  
**Kernel minimo richiesto**: 5.8+  
**Driver supportati**: MLX5, i40e, ice, ixgbe  
**Architetture**: x86_64, ARM64

