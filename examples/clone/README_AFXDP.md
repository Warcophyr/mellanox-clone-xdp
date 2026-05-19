# XDP Clone to AF_XDP - Implementazione Completa

## 📦 File Creati

1. **xdp_clone_to_afxdp.bpf.c** - Programma BPF XDP che effettua clonazione e redirezione
2. **xdp_clone_to_afxdp.c** - Programma user-space che carica il BPF
3. **xdp_afxdp_receiver.c** - Ricevitore AF_XDP per catturare i pacchetti clonati
4. **XDP_CLONE_AFXDP_GUIDE.md** - Documentazione dettagliata
5. **Makefile.afxdp** - Makefile per compilare

## 🎯 Architettura

```
┌─────────────────────────────────────────────┐
│         Hardware Mellanox MLX5              │
│      (Riceve traffico UDP:8901)             │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │  Programma BPF XDP   │
        │  (xdp_clone_to_*)    │
        │                      │
        │  Clona 4 volte:      │
        │  - Copia 1: TX       │
        │  - Copia 2: AF_XDP   │
        │  - Copia 3: TX       │
        │  - Copia 4: AF_XDP   │
        └──────────────────────┘
                 │
        ┌────────┴──────────┐
        │                   │
        ▼                   ▼
    [TX Hardware]    [AF_XDP Ring]
    Trasmissione      User-Space
                     (ricevitore)
```

## 🚀 Quick Start

### 1. Compilazione

```bash
cd examples/clone

# Compilare il BPF program e il loader
make -f Makefile.afxdp

# Oppure compilare il ricevitore AF_XDP
gcc -o xdp_afxdp_receiver xdp_afxdp_receiver.c \
    -I/usr/include/xdp -I/usr/include/bpf \
    -lxdp -lbpf -lz
```

### 2. Caricamento del Programma

```bash
# Carica il programma BPF su eth0
sudo ./xdp_clone_to_afxdp eth0

# Output atteso:
# Loading XDP clone-to-AF_XDP program on eth0 (ifindex: 2)
# XDP program attached successfully
# Configuration updated in BPF map
#   - num_copies: 4
#   - afxdp_queue: 0
#   - enable_afxdp: 1
# XDP clone-to-AF_XDP program is running...
```

### 3. Avvio del Ricevitore AF_XDP (in altro terminale)

```bash
# Avvia il ricevitore su eth0, queue 0
sudo ./xdp_afxdp_receiver eth0 0

# Output atteso:
# AF_XDP Ricevitore
# Interface: eth0 (ifindex=2)
# Queue: 0
# UMEM configurato: 16777216 bytes
# Socket AF_XDP creato e legato
# In ascolto di pacchetti clonati (Ctrl+C per uscire)...
```

### 4. Generazione Traffico di Test

```bash
# In un terzo terminale, genera traffico UDP verso porta 8901
# Opzione 1: con iperf
iperf3 -c localhost -p 8901 -u -b 1M

# Opzione 2: con socat
socat - UDP:localhost:8901

# Opzione 3: con netcat
nc -u localhost 8901

# Oppure con un semplice script Python:
python3 << 'EOF'
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.connect(("127.0.0.1", 8901))
for i in range(10):
    sock.send(b"Test packet " + str(i).encode())
    print(f"Sent packet {i}")
sock.close()
EOF
```

## 📊 Osservazione del Comportamento

### Nel Ricevitore AF_XDP:

```
Ricevuti 2 pacchetti:

Pacchetto 1: 58 bytes
  Ethernet: 00:16:3e:aa:bb:cc -> ff:ff:ff:ff:ff:ff
  IP: 127.0.0.1 -> 127.0.0.3
  Protocol: 17, TTL: 64
  UDP: port 8901 -> 12345

Pacchetto 2: 58 bytes
  Ethernet: 00:16:3e:aa:bb:cc -> ff:ff:ff:ff:ff:ff
  IP: 127.0.0.1 -> 127.0.0.5
  Protocol: 17, TTL: 64
  UDP: port 8901 -> 12345
```

**Nota**: Ricevi solo le copie pari (modificate) perché:
- Copia 2: AF_XDP (pari) ✓
- Copia 4: AF_XDP (pari) ✓
- Copie 1,3: TX (dispari) → Hardware

### Nel Kernel (con trace_printk)

```bash
# Monitora l'output del BPF:
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "xdp_clone"

# Output atteso:
# <idle>-0     [000] d.s.  1234.567890: bpf: XDP: Pacchetto ricevuto, num_copy=0
# <idle>-0     [000] d.s.  1234.567891: bpf: XDP: CLONE_TX con 4 copie (AF_XDP enabled)
# <idle>-0     [000] d.s.  1234.567892: bpf: XDP: Elaborando copia 1
# <idle>-0     [000] d.s.  1234.567892: bpf: XDP: Copia 1 -> TX
# <idle>-0     [000] d.s.  1234.567893: bpf: XDP: Elaborando copia 2
# <idle>-0     [000] d.s.  1234.567893: bpf: XDP: Copia 2 -> AF_XDP queue 0
```

## 🔧 Configurazione

Modifica il comportamento in `xdp_clone_to_afxdp.c`:

```c
struct config cfg = {
    .num_copies = 4,       // Cambia numero di copie
    .afxdp_queue = 0,      // Cambia queue AF_XDP
    .enable_afxdp = 1,     // 0 per disabilitare AF_XDP
};
```

## 🐛 Debugging

### 1. Verifica il caricamento del BPF

```bash
sudo ip link show dev eth0 | grep xdp
# Output: xdp/id:42

# O con bpftool:
sudo bpftool net list
```

### 2. Monitora le statistiche XDP

```bash
sudo ethtool -S eth0 | grep -i xdp
# Mostra: XDP_DROP, XDP_TX, XDP_PASS, etc.
```

### 3. Controlla i pacchetti ricevuti da AF_XDP

```bash
# Capture con tcpdump
sudo tcpdump -i eth0 udp port 8901

# Oppure con nftrace
sudo nftrace -i eth0
```

### 4. Visualizza i BPF map

```bash
# Lista tutti i map
sudo bpftool map list

# Leggi config_map
sudo bpftool map dump name config_map

# Leggi xsk_map
sudo bpftool map dump name xsk_map
```

## ⚠️ Limitazioni e Considerazioni

1. **Una sola interfaccia**: Il programma BPF nel kernel vede una sola interfaccia alla volta
2. **AF_XDP single-queue**: Ogni ricevitore AF_XDP è legato a una queue specifica
3. **Zero-copy**: I dati rimangono in kernel, AF_XDP accede tramite mmap
4. **CPU affinity**: Per performance, legare i processi a CPU specifiche
5. **Memory pool**: UMEM è separato tra kernel e user-space

## 🎓 Approfondimenti

### Modificare la Logica di Clonazione

Nel BPF program `xdp_clone_to_afxdp.bpf.c`, modifica la logica di instradamento:

```c
// Esempio: alternare le copie
if (num_copy % 2 == 0) {
    // Pari: AF_XDP
    return bpf_redirect_map(&xsk_map, cfg->afxdp_queue, 0);
} else {
    // Dispari: TX
    return XDP_TX;
}

// Oppure: AF_XDP solo per copie specifiche
if (num_copy == 2 || num_copy == 4) {
    return bpf_redirect_map(&xsk_map, cfg->afxdp_queue, 0);
} else {
    return XDP_TX;
}

// O: AF_XDP based su IP destination
if (iph->daddr & 0x00000001) {  // IP pari
    return bpf_redirect_map(&xsk_map, cfg->afxdp_queue, 0);
} else {
    return XDP_TX;
}
```

### Collegare Più Socket AF_XDP

Nel `config_map`, puoi gestire multiple queue:

```c
struct config {
  __u32 num_copies;
  __u32 afxdp_queues[4];  // Array di queue per diverse destinazioni
  __u32 num_queues;
};

// Nel BPF:
__u32 queue_idx = num_copy % cfg->num_queues;
return bpf_redirect_map(&xsk_map, cfg->afxdp_queues[queue_idx], 0);
```

## 📚 Riferimenti Utili

- [XDP Specification](https://www.kernel.org/doc/html/latest/networking/xdp-rx-metadata.html)
- [AF_XDP Socket](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
- [libbpf Documentation](https://libbpf.readthedocs.io/)
- [libxdp Documentation](https://github.com/xdp-project/xdp-tools/tree/master/lib/libxdp)

## 🆘 Troubleshooting

### "Permission denied" durante il caricamento

```bash
# Richiede root per caricare BPF
sudo ./xdp_clone_to_afxdp eth0
```

### "No such file or directory" per i .skel.h

```bash
# Rigenera gli skeleton:
bpftool gen skeleton xdp_clone_to_afxdp.bpf.o > xdp_clone_to_afxdp.bpf.skel.h
```

### I pacchetti non arrivano al ricevitore

1. Verifica che `enable_afxdp = 1` in config
2. Controlla l'ifindex corretto: `ip link show dev <interface>`
3. Assicurati che la porta UDP sia 8901
4. Monitora con `tcpdump`

### "Device not found"

```bash
# Verifica disponibilità di AF_XDP sul driver:
ethtool -i eth0 | grep driver
# I driver supportati: i40e, ice, ixgbe, mlx5, mlx4...
```

