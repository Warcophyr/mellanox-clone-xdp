// SPDX-License-Identifier: GPL-2.0
//
// xdp_tx.c — MAC-swap + XDP_TX (packet bounce)
//
// Purpose: bounce every received packet straight back to the sender.
// This exercises the driver's XDP_TX path — the fast-path that recycles
// the RX buffer directly into the TX ring without going through the
// kernel's socket layer.
//
// How to use:
//   1. Load on the DUT.
//   2. Send ICMP pings from the peer: ping -f -c 100000 <DUT_IP>
//   3. Measure RTT — this is: peer TX → DUT XDP_TX → peer RX, with
//      no kernel involvement on the DUT side.
//   4. Compare against sockperf ping-pong to quantify the XDP_TX
//      advantage over the normal TX path.
//
// Note: Only swap Ethernet addresses — do NOT modify IP addresses.
// The peer's IP stack will still recognise the bounced ICMP reply.
//
// Safety: XDP_TX requires the NIC to support transmitting on the same
// queue it received on (most Mellanox NICs do).  If it fails to attach,
// the driver does not support XDP_TX recycling — log that as a finding.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_tx_prog(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;   // malformed frame — let the stack deal with it

    /* Swap src/dst MAC so the bounced frame reaches the original sender */
    __u8 tmp[ETH_ALEN];
    __builtin_memcpy(tmp,            eth->h_dest,   ETH_ALEN);
    __builtin_memcpy(eth->h_dest,   eth->h_source,  ETH_ALEN);
    __builtin_memcpy(eth->h_source,  tmp,            ETH_ALEN);

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
