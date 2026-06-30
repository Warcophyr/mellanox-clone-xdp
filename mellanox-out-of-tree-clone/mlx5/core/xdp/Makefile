# Makefile to compile all *.bpf.c files
all: tx_header.bpf.o tx_metadata_flow.bpf.o axdp_firewall.bpf.o axdp_firewall_test.bpf.o axdp_telemetry.bpf.o axdp_telemetry_test.bpf.o axdp_policer.bpf.o axdp_policer_test.bpf.o axdp_rule_daemon axdp_add_rule

%.bpf.o: %.bpf.c
	clang -O2 -target bpf -g -c $< -o $@

# Two variants from the same axdp_firewall.bpf.c source:
#   axdp_firewall.bpf.o      -- plain firewall (AXDP_TEST off)
#   axdp_firewall_test.bpf.o -- id/conn_state accelerated path (AXDP_TEST on)
axdp_firewall.bpf.o: axdp_firewall.bpf.c
	clang -O2 -target bpf -g -c $< -o $@

axdp_firewall_test.bpf.o: axdp_firewall.bpf.c
	clang -O2 -target bpf -g -DAXDP_TEST -c $< -o $@

# Two variants from the same axdp_telemetry.bpf.c source:
#   axdp_telemetry.bpf.o      -- plain per-packet telemetry (AXDP_TEST off)
#   axdp_telemetry_test.bpf.o -- id/conn_state accelerated path (AXDP_TEST on)
axdp_telemetry.bpf.o: axdp_telemetry.bpf.c
	clang -O2 -target bpf -g -c $< -o $@

axdp_telemetry_test.bpf.o: axdp_telemetry.bpf.c
	clang -O2 -target bpf -g -DAXDP_TEST -c $< -o $@

# Two variants from the same axdp_policer.bpf.c source:
#   axdp_policer.bpf.o      -- plain token-bucket policer (AXDP_TEST off)
#   axdp_policer_test.bpf.o -- id/ft_metadata accelerated path (AXDP_TEST on)
axdp_policer.bpf.o: axdp_policer.bpf.c
	clang -O2 -target bpf -g -c $< -o $@

axdp_policer_test.bpf.o: axdp_policer.bpf.c
	clang -O2 -target bpf -g -DAXDP_TEST -c $< -o $@

# Userspace daemon that drains the ring buffer and replays rules via ioctl.
axdp_rule_daemon: axdp_rule_daemon.c axdp_ringbuf.h ../en_ioctl.h
	cc -Wall -O2 -o $@ axdp_rule_daemon.c -lbpf

# Userspace CLI to add/remove a single rule via the ioctl device.
axdp_add_rule: axdp_add_rule.c ../en_ioctl.h
	cc -Wall -O2 -o $@ axdp_add_rule.c

# Load the plain producer and pin its ring-buffer map at /sys/fs/bpf/axdp_rb.
attach-axdp_firewall: axdp_firewall.bpf.o
	sudo bpftool prog loadall axdp_firewall.bpf.o /sys/fs/bpf/axdp_ringbuf pinmaps /sys/fs/bpf
	sudo bpftool net attach xdpdrv name axdp_rb_producer dev ${ETH}

detach-axdp_firewall:
	sudo bpftool net detach xdpdrv dev ${ETH}
	sudo rm -f /sys/fs/bpf/conntrack /sys/fs/bpf/conn_by_id /sys/fs/bpf/id_gen
	sudo rm /sys/fs/bpf/axdp_fir_rodata
	sudo rm /sys/fs/bpf/axdp_ringbuf

# Load the AXDP_TEST producer (id/conn_state accelerated path).
attach-axdp_firewall_test: axdp_firewall_test.bpf.o
	sudo bpftool prog loadall axdp_firewall_test.bpf.o /sys/fs/bpf/axdp_ringbuf pinmaps /sys/fs/bpf
	sudo bpftool net attach xdpdrv name axdp_rb_producer dev ${ETH}

detach-axdp_firewall_test:
	sudo bpftool net detach xdpdrv dev ${ETH}
	sudo rm -f /sys/fs/bpf/conntrack /sys/fs/bpf/conn_by_id /sys/fs/bpf/id_gen
	sudo rm /sys/fs/bpf/axdp_fir_rodata
	sudo rm /sys/fs/bpf/axdp_ringbuf

# Load the plain telemetry producer and pin its ring-buffer map at /sys/fs/bpf/axdp_rb.
attach-axdp_telemetry: axdp_telemetry.bpf.o
	sudo bpftool prog loadall axdp_telemetry.bpf.o /sys/fs/bpf/axdp_ringbuf pinmaps /sys/fs/bpf
	sudo bpftool net attach xdpdrv name axdp_telemetry dev ${ETH}

detach-axdp_telemetry:
	sudo bpftool net detach xdpdrv dev ${ETH}
	sudo rm -f /sys/fs/bpf/telemetry /sys/fs/bpf/conn_by_id /sys/fs/bpf/id_gen
	sudo rm -f /sys/fs/bpf/axdp_ringbuf

# Load the AXDP_TEST telemetry producer (id/conn_state accelerated path).
attach-axdp_telemetry_test: axdp_telemetry_test.bpf.o
	sudo bpftool prog loadall axdp_telemetry_test.bpf.o /sys/fs/bpf/axdp_ringbuf pinmaps /sys/fs/bpf
	sudo bpftool net attach xdpdrv name axdp_telemetry dev ${ETH}

detach-axdp_telemetry_test:
	sudo bpftool net detach xdpdrv dev ${ETH}
	sudo rm -f /sys/fs/bpf/telemetry /sys/fs/bpf/conn_by_id /sys/fs/bpf/id_gen
	sudo rm -f /sys/fs/bpf/axdp_ringbuf

# Token-bucket rate policer. Per-packet program; conforming traffic -> XDP_TX,
# non-conforming -> XDP_TX2 (low-priority second XDP SQ). Pins its bucket map.
attach-axdp_policer: axdp_policer.bpf.o
	sudo bpftool prog loadall axdp_policer.bpf.o /sys/fs/bpf/axdp_policer pinmaps /sys/fs/bpf
	sudo bpftool net attach xdpdrv name xdp_policer dev ${ETH}

detach-axdp_policer:
	sudo bpftool net detach xdpdrv dev ${ETH}
	sudo rm -f /sys/fs/bpf/buckets
	sudo rm -rf /sys/fs/bpf/axdp_policer

# AXDP_TEST policer: id/ft_metadata accelerated path. Also pins the ring buffer
# and conn_by_id/id_gen maps, and needs the rule daemon running to install rules.
attach-axdp_policer_test: axdp_policer_test.bpf.o
	sudo bpftool prog loadall axdp_policer_test.bpf.o /sys/fs/bpf/axdp_policer pinmaps /sys/fs/bpf
	sudo bpftool net attach xdpdrv name xdp_policer dev ${ETH}

detach-axdp_policer_test:
	sudo bpftool net detach xdpdrv dev ${ETH}
	sudo rm -f /sys/fs/bpf/buckets /sys/fs/bpf/conn_by_id /sys/fs/bpf/id_gen
	sudo rm -f /sys/fs/bpf/axdp_ringbuf
	sudo rm -rf /sys/fs/bpf/axdp_policer

# Run the daemon (needs the producer loaded first).
run-daemon: axdp_rule_daemon
	sudo ./axdp_rule_daemon


attach-tx_header:
	sudo bpftool prog load  tx_header.bpf.o /sys/fs/bpf/tx_header
	sudo bpftool net attach xdpdrv name xdptx_header dev ${ETH}

attach-tx_metadata_flow:
	sudo bpftool prog load  tx_metadata_flow.bpf.o /sys/fs/bpf/tx_metadata_flow
	sudo bpftool net attach xdpdrv name xdptx_metadata_flow dev ${ETH}

detach-tx_metadata_flow:
	sudo bpftool net detach xdpdrv dev ${ETH}
	sudo rm /sys/fs/bpf/tx_metadata_flow

detach:
	sudo bpftool net detach xdpdrv dev ${ETH}
	sudo rm -f /sys/fs/bpf/conntrack /sys/fs/bpf/conn_by_id /sys/fs/bpf/id_gen
	sudo rm -rf /sys/fs/bpf/axdp_fir_rodata
	sudo rm -rf /sys/fs/bpf/axdp_ringbuf
	sudo rm -rf /sys/fs/bpf/axdp_rb
	#sudo rm /sys/fs/bpf/tx_header
	sudo rm -rf /sys/fs/bpf/tx_metadata_flow

.PHONY: all
