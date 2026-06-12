# Makefile to compile all *.bpf.c files
all: tx_header.bpf.o tx_metadata_flow.bpf.o axdp_ringbuf.bpf.o axdp_rule_daemon axdp_add_rule 08_tcp_firewall.bpf.o 08_tcp_firewall_axdp.bpf.o

%.bpf.o: %.bpf.c
	clang -O2 -target bpf -g -c $< -o $@

# Userspace daemon that drains the ring buffer and replays rules via ioctl.
axdp_rule_daemon: axdp_rule_daemon.c axdp_ringbuf.h ../en_ioctl.h
	cc -Wall -O2 -o $@ axdp_rule_daemon.c -lbpf

# Userspace CLI to add/remove a single rule via the ioctl device.
axdp_add_rule: axdp_add_rule.c ../en_ioctl.h
	cc -Wall -O2 -o $@ axdp_add_rule.c

# Load the producer and pin its ring-buffer map at /sys/fs/bpf/axdp_rb.
attach-axdp_ringbuf: axdp_ringbuf.bpf.o
	sudo bpftool prog loadall axdp_ringbuf.bpf.o /sys/fs/bpf/axdp_ringbuf pinmaps /sys/fs/bpf
	sudo bpftool net attach xdpdrv name axdp_rb_producer dev ${ETH}

detach-axdp_ringbuf:
	sudo bpftool net detach xdpdrv dev ${ETH}
	sudo rm -f /sys/fs/bpf/axdp_rb
	sudo rm -rf /sys/fs/bpf/axdp_ringbuf
	sudo rm -rf /sys/fs/bpf/axdp_rin_bss

# Run the daemon (needs the producer loaded first).
run-daemon: axdp_rule_daemon
	sudo ./axdp_rule_daemon


attach-tx_header:
	sudo bpftool prog load  tx_header.bpf.o /sys/fs/bpf/tx_header
	sudo bpftool net attach xdpdrv name xdptx_header dev ${ETH}

attach-tx_metadata_flow:
	sudo bpftool prog load  tx_metadata_flow.bpf.o /sys/fs/bpf/tx_metadata_flow
	sudo bpftool net attach xdpdrv name xdptx_metadata_ dev ${ETH}

detach-tx_metadata_flow:
	sudo bpftool net detach xdpdrv dev ${ETH}
	sudo rm /sys/fs/bpf/tx_metadata_flow

detach:
	sudo bpftool net detach xdpdrv dev ${ETH}
	sudo rm /sys/fs/bpf/tx_metadata_flow
	#sudo rm /sys/fs/bpf/tx_header

.PHONY: all
