# Makefile to compile all *.bpf.c files
all: tx_header.bpf.o tx_metadata_flow.bpf.o

%.bpf.o: %.bpf.c
	clang -O2 -target bpf -c $< -o $@


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
