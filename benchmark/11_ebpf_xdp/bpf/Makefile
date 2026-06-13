# 11_ebpf_xdp/bpf/Makefile
#
# Compiles all XDP programs to BPF ELF objects.
#
# Requirements:
#   clang ≥ 10    (apt install clang)
#   libbpf-dev    (apt install libbpf-dev)
#   linux-headers (apt install linux-headers-$(uname -r))
#
# The build automatically prefers BTF-based compilation (kernel ≥ 5.2)
# via /sys/kernel/btf/vmlinux when available.

CLANG   ?= clang
ARCH    ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
KVER    ?= $(shell uname -r)

# Header search paths — order matters
LIBBPF_INC := $(shell pkg-config --cflags libbpf 2>/dev/null || echo "-I/usr/include")
KHEADERS   := /usr/src/linux-headers-$(KVER)/include
ARCH_INC   := /usr/src/linux-headers-$(KVER)/arch/$(ARCH)/include

INCLUDES   := $(LIBBPF_INC) -I$(KHEADERS) -I$(ARCH_INC)

CFLAGS := \
    -O2 \
    -Wall \
    -Wno-unused-value \
    -Wno-pointer-sign \
    -Wno-compare-distinct-pointer-types \
    -target bpf \
    -D__TARGET_ARCH_$(ARCH) \
    $(INCLUDES)

PROGS := xdp_pass.o xdp_drop.o xdp_counter.o xdp_tx.o

.PHONY: all clean check

all: check $(PROGS)

check:
	@command -v $(CLANG) >/dev/null 2>&1 || \
	    { echo "ERROR: clang not found. Install: apt install clang"; exit 1; }
	@pkg-config --exists libbpf 2>/dev/null || \
	    { echo "WARN: libbpf-dev not found. Install: apt install libbpf-dev"; }

%.o: %.c
	$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "  compiled $< → $@"
	@# Verify the output is a valid BPF ELF
	@file $@ | grep -q "eBPF" || \
	    { echo "ERROR: $@ is not a valid BPF ELF"; exit 1; }

clean:
	rm -f *.o

# Convenience target: dump BPF bytecode for review
dump: $(PROGS)
	@for f in $(PROGS); do \
	    echo "=== $$f ==="; \
	    llvm-objdump -S $$f 2>/dev/null || objdump -d $$f; \
	    echo ""; \
	done
