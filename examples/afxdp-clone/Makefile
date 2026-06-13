TARGET := afxdp_clone

.PHONY : all clean

DEBUG ?= 0

CFLAGS := -g -O2 $(shell pkg-config --cflags libxdp libbpf)
LDFLAGS := $(shell pkg-config --libs libxdp libbpf) -lz

all:
	clang -g -O2 --target=bpf -c $(TARGET).bpf.c -o $(TARGET).bpf.o -DDEBUG=$(DEBUG)
	bpftool gen skeleton $(TARGET).bpf.o > $(TARGET).bpf.skel.h
	gcc $(CFLAGS) -o $(TARGET) $(TARGET).c $(LDFLAGS)

clean:
	rm -f $(TARGET) $(TARGET:=.bpf.o) $(TARGET:=.bpf.skel.h)
