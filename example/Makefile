TARGETS := xdp_clone.c xdp_clone.bpf.c

.PHONY : all clean


all: $(TARGETS) 


xdp_clone: $(TARGETS)
	clang -g -O2 --target=bpf -c $@.bpf.c -o $@.bpf.o -I ./kernel_module
	bpftool gen skeleton $@.bpf.o > $@.bpf.skel.h
	gcc -g -O2 -o $@ $@.c -lbpf


clean:
	rm -f $(TARGETS) $(TARGETS:=.bpf.o) $(TARGETS:=.bpf.skel.h)
