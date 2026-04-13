TARGET := xdp_clone

.PHONY : all clean


all: $(TARGET) 


$(TARGET):
	clang -g -O2 --target=bpf -c $@.bpf.c -o $@.bpf.o -I ./kernel_module
	bpftool gen skeleton $@.bpf.o > $@.bpf.skel.h
	gcc -g -O2 -o $@ $@.c -lbpf


clean:
	rm -f $(TARGET) $(TARGET:=.bpf.o) $(TARGET:=.bpf.skel.h)
