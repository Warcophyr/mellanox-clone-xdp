CLANG        := clang
GCC          := gcc
# KFLAGS       := -O2 -g -target bpf
UFLAGS       := -O3 -Wall 
GDB          := -g -fsanitize=address -fno-omit-frame-pointer
LIBS         := -lbpf -lelf -lz -lxdp -lm

# KOBJ         := xdp_prog_kern.o
# KMAP         := xdp_map_mpi.o
# ULOADER      := xdp_loader
# MPI     	 := MPI
# KERNELMODULE := kernel_module_xdp.ko
TARGETS := xdp_clone.c xdp_clone.bpf.c

.PHONY : all clean


all: $(TARGETS) 


# $(KOBJ): xdp_prog_kern.c
# 	$(CLANG) $(KFLAGS) -c $< -o $@ -I ../XDP-MPI-Collectives/kernel_module

# $(KMAP): xdp_map_mpi.c
# 	$(CLANG) $(KFLAGS) -c $< -o $@

# $(ULOADER): xdp_loader.c $(KOBJ)
# 	$(GCC) $(UFLAGS) $< -o $@ $(LIBS)

# $(MPI): MPI.c 
# 	$(GCC) $(UFLAGS) $< -o $@ $(LIBS)

MPI: ./MPI.c
	$(GCC) $(UFLAGS) $< -o $@ $(LIBS)

xdp_clone: $(TARGETS)
	clang -g -O2 --target=bpf -c $@.bpf.c -o $@.bpf.o -I ./kernel_module
	bpftool gen skeleton $@.bpf.o > $@.bpf.skel.h
	gcc -g -O2 -o $@ $@.c -lbpf

run:
	sudo ./MPI -n 4 -i enp52s0f1np1

clean:
	rm -f MPI
# 	rm -f $(KOBJ) $(ULOADER)
	rm -f $(TARGETS) $(TARGETS:=.bpf.o) $(TARGETS:=.bpf.skel.h)
