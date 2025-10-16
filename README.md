# XDP_CLONE
this driver mellanox are modify version of the driver kervel ubuntu linux-headers-6.8.0-60-generic

## how to compile

```bash
make xdp_clone
```

## how to run
```bash
 ./xdp_clone <ifname>
```

## how to mount the driver
inside the mellanox-out-of-tree-clone folder the following commands

- to compile the driver
```bash
make
```
- to load the driver after a reboot
```bash
make load
```
- to load the driver after we have all ready load the driver
```bash
make reload
```
- to unload the driver and go back to the default driver
```bash
make reset
```

IMPORTANT when you load the driver by default is mounth on the lo (loop back) iterface and problabli it wont work givin back an error, you need to chang it in what iterface you need use it 
```bash
./mellanox-out.of-tree-clone/mlx5/core
```
there there is a Makefile inside there is a ETH variable change it in what iterface you need


## struct of the example
- xdp_clone.c is the code in user space how load the XDP program on the the secificate \<ifname> (xdp_clone.c)
- xdp_clone.bpf.shel.h is a header contening help function used in kfunc.c to atomatizate the load of the XDP program and all the map create on the kfunc.bpf.c (auto generate durig the compile)
- xdp_clone.bpf.c is the XDP code where we write the main logic of the program inside there is written an exaple of the XDP_CLONE_PASS and XDP_CLONE_TX


## man XDP_CLONE_PASS
```C
#define __XDP_CLONE_PASS 5
#define XDP_CLONE_PASS(num_copy) (((int)(num_copy) << 5) | (int)__XDP_CLONE_PASS)
```

- during the return code the first 5 bit we get the exit code of XDP if exit code > 4 the we see also use the remaing bit to know how may iteration we to do
- the fate of the original packet is like is doing XDP_PASS
- XDP_CLONE_PASS(10) mean make 10 copy and XDP_PASS this packet so in tottal 11 packet
- IMPORTANT each copy is the copy of the previus copy so if copy_i is modify then copy_j will have the
moidify apply to copy_i (with i < j)
- see section ID to know how to distinguish copy and not copy
- if you want to know how is implement see on folder ./mellanox-out-of-tree-clone/core file en_rx.c the fuction mlx5e_skb_from_cqe_linear


## man XDP_CLONE_TX
```C
#define __XDP_CLONE_TX 5
#define XDP_CLONE_TX(num_copy) (((int)(num_copy) << 5) | (int)__XDP_CLONE_TX)
```

- during the return code the first 5 bit we get the exit code of XDP if exit code > 4 the we see also use the remaing bit to know how may iteration we to do
- the fate of the original packet is like is doing XDP_PASS
- XDP_CLONE_TX(10) mean make 10 copy and XDP_TX this packet so in tottal 11 packet
- IMPORTANT each copy is the copy of the previus copy so if copy_i is modify then copy_j will have the
moidify apply to copy_i (with i < j)
- see section ID to know how to distinguish copy and not copy
- if you want to know how is implement see on folder ./mellanox-out-of-tree-clone/core file en_rx.c the fuction mlx5e_skb_from_cqe_linear
## ID copy
evry packet have a meta data to know if is a copy or not
- not copy packet have ID = 0
- copy packet have ID > 0
- IDs are sequenze of Int $\forall i>0 => \exists j=i-1 \land \exists! k=0 \space \land \not \exists j'=j$
this rules are must be respect every time we do a clone
- with this whe can also know at witch step of the copy we are

to extrapolate the ID 
```C
void *data = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;
void *data_meta = (void *)(long)ctx->data_meta;

if (ctx->data_meta + sizeof(__u32) <= ctx->data) {
    int id = 0;
    __builtin_memcpy(id, data_meta, sizeof(num_copy));
    return XDP_PASS;
  }
```

## Retun code for the copy
packet with ID > 0 will only accept the default retun code

```C
enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT, // still not fully support after XDP_CLONE_PASS or XDP_CLONE_TX udefine behaviour use at you on risk
};
```

using again XDP_CLONE_PASS or XDP_CLONE_TX are managed as XDP_DROP
