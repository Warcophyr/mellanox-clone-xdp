# clone-kfunc

Same thing as [`../clone-tx`](../clone-tx), asked for the other way: through the
`bpf_xdp_clone()` kfunc instead of encoding the number of copies in the return
value.

```c
/* here */
return bpf_xdp_clone(ctx, n_clone, ACT_CLONE_TX, XDP_PASS);

/* in ../clone-tx */
return (n_clone << 5) | ACT_CLONE_TX;
```

Both paths are supported by the driver and produce the same copies. What the
kfunc adds is that the request is checked where it is made, so three cases that
would otherwise cost the packet come back as a return value the program can act
on — here `XDP_PASS`, the fallback given in the last argument:

| the kfunc refuses when | with the encoded form |
|---|---|
| already running on a copy (nested clone) | driver returns `XDP_ABORTED`, packet dropped |
| no headroom for the copy metadata | driver returns `XDP_ABORTED`, packet dropped |
| `n_copies` is 0, or above the driver's cap | silently clamped |

It also means the count no longer travels in the return value, so a count
computed at runtime is checked just as well as a constant one.

The cost is one direct call plus a per-CPU store per cloning packet, and a
single per-CPU store on every packet (the driver resets the request slot before
each program run).

## Requirements

- the patched kernel, with the `XDP_CLONE_*` actions and the verifier checks;
- `CONFIG_DEBUG_INFO_BTF_MODULES=y`, otherwise the module has no BTF and the
  kfunc cannot be resolved;
- the patched `mlx5_core` **loaded**: libbpf resolves `bpf_xdp_clone` from that
  module's BTF, so `open_and_load()` fails if it is not there.

## Build and run

```bash
make
sudo ./xdp_clone_kfunc <ifname> [n clones]
```

Send UDP to port 8901 on that interface. The original packet is duplicated
`n clones` times; each copy is modified in the branch that reads its index from
`data_meta` and is transmitted back out, exactly as in `../clone-tx`.
