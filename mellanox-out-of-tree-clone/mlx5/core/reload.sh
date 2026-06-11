#!/bin/bash
make detach
sudo rmmod mlx5_core
sudo insmod ./mlx5_core.ko
sudo ip link set ${ETH} up
sudo ethtool --set-priv-flags ${ETH} skb_tx_mpwqe off
sudo ethtool --set-priv-flags ${ETH} xdp_tx_mpwqe off
sudo ethtool --set-priv-flags ${ETH} rx_striding_rq off
make attach
sudo ip link set ${ETH} promisc on
