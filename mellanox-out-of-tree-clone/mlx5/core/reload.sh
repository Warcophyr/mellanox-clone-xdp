#!/bin/bash
make detach
sudo rmmod mlx5_core
#sudo insmod mlx5_core.ko debug=1
sudo insmod ./mlx5_core.ko
sudo ip link set ${ETH} up
sudo ethtool --set-priv-flags ${ETH} skb_tx_mpwqe off
sudo ethtool --set-priv-flags ${ETH} xdp_tx_mpwqe off
sudo ethtool --set-priv-flags ${ETH} rx_striding_rq off
#sudo devlink dev eswitch set pci/0000:81:00.0 mode switchdev
make attach
sudo ip link set ${ETH} promisc on
