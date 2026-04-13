# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the Mellanox device drivers.
#

.PHONY: all reload load reset clean

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	@echo "Building Mellanox device drivers..."
	( cd ./mlx5/core; $(MAKE) KDIR=$(KDIR) )

reload:
	@echo "Reloading Mellanox device drivers..."
	( cd ./mlx5/core; $(MAKE) reload )

load:
	@echo "Loading Mellanox device drivers..."
	-sudo rmmod mlx5_ib
	-sudo rmmod mlx5_fwctl
	( cd ./mlx5/core; $(MAKE) reload )

reset:
	@echo "Resetting to standard Mellanox drivers..."
	( cd ./mlx5/core; $(MAKE) reset )

clean:
	@echo "Cleaning Mellanox device drivers..."
	( cd ./mlx5/core; $(MAKE) KDIR=$(KDIR) clean )
