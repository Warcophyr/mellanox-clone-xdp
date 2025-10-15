# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the Mellanox device drivers.
#

.PHONY: all reload load reset clean

all:
	@echo "Building Mellanox device drivers..."
	( cd ./mlx5/core; $(MAKE) )

reload:
	@echo "Reloading Mellanox device drivers..."
	( cd ./mlx5/core; $(MAKE) reload )

load:
	@echo "Loading Mellanox device drivers..."
	sudo rmmod mlx5_ib
	( cd ./mlx5/core; $(MAKE) reload )

reset:
	@echo "Resetting to standard Mellanox drivers..."
	( cd ./mlx5/core; $(MAKE) reset )

clean:
	@echo "Cleaning Mellanox device drivers..."
	( cd ./mlx5/core; $(MAKE) clean )
