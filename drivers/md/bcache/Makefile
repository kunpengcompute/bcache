# SPDX-License-Identifier: GPL-2.0

obj-m	+= bcache.o

bcache-y		:= alloc.o bset.o btree.o closure.o debug.o extents.o\
	io.o journal.o movinggc.o request.o stats.o super.o sysfs.o trace.o\
	util.o writeback.o

CFLAGS_request.o	+= -Iblock

ARCH=arm64
KERNEL_DIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	make -C $(KERNEL_DIR) M=$(PWD) ARCH=$(ARCH) modules

clean:
	rm *.o *.ko *.mod.c
