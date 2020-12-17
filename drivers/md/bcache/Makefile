# SPDX-License-Identifier: GPL-2.0

obj-m += bcache.o

bcache-y		:= alloc.o bset.o btree.o closure.o debug.o extents.o\
	io.o journal.o movinggc.o interface.o request.o stats.o prefetch.o super.o sysfs.o trace.o\
	util.o writeback.o ftrace.o

CFLAGS_request.o	+= -Iblock
CFLAGS_ftrace.o         += -I$(src)
