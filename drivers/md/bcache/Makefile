# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2021. Huawei Technologies Co., Ltd.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and
# only version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

obj-m += bcache.o

bcache-y		:= alloc.o bset.o btree.o closure.o debug.o extents.o\
	io.o journal.o movinggc.o interface.o request.o stats.o prefetch.o super.o sysfs.o trace.o\
	util.o writeback.o ftrace.o

CFLAGS_ftrace.o         += -I$(src)
