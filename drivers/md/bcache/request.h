/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021. Huawei Technologies Co., Ltd.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#ifndef _BCACHE_REQUEST_H_
#define _BCACHE_REQUEST_H_
#include "btree.h"
#include "interface.h"

struct data_insert_op {
	struct closure		cl;
	struct cache_set	*c;
	struct bio		*bio;
	struct workqueue_struct *wq;

	unsigned int		inode;
	uint16_t		write_point;
	uint16_t		write_prio;
	blk_status_t		status;

	union {
		uint16_t	flags;

	struct {
		unsigned int	bypass:1;
		unsigned int	writeback:1;
		unsigned int	flush_journal:1;
		unsigned int	csum:1;

		unsigned int	replace:1;
		unsigned int	replace_collision:1;

		unsigned int	insert_data_done:1;
	};
	};

	struct keylist		insert_keys;
	BKEY_PADDED(replace_key);
};

unsigned int bch_get_congested(struct cache_set *c);
void bch_data_insert(struct closure *cl);

void bch_cached_dev_request_init(struct cached_dev *dc);
void bch_flash_dev_request_init(struct bcache_device *d);

extern struct kmem_cache *bch_search_cache;

struct search {
	/* Stack frame for bio_complete */
	struct closure		cl;

	struct bbio		bio;
	struct bio		*orig_bio;
	struct bio		*cache_miss;
	struct bcache_device	*d;

	unsigned int		insert_bio_sectors;
	unsigned int		recoverable:1;
	unsigned int		write:1;
	unsigned int		read_dirty_data:1;
	unsigned int		cache_missed:1;

	unsigned long		start_time;
	/* for prefetch, we do not need copy data to bio */
	bool			prefetch;
	bool			bypass;
	struct list_head	list_node;
	wait_queue_head_t	wqh;
	struct sample		smp;

	struct btree_op		op;
	struct data_insert_op	iop;
};

#endif /* _BCACHE_REQUEST_H_ */
