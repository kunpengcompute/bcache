// SPDX-License-Identifier: GPL-2.0
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
/*
 * do prefetch - read data from backing device according to bio info
 * recommended based on algorithm
 */

#include "ftrace.h"
#include "bcache.h"
#include "debug.h"
#include "request.h"
#include "interface.h"
#include "prefetch.h"

#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/sched/clock.h>
#include <trace/events/bcache.h>

struct cached_dev *get_cached_device_by_dev(dev_t dev)
{
	struct cache_set *c, *tc;
	struct cached_dev *dc, *t;

	list_for_each_entry_safe(c, tc, &bch_cache_sets, list)
		list_for_each_entry_safe(dc, t, &c->cached_devs, list)
			if (dc->bdev->bd_dev == dev && cached_dev_get(dc))
				return dc;

	return NULL;
}

/* Make sure dc and item is valid */
struct bio *get_bio_by_item(struct cached_dev *dc, struct sample *item)
{
	struct bio *bio;
	uint64_t offset = item->offset + dc->sb.data_offset;
	unsigned int nr_iovecs;
	unsigned int item_sectors;
	long unsigned int kmalloc_max_size;

	kmalloc_max_size = (1 << (PAGE_SHIFT + 10)) - 1;
	if (item->length > kmalloc_max_size) {
		pr_debug("prefetch length: %llu exceed kmalloc max size: %lu", 
				 item->length, kmalloc_max_size);
		return NULL;
	}

	item_sectors = item->length >> 9;
	if (get_capacity(dc->bdev->bd_disk) < offset + item_sectors) {
		pr_debug("acache: prefetch area exceeds the capacity of disk(%d:%d), "
				 "end: %llx, capacity: %lx",
				 MAJOR(dc->bdev->bd_dev), MINOR(dc->bdev->bd_dev),
				 offset + item_sectors,
				 get_capacity(dc->bdev->bd_disk));
		return NULL;
	}

	nr_iovecs = DIV_ROUND_UP(item_sectors, PAGE_SECTORS);
	if (nr_iovecs == 0) {
		pr_debug("acache: nr_iovecs can not be %u, prefetch length: %llu", 
				 nr_iovecs, item->length);
		return NULL;
	}

	bio = bio_alloc_bioset(GFP_NOWAIT, nr_iovecs, dc->disk.bio_split);
	if (bio == NULL) {
		bio = bio_alloc_bioset(GFP_NOWAIT, nr_iovecs, NULL);
		if (bio == NULL) {
			pr_debug("acache: bio_alloc_bioset error, prefetch length: %llu",
					 item->length);
			return NULL;
		}
	}

	bio_set_dev(bio, dc->bdev);
	bio->bi_iter.bi_sector = item->offset + dc->sb.data_offset;
	bio->bi_iter.bi_size = item_sectors << 9;

	bch_bio_map(bio, NULL);
	if (bio_alloc_pages(bio, __GFP_NOWARN | GFP_NOIO)) {
		pr_debug("acache: bio alloc pages error, prefetch length: %llu", 
				 item->length);
		goto out_put;
	}

	return bio;

out_put:
	bio_put(bio);

	return NULL;
}

int process_one_sample(struct sample *item)
{
	struct cached_dev *dc;
	struct bio *cache_bio;
	struct search *s;
	struct request_queue *q;
	int rw;

	dc = get_cached_device_by_dev(item->dev);
	if (dc == NULL) {
		pr_debug("acache: get cached device failed, prefetch dropped");
		return 0;
	}

	cache_bio = get_bio_by_item(dc, item);
	if (cache_bio == NULL) {
		goto put_dev;
	}
	trace_bcache_prefetch_request(&dc->disk, cache_bio);

	s = search_alloc(cache_bio, &dc->disk, true);
	q = cache_bio->bi_disk->queue;
	rw = bio_data_dir(cache_bio);
	generic_start_io_acct(q, rw, bio_sectors(cache_bio), &s->d->disk->part0);

	cached_dev_read(dc, s);

	return 0;

put_dev:
	cached_dev_put(dc);

	return -1;
}
