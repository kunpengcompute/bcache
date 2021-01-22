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

#ifndef _ACHACHE_READAHEAD_H_
#define _ACHACHE_READAHEAD_H_

extern void search_free(struct closure *cl);
extern struct search *search_alloc(struct bio *bio, struct bcache_device *d, bool prefetch);
extern void cached_dev_read(struct cached_dev *dc, struct search *s);

#endif
