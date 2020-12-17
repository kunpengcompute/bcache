// SPDX-License-Identifier: GPL-2.0

#ifndef _ACHACHE_READAHEAD_H_
#define _ACHACHE_READAHEAD_H_

extern void search_free(struct closure *cl);
extern struct search *search_alloc(struct bio *bio, struct bcache_device *d, bool prefetch);
extern void cached_dev_read(struct cached_dev *dc, struct search *s);

#endif
