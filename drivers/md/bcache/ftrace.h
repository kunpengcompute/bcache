#undef TRACE_SYSTEM
#define TRACE_SYSTEM bcache

#if !defined(_BCACHE_MOD_FTRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _BCACHE_MOD_FTRACE_H

#include <linux/tracepoint.h>
#include <linux/blktrace_api.h>

#include "bcache.h"
#include "interface.h"

DECLARE_EVENT_CLASS(bcache_inflight,
	TP_PROTO(struct bcache_device *d, struct bio *bio),
	TP_ARGS(d, bio),

	TP_STRUCT__entry(
		__field(dev_t,			dev				)
		__field(unsigned int,	orig_major		)
		__field(unsigned int,	orig_minor		)
		__field(sector_t,		sector			)
		__field(dev_t,			orig_sector		)
		__field(unsigned int,	nr_sector		)
		__array(char,			rwbs,		6	)
	),

	TP_fast_assign(
		__entry->dev			= bio_dev(bio);
		__entry->orig_major		= d->disk->major;
		__entry->orig_minor		= d->disk->first_minor;
		__entry->sector			= bio->bi_iter.bi_sector;
		__entry->orig_sector	= bio->bi_iter.bi_sector - 16;
		__entry->nr_sector		= bio->bi_iter.bi_size >> 9;
		blk_fill_rwbs(__entry->rwbs, bio->bi_opf, bio->bi_iter.bi_size);
	),

	TP_printk("%d,%d %s %llu + %u (from %d,%d @ %llu)",
			MAJOR(__entry->dev), MINOR(__entry->dev),
			__entry->rwbs, (unsigned long long)__entry->sector,
			__entry->nr_sector, __entry->orig_major, __entry->orig_minor,
			(unsigned long long)__entry->orig_sector)
);

/* readahead.c */
DEFINE_EVENT(bcache_inflight, bcache_prefetch_request,
	TP_PROTO(struct bcache_device *d, struct bio *bio),
	TP_ARGS(d, bio)
);

/* interface.c */
DEFINE_EVENT(bcache_inflight, bcache_inflight_list_insert,
	TP_PROTO(struct bcache_device *d, struct bio *bio),
	TP_ARGS(d, bio)
);

DEFINE_EVENT(bcache_inflight, bcache_inflight_list_remove,
	TP_PROTO(struct bcache_device *d, struct bio *bio),
	TP_ARGS(d, bio)
);

TRACE_EVENT(bcache_dfx_info,
	TP_PROTO(struct dfx *d),
	TP_ARGS(d),

	TP_STRUCT__entry(
		__field(uint32_t,	partial_overlap		)
		__field(uint32_t,	all_overlap			)
		__field(uint32_t,	multi_pending		)
		__field(uint32_t,	discard_read		)
		__field(uint32_t,	discard_insert		)
		__field(uint32_t,	discard_latency		)
		__field(uint32_t,	picked_read			)
		__field(uint32_t,	picked_insert		)
		__field(uint32_t,	picked_latency		)
		__field(uint32_t,	worker_drop			)
	),

	TP_fast_assign(
		__entry->partial_overlap	= d->overlap.partial;
		__entry->all_overlap		= d->overlap.all;
		__entry->multi_pending		= d->multi_pending;
		__entry->discard_read		= d->io_req.discard.read;
		__entry->discard_insert		= d->io_req.discard.insert;
		__entry->discard_latency	= d->io_req.discard.latency;
		__entry->picked_read		= d->io_req.picked.read;
		__entry->picked_insert		= d->io_req.picked.insert;
		__entry->picked_latency		= d->io_req.picked.latency;
		__entry->worker_drop		= d->worker_drop;
	),

	TP_printk("%u %u %u %u %u %u %u %u %u %u", 
		__entry->partial_overlap, __entry->all_overlap, __entry->multi_pending,
		__entry->discard_read, __entry->discard_insert, __entry->discard_latency,
		__entry->picked_read, __entry->picked_insert, __entry->picked_latency,
		__entry->worker_drop)
);

#endif /* _BCACHE_MOD_FTRACE_H */

/* this part has to be here */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .

#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE ftrace

#include <trace/define_trace.h>
