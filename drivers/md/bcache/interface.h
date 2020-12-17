// SPDX-License-Identifier: GPL-2.0

#ifndef _ACHACHE_INTERFACE_H_
#define _ACHACHE_INTERFACE_H_

#define ACACHE_NR_DEVS 1

#define RING_SIZE

/* 
 * Record the amount of prefetch request and normal request 
 * that their io LBA is overlapped.
 */
struct dfx_overlap
{
	uint32_t partial;
	uint32_t all;
};

struct dfx_io_sample
{
	uint32_t read;
	uint32_t insert;
	uint32_t latency;
};

struct dfx_io_req
{
	struct dfx_io_sample discard;
	struct dfx_io_sample picked;
};

struct dfx
{
	struct dfx_overlap overlap;
	struct dfx_io_req io_req;
	uint64_t time;
	uint32_t multi_pending;
	uint32_t worker_drop;
};

struct mem_reg {
	char *data;
	unsigned long size;
};

struct sample {
	uint64_t length;
	uint64_t offset;
	uint64_t start_time;
	dev_t dev;
	int opcode;
};

enum sample_ops {
	ACACHE_SAMPLE_READ = 0,
	ACACHE_SAMPLE_WRITE,
	ACACHE_SAMPLE_CACHE_INSERT,
	ACACHE_SAMPLE_LATENCY,
};

struct acache_circ {
	spinlock_t lock;
	int tail;
	int head;
	int size;
	int item_size;
	struct sample data[0];
};

struct acache_metadata {
	uint32_t magic;
	uint32_t conntype;
	uint32_t devsize;
};

#include "bcache.h"
extern int process_one_sample(struct sample *);
extern struct acache_circ *sample_circ;
extern struct sample sample_out;

#define ACACHE_DEV_SIZE acache_dev_size
#define ACACHE_MAGIC 2

enum acache_conn_types {
	ACACHE_NO_CONN = 0,
	ACACHE_RINGBUFFER_CONN,
	ACACHE_READWRITE_CONN,
};

#define SAMPLE_CIRC_SIZE \
	({int i = (ACACHE_DEV_SIZE/2 - sizeof(struct acache_circ))/sizeof(struct sample); \
	int bits = 0; \
	while (i > 0) {i >>= 1; bits++; } \
	  1 << (bits - 1); })


#define  ACACHE_GET_METADATA	_IOR('a', 1, struct acache_metadata)

int acache_dev_init(void);
void acache_dev_exit(void);
void save_circ_item(struct acache_circ *circ, struct sample *data);

struct inflight_queue_ops {
	void (*init)(void);
	void (*exit)(void);

	int (*insert) (struct search *s);
	int (*remove) (struct search *s);
	bool (*wait) (struct search *s);
};
extern struct inflight_queue_ops inflight_list_ops;
#endif
