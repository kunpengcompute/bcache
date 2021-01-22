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
 * acache device - provide interfaces for user space to visit ringbuffer 
 * that store a series of bio sample info
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/circ_buf.h>
#include <linux/list.h>

#include "ftrace.h"
#include "interface.h"
#include "request.h"

#include <trace/events/bcache.h>

#define DEV_NAME "acache"

#define DEFAULT_USERBUF_SIZE 		(1024 * 1024)
#define DEFAULT_PREFETCH_WORKERS 	1000
#define MIN_ACACHE_BUFFER_SIZE 		4096

#define bio_same_disk(bio1, bio2) 	(bio1->bi_disk == bio2->bi_disk)
#define bio_start_sector(bio)		(bio->bi_iter.bi_sector)

unsigned int acache_dev_size = MIN_ACACHE_BUFFER_SIZE;

module_param_named(acache_size, acache_dev_size, uint, 0444);
MODULE_PARM_DESC(acache_size, "acache ringbuf size in byte");

unsigned int acache_prefetch_workers = DEFAULT_PREFETCH_WORKERS;

module_param_named(prefetch_workers, acache_prefetch_workers, uint, 0444);
MODULE_PARM_DESC(prefetch_workers, "num of workers which process samples");

struct inflight_list_head {
	struct list_head entry;
	spinlock_t io_lock;
	bool initialized;
};

struct prefetch_worker {
	struct sample s;
	struct work_struct work;
	struct list_head list;
};

struct acache_device {
	bool initialized;
	dev_t devno;
	struct cdev cdev;
	struct class *class;
	struct mem_reg *mem_regionp;

	struct sample *userbuf_read;
	struct sample *userbuf_write;
	ssize_t userbuf_size;

	struct inflight_list_head inflight_list;

	struct workqueue_struct *wq;
	struct prefetch_worker *prefetch_workers;
	struct list_head prefetch_workers_free;
	spinlock_t prefetch_workers_free_list_lock;
} adev;

/* Record the dfx info */
struct dfx dfx;

struct sample sample_out;

/* 
 * smaple_circ is a ringbuffer for prefetch io info,
 * kernel thread is producer, user process is consumer.
 */
struct acache_circ *sample_circ;

static atomic_t acache_opened_dev = ATOMIC_INIT(0);
static struct acache_metadata metadata;

int acache_open(struct inode *inode, struct file *filp)
{
	struct mem_reg *dev;

	int minor = MINOR(inode->i_rdev);

	if (minor >= ACACHE_NR_DEVS)
		return -ENODEV;
	if (atomic_xchg(&acache_opened_dev, 1))
		return -EPERM;

	dev = &adev.mem_regionp[minor];

	filp->private_data = dev;

	return 0;
}

int acache_release(struct inode *inode, struct file *filp)
{
	atomic_dec(&acache_opened_dev);
	return 0;
}

ssize_t read_circ_slice(struct acache_circ *circ, struct sample *buf,
			size_t size)
{
	unsigned long first, todo, flags;

	spin_lock_irqsave(&circ->lock, flags);

	todo = CIRC_CNT(circ->head, circ->tail, circ->size);
	if (todo == 0) {
		spin_unlock_irqrestore(&circ->lock, flags);
		return 0;
	}
	if (todo > size / sizeof(struct sample))
		todo = size / sizeof(struct sample);

	first = CIRC_CNT_TO_END(circ->head, circ->tail, circ->size);
	if (first > todo)
		first = todo;

	memcpy(buf, circ->data + circ->tail, first * sizeof(struct sample));
	if (first < todo)
		memcpy(buf + first, circ->data,
		       (todo - first) * sizeof(struct sample));
	circ->tail = (circ->tail + todo) & (circ->size - 1);

	spin_unlock_irqrestore(&circ->lock, flags);
	return todo * sizeof(struct sample);
}

static ssize_t acache_read(struct file *filp, char __user *buf,
			   size_t size, loff_t *ppos)
{
	long ret, cut;

	if (metadata.conntype != ACACHE_READWRITE_CONN)
		return -EINVAL;

	if (size > adev.userbuf_size)
		size = adev.userbuf_size;
	ret = read_circ_slice(sample_circ, adev.userbuf_read, size);
	if (ret <= 0)
		return ret;

	cut = copy_to_user(buf, adev.userbuf_read, size);
	return ret - cut;
}

static void worker_func(struct work_struct *work)
{
	struct prefetch_worker *sw =
		container_of(work, struct prefetch_worker, work);

	process_one_sample(&sw->s);
	spin_lock(&adev.prefetch_workers_free_list_lock);
	list_add_tail(&sw->list, &adev.prefetch_workers_free);
	spin_unlock(&adev.prefetch_workers_free_list_lock);
}

static int queue_prefetch_item(struct sample *s)
{
	struct prefetch_worker *sw;

	spin_lock(&adev.prefetch_workers_free_list_lock);
	sw = list_first_entry_or_null(&adev.prefetch_workers_free,
			struct prefetch_worker, list);
	if (!sw) {
		dfx.worker_drop++;
		spin_unlock(&adev.prefetch_workers_free_list_lock);
		return -1;
	}
	list_del_init(&sw->list);
	spin_unlock(&adev.prefetch_workers_free_list_lock);

	memcpy(&sw->s, s, sizeof(struct sample));
	INIT_WORK(&sw->work, worker_func);
	queue_work(adev.wq, &sw->work);
	return 0;
}

static ssize_t acache_write(struct file *filp, const char __user *buf,
			    size_t size, loff_t *ppos)
{
	long cut;
	int i;

	if (metadata.conntype != ACACHE_READWRITE_CONN)
		return -EINVAL;

	if (size > adev.userbuf_size)
		size = adev.userbuf_size;
	cut = copy_from_user(adev.userbuf_write, buf, size);
	for (i = 0; i < (size - cut) / sizeof(struct sample); i++) {
		if (queue_prefetch_item(adev.userbuf_write + i))
			break;
	}
	return i * sizeof(struct sample);
}

static loff_t acache_llseek(struct file *filp, loff_t offset, int whence)
{
	loff_t newpos;

	if (metadata.conntype != ACACHE_READWRITE_CONN)
		return -EINVAL;

	switch (whence) {
	case 0:		/* SEEK_SET */
		newpos = offset;
		break;
	case 1:		/* SEEK_CUR */
		newpos = filp->f_pos + offset;
		break;
	case 2:		/* SEEK_END */
		newpos = ACACHE_DEV_SIZE - 1 + offset;
		break;
	default:		/* can't happen */
		return -EINVAL;
	}
	if ((newpos < 0) || (newpos > ACACHE_DEV_SIZE))
		return -EINVAL;

	filp->f_pos = newpos;
	return newpos;

}

static int acache_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct mem_reg *dev = filp->private_data;

	if (metadata.conntype != ACACHE_RINGBUFFER_CONN)
		return -EINVAL;

	vma->vm_flags |= VM_IO;
	vma->vm_flags |= (VM_DONTEXPAND | VM_DONTDUMP);

	if (remap_pfn_range
	    (vma, vma->vm_start, virt_to_phys(dev->data) >> PAGE_SHIFT,
	     vma->vm_end - vma->vm_start, vma->vm_page_prot))
		return -EAGAIN;

	pr_info("useraddr: %lx, kerneladdr: %p\n", vma->vm_start, dev->data);
	return 0;
}

static long acache_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case ACACHE_GET_METADATA:
		return copy_to_user((struct acache_metadata __user *)arg,
				    &metadata, sizeof(struct acache_metadata));
	default:
		return -EINVAL;
	}
}

static const struct file_operations acache_fops = {
	.owner = THIS_MODULE,
	.llseek = acache_llseek,
	.read = acache_read,
	.write = acache_write,
	.open = acache_open,
	.release = acache_release,
	.mmap = acache_mmap,
	.unlocked_ioctl = acache_ioctl,
};

void init_circ_buf(struct acache_circ **circ, void *startaddr)
{
	*circ = (struct acache_circ *)startaddr;
	(*circ)->head = 0;
	(*circ)->tail = 0;
	(*circ)->size = SAMPLE_CIRC_SIZE;
	spin_lock_init(&(*circ)->lock);
}

void acache_dfx_record(struct sample *data)
{
	if ((data->opcode == ACACHE_SAMPLE_READ) ||
		(data->opcode == ACACHE_SAMPLE_CACHE_INSERT)) {
		/* Record dfx message every 10 second */
		if ((data->start_time - dfx.time) > 10000000000) {
			trace_bcache_dfx_info(&dfx);
			memset(&dfx, 0, sizeof(struct dfx));
			dfx.time = data->start_time;
		}
	}
}

void acache_dfx_count_io_sample(struct sample *data, struct dfx_io_sample *io_sample)
{
	switch (data->opcode) {
	case ACACHE_SAMPLE_READ:
		io_sample->read++;
		break;
	case ACACHE_SAMPLE_CACHE_INSERT:
		io_sample->insert++;
		break;
	case ACACHE_SAMPLE_LATENCY:
		io_sample->latency++;
		break;
	default:
		break;
	}
}

void save_circ_item(struct acache_circ *circ, struct sample *data)
{
	unsigned long flags;

	spin_lock_irqsave(&circ->lock, flags);
	if (CIRC_SPACE(circ->head, circ->tail, circ->size) >= 1) {
		/* insert one item into the buffer */
		memcpy(&circ->data[circ->head], data, sizeof(sample_out));
		circ->head = (circ->head + 1) & (circ->size - 1);
		acache_dfx_count_io_sample(data, &dfx.io_req.picked);
	} else {
		acache_dfx_count_io_sample(data, &dfx.io_req.discard);
	}
	spin_unlock_irqrestore(&circ->lock, flags);
	acache_dfx_record(data);
}

static void acache_free_mem(void)
{
	int i;

	for (i = 0; i < ACACHE_NR_DEVS; i++) {
		vfree(adev.mem_regionp[i].data);
		adev.mem_regionp[i].data = NULL;
	}
		
	kfree(adev.mem_regionp);
	adev.mem_regionp = NULL;

	kfree(adev.userbuf_read);
	adev.userbuf_read = NULL;

	kfree(adev.userbuf_write);
	adev.userbuf_write = NULL;

	kfree(adev.prefetch_workers);
	adev.prefetch_workers = NULL;
}

int acache_dev_prefetch_init(struct acache_device *adev)
{
	int i;

	if (acache_prefetch_workers < 1) {
		pr_err("acache_prefetch_workers %u too small, need more than 0", 
				acache_prefetch_workers);
		return -EINVAL;
	}

	adev->prefetch_workers = kmalloc_array(acache_prefetch_workers,
					       sizeof(struct prefetch_worker),
					       GFP_KERNEL);
	if (!adev->prefetch_workers) {
		pr_err("acache: could not alloc prefetch workers");
		goto fail_prefetch_workers_alloc;
	}

	INIT_LIST_HEAD(&adev->prefetch_workers_free);
	spin_lock_init(&adev->prefetch_workers_free_list_lock);
	for (i = 0; i < acache_prefetch_workers; i++) {
		spin_lock(&adev->prefetch_workers_free_list_lock);
		list_add_tail(&adev->prefetch_workers[i].list,
			      &adev->prefetch_workers_free);
		spin_unlock(&adev->prefetch_workers_free_list_lock);
	}

	adev->wq = alloc_workqueue("acache_prefetch", WQ_MEM_RECLAIM, 0);
	if (!adev->wq) {
		pr_err("acache: could not alloc workqueue");
		goto fail_workqueue_alloc;
	}

	return 0;

fail_workqueue_alloc:
	kfree(adev->prefetch_workers);
	adev->prefetch_workers = NULL;

fail_prefetch_workers_alloc:
	if (adev->wq) {
		destroy_workqueue(adev->wq);
		adev->wq = NULL;
	}

	return -1;
}

int acache_dev_init(void)
{
	int ret;
	int i;
	int major;
	struct device *dev;

	if (acache_dev_size < MIN_ACACHE_BUFFER_SIZE) {
		pr_info("acache_dev_size %u too small, set to default %d", 
				acache_dev_size, MIN_ACACHE_BUFFER_SIZE);
		acache_dev_size = MIN_ACACHE_BUFFER_SIZE;
	}

	inflight_list_ops.init();
	major = alloc_chrdev_region(&adev.devno, 0, ACACHE_NR_DEVS, DEV_NAME);

	if (major < 0) {
		pr_err("acache: could not allocate chrdev region (err %d)", major);
		ret = -1;
		goto fail_inflight_list;
	}

	adev.class = class_create(THIS_MODULE, DEV_NAME);

	if (IS_ERR(adev.class)) {
		pr_err("acache: could not create acache class");
		ret = -1;
		goto fail_class;
	}

	metadata.devsize = acache_dev_size;
	metadata.magic = ACACHE_MAGIC;
	metadata.conntype = ACACHE_READWRITE_CONN;
	cdev_init(&adev.cdev, &acache_fops);
	adev.cdev.owner = THIS_MODULE;

	ret = cdev_add(&adev.cdev, adev.devno, ACACHE_NR_DEVS);
	if (ret < 0) {
		pr_err("acache: %s: failed to add cdev", __func__);
		goto fail_dev_add;
	}

	dev = device_create(adev.class, NULL, adev.devno, NULL, DEV_NAME);
	if (IS_ERR(dev)) {
		pr_err("acache: could not create device");
		ret = -1;
		goto fail_device;
	}

	adev.mem_regionp = kmalloc_array(ACACHE_NR_DEVS, sizeof(struct mem_reg), 
									 GFP_KERNEL);
	if (!adev.mem_regionp) {
		pr_err("acache: could not create device");
		ret = -ENOMEM;
		goto fail_malloc;
	}
	memset(adev.mem_regionp, 0, sizeof(struct mem_reg) * ACACHE_NR_DEVS);

	for (i = 0; i < ACACHE_NR_DEVS; i++) {
		adev.mem_regionp[i].size = ACACHE_DEV_SIZE;
		adev.mem_regionp[i].data = vmalloc(ACACHE_DEV_SIZE);
		if (!adev.mem_regionp[i].data) {
			pr_err("acache: could not alloc region data mem");
			ret = -ENOMEM;
			goto fail_memregion_data_malloc;
		}
		memset(adev.mem_regionp[i].data, 0, ACACHE_DEV_SIZE);
	}

	adev.userbuf_size = DEFAULT_USERBUF_SIZE;
	adev.userbuf_read = kmalloc(adev.userbuf_size, GFP_KERNEL);
	adev.userbuf_write = kmalloc(adev.userbuf_size, GFP_KERNEL);
	if (!adev.userbuf_read || !adev.userbuf_write) {
		pr_err("acache: could not alloc region data mem");
		goto fail_userbuf_malloc;
	}

	//FIXME: assume there is only one device

	init_circ_buf(&sample_circ, adev.mem_regionp[0].data);
	ret = acache_dev_prefetch_init(&adev);
	if (ret)
		goto fail_prefetch_init;

	adev.initialized = true;

	return 0;

fail_prefetch_init:
fail_userbuf_malloc:
fail_memregion_data_malloc:
	acache_free_mem();

fail_malloc:
	device_destroy(adev.class, adev.devno);

fail_device:
	cdev_del(&adev.cdev);

fail_dev_add:
	class_destroy(adev.class);

fail_class:
	unregister_chrdev_region(adev.devno, ACACHE_NR_DEVS);

fail_inflight_list:
	inflight_list_ops.exit();

	adev.initialized = false;

	return ret;
}

void acache_dev_exit(void)
{
	if (!adev.initialized) {
		return ;
	}

	if (adev.wq) {
		flush_workqueue(adev.wq);
		destroy_workqueue(adev.wq);
	}

	device_destroy(adev.class, adev.devno);
	cdev_del(&adev.cdev);
	acache_free_mem();
	unregister_chrdev_region(adev.devno, ACACHE_NR_DEVS);
	class_destroy(adev.class);
	inflight_list_ops.exit();
}

static struct search *__inflight_list_lookup_locked(struct search *s)
{
	struct search *iter;
	struct bio *prefetch, *normal;

	if (!adev.inflight_list.initialized)
		return NULL;
	normal = &s->bio.bio;
	list_for_each_entry(iter, &adev.inflight_list.entry, list_node) {
		prefetch = &iter->bio.bio;
		if (bio_same_disk(normal, prefetch) &&
			bio_start_sector(normal) < bio_end_sector(prefetch) &&
		    bio_end_sector(normal) > bio_start_sector(prefetch)) {

			if (bio_start_sector(normal) > bio_start_sector(prefetch) &&
				bio_end_sector(normal) < bio_end_sector(prefetch)) {
				dfx.overlap.all++;
			} else {
				dfx.overlap.partial++;
			}
			return iter;
		}
	}
	return NULL;
}

static void inflight_list_init(void)
{
	INIT_LIST_HEAD(&adev.inflight_list.entry);
	spin_lock_init(&adev.inflight_list.io_lock);
	adev.inflight_list.initialized = true;
}

static void inflight_list_exit(void)
{
	BUG_ON(!list_empty(&adev.inflight_list.entry));
}

static int inflight_list_insert(struct search *s)
{
	if (!adev.inflight_list.initialized)
		return -1;

	/* init  wait queue head to block inflight ios */
	init_waitqueue_head(&s->wqh);
	spin_lock(&adev.inflight_list.io_lock);
	list_add_tail(&s->list_node, &adev.inflight_list.entry);
	spin_unlock(&adev.inflight_list.io_lock);

	trace_bcache_inflight_list_insert(s->d, s->orig_bio);
	return 0;
}

static int inflight_list_remove(struct search *s)
{
	if (!adev.inflight_list.initialized)
		return -1;

	spin_lock(&adev.inflight_list.io_lock);
	list_del_init(&s->list_node);
	spin_unlock(&adev.inflight_list.io_lock);

	wake_up_interruptible_all(&s->wqh);
	return 0;
}

static bool inflight_list_wait_once(struct search *s)
{
	struct search *pfs = NULL;
	struct cached_dev *dc;
	DEFINE_WAIT(wqe);

	if (!adev.inflight_list.initialized)
		return false;

	spin_lock(&adev.inflight_list.io_lock);
	pfs = __inflight_list_lookup_locked(s);
	if (pfs == NULL) {
		spin_unlock(&adev.inflight_list.io_lock);
		return false;
	}

	dc = container_of(pfs->d, struct cached_dev, disk);
	if (!dc->inflight_block_enable) {
		spin_unlock(&adev.inflight_list.io_lock);
		return true;
	}

	prepare_to_wait(&pfs->wqh, &wqe, TASK_INTERRUPTIBLE);

	/* unlock here to ensure pfs not changed. */
	spin_unlock(&adev.inflight_list.io_lock);
	schedule();

	finish_wait(&pfs->wqh, &wqe);

	return true;
}

static bool inflight_list_wait(struct search *s)
{
	bool pend = false;
	int count = 0;

	while (inflight_list_wait_once(s)) {
		pend = true;
		count++;
		if (count > 1) {
			dfx.multi_pending++;
		}
	}

	return pend;
}

struct inflight_queue_ops inflight_list_ops = {
	.init	= inflight_list_init,
	.exit	= inflight_list_exit,
	.insert	= inflight_list_insert,
	.remove	= inflight_list_remove,
	.wait	= inflight_list_wait,
};
