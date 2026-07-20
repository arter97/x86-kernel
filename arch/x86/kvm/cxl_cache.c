// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM CXL Host-Side Cache
 *
 * 4-way set-associative cache with LRU eviction, ported from
 * QEMU's OpenCIS implementation (cxl_hcache.c / cxl_type3_hcoh.c).
 */

#include <linux/string.h>
#include <linux/minmax.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/kref.h>

#include <asm/kvm_host.h>

#include "cxl.h"

/* ---- Shared cache-miss log ----
 *
 * One ring buffer + one output file per LOGBIN path, shared across every
 * VM that registers the same path.  All producers serialize on a single
 * spinlock when pushing into the ring, so events appear in the file in
 * strict push (≈ real-time) order across VMs.  A single workqueue consumer
 * drains the ring to the file.  The ring stores entries in the on-disk
 * binary format (see cxl_log_entry), so draining is a straight
 * ring-memory-to-file write with no per-entry formatting.
 *
 * The shared structure is refcounted and registered in a global list keyed
 * by path.  The first VM to claim a path opens (and truncates) the file;
 * later VMs join the existing entry.  Teardown happens only when the last
 * reference drops.
 */

#define CXL_LOG_PATH_MAX	256

struct cxl_log_shared {
	char path[CXL_LOG_PATH_MAX];
	struct list_head list;
	struct kref ref;

	/* Output file. Single consumer, no extra serialization needed. */
	struct file *file;
	loff_t file_offset;

	/* Shared ring buffer. */
	char *buf;
	unsigned long buf_size;
	unsigned long head;		/* producer offset (bytes) */
	unsigned long tail;		/* consumer offset (bytes) */
	spinlock_t prod_lock;		/* serializes all producers */
	wait_queue_head_t space_wq;	/* producers wait for room here */
	bool closing;			/* teardown in progress */

	/* Drain. */
	struct work_struct work;
};

/* Ring entries double as the on-disk records; keep them from wrapping
 * mid-record so each drain chunk is a whole number of entries. */
static_assert(sizeof(struct cxl_log_entry) == 16);
static_assert(sizeof(struct cxl_log_file_header) == 16);
static_assert(CXL_LOG_BUF_SIZE % sizeof(struct cxl_log_entry) == 0);
static_assert(KVM_MAX_VCPU_IDS - 1 <= U16_MAX);	/* vcpu_id fits u16 */

static LIST_HEAD(cxl_log_shareds);
static DEFINE_MUTEX(cxl_log_shareds_lock);

/* ---- Ring helpers ---- */

static inline void cxl_ring_write(struct cxl_log_shared *s, unsigned long pos,
				  const void *src, size_t len)
{
	unsigned long remain = s->buf_size - pos;

	if (remain >= len) {
		memcpy(s->buf + pos, src, len);
	} else {
		memcpy(s->buf + pos, src, remain);
		memcpy(s->buf, (const char *)src + remain, len - remain);
	}
}

/* ---- Consumer ---- */

static void cxl_log_write_all(struct cxl_log_shared *s, const char *buf,
			      size_t len)
{
	while (len) {
		ssize_t ret = kernel_write(s->file, buf, len,
					   &s->file_offset);
		if (ret > 0) {
			buf += ret;
			len -= ret;
			continue;
		}
		if (ret == -EINTR || ret == -EAGAIN)
			continue;
		pr_err_ratelimited("kvm_cxl: log write failed: %zd (lost %zu bytes)\n",
				   ret, len);
		break;
	}
}

/* Bound each write so producers blocked on ring space are released in
 * chunk granules instead of only after a full-backlog drain. */
#define CXL_LOG_FLUSH_CHUNK	(1024 * 1024)

static void cxl_log_flush_work(struct work_struct *work)
{
	struct cxl_log_shared *s = container_of(work, struct cxl_log_shared,
						work);
	unsigned long tail = s->tail;
	unsigned long head = smp_load_acquire(&s->head);

	while (tail != head) {
		unsigned long pos = tail % s->buf_size;
		unsigned long len = min3(head - tail, s->buf_size - pos,
					 (unsigned long)CXL_LOG_FLUSH_CHUNK);

		/* Bytes in [tail, head) are stable - producers only write
		 * into the free region starting at head - and the ring
		 * layout is the on-disk format, so write straight from the
		 * ring. */
		cxl_log_write_all(s, s->buf + pos, len);

		tail += len;
		smp_store_release(&s->tail, tail);
		wake_up(&s->space_wq);
	}
}

/* ---- Producer ---- */

int cxl_log_push(struct cxl_log *log, u32 vcpu_id,
		 const struct cxl_log_event *evs, unsigned int n)
{
	struct cxl_log_shared *s = log->shared;
	size_t need = (size_t)n * sizeof(struct cxl_log_entry);
	unsigned long head;
	unsigned int i;
	int ret;

	if (!n)
		return 0;
	if (WARN_ON_ONCE(need > s->buf_size))
		return -EINVAL;

again:
	spin_lock(&s->prod_lock);
	if (s->closing) {
		spin_unlock(&s->prod_lock);
		return -ESHUTDOWN;
	}
	if ((s->head - smp_load_acquire(&s->tail)) + need > s->buf_size) {
		/* Ring full.  Drop the spinlock and block until the consumer
		 * frees space; recheck under the lock to handle races where
		 * another producer fills the gap before we get back in. */
		spin_unlock(&s->prod_lock);
		ret = wait_event_killable(s->space_wq,
			READ_ONCE(s->closing) ||
			(READ_ONCE(s->head) - smp_load_acquire(&s->tail))
				+ need <= s->buf_size);
		if (ret) {
			pr_err_ratelimited("kvm_cxl: fatal signal during log push; lost %u event(s)\n",
					   n);
			return -EINTR;
		}
		goto again;
	}

	head = s->head;
	for (i = 0; i < n; i++) {
		struct cxl_log_entry entry = {
			.gpa = evs[i].gpa,
			.vmid = (u32)log->vmid,
			.vcpu_id = (u16)vcpu_id,
			.is_write = evs[i].is_write,
		};
		cxl_ring_write(s,
			       (head + i * sizeof(entry)) % s->buf_size,
			       &entry, sizeof(entry));
	}
	smp_store_release(&s->head, head + need);
	spin_unlock(&s->prod_lock);

	schedule_work(&s->work);
	return 0;
}

/* ---- Shared lifecycle ---- */

static struct cxl_log_shared *cxl_log_shared_get(const char *path)
{
	struct cxl_log_shared *s;
	int ret;

	mutex_lock(&cxl_log_shareds_lock);
	list_for_each_entry(s, &cxl_log_shareds, list) {
		if (!strcmp(s->path, path)) {
			kref_get(&s->ref);
			mutex_unlock(&cxl_log_shareds_lock);
			return s;
		}
	}

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s) {
		ret = -ENOMEM;
		goto err_unlock;
	}
	if (strscpy(s->path, path, sizeof(s->path)) < 0) {
		ret = -ENAMETOOLONG;
		goto err_free_s;
	}
	s->buf = vmalloc(CXL_LOG_BUF_SIZE);
	if (!s->buf) {
		ret = -ENOMEM;
		goto err_free_s;
	}
	s->file = filp_open(path,
			    O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE,
			    0644);
	if (IS_ERR(s->file)) {
		ret = PTR_ERR(s->file);
		goto err_free_buf;
	}

	s->buf_size = CXL_LOG_BUF_SIZE;
	s->head = 0;
	s->tail = 0;
	s->file_offset = 0;
	s->closing = false;

	{
		struct cxl_log_file_header hdr = {
			.header_size = sizeof(hdr),
			.entry_size = sizeof(struct cxl_log_entry),
		};
		ssize_t written;

		BUILD_BUG_ON(sizeof(CXL_LOG_MAGIC) - 1 != sizeof(hdr.magic));
		memcpy(hdr.magic, CXL_LOG_MAGIC, sizeof(hdr.magic));
		written = kernel_write(s->file, &hdr, sizeof(hdr),
				       &s->file_offset);
		if (written != sizeof(hdr)) {
			ret = written < 0 ? written : -EIO;
			goto err_close_file;
		}
	}
	spin_lock_init(&s->prod_lock);
	init_waitqueue_head(&s->space_wq);
	INIT_WORK(&s->work, cxl_log_flush_work);
	kref_init(&s->ref);
	list_add(&s->list, &cxl_log_shareds);

	mutex_unlock(&cxl_log_shareds_lock);
	return s;

err_close_file:
	filp_close(s->file, NULL);
err_free_buf:
	vfree(s->buf);
err_free_s:
	kfree(s);
err_unlock:
	mutex_unlock(&cxl_log_shareds_lock);
	return ERR_PTR(ret);
}

/* Called with cxl_log_shareds_lock held by kref_put_mutex.  Just unlink
 * so a concurrent _get for the same path can't find this dying entry. */
static void cxl_log_shared_release(struct kref *ref)
{
	struct cxl_log_shared *s = container_of(ref, struct cxl_log_shared,
						ref);

	list_del(&s->list);
}

/* Slow teardown after the last reference dropped and the entry was
 * unlinked from the registry; runs without any lock held. */
static void cxl_log_shared_teardown(struct cxl_log_shared *s)
{
	spin_lock(&s->prod_lock);
	s->closing = true;
	spin_unlock(&s->prod_lock);
	wake_up_all(&s->space_wq);

	cancel_work_sync(&s->work);
	cxl_log_flush_work(&s->work);	/* final drain */

	filp_close(s->file, NULL);
	vfree(s->buf);
	kfree(s);
}

/* ---- Per-VM API ---- */

struct cxl_log *cxl_log_init(const char *path, pid_t vmid)
{
	struct cxl_log *log;

	log = kzalloc(sizeof(*log), GFP_KERNEL);
	if (!log)
		return ERR_PTR(-ENOMEM);

	log->shared = cxl_log_shared_get(path);
	if (IS_ERR(log->shared)) {
		int ret = PTR_ERR(log->shared);

		kfree(log);
		return ERR_PTR(ret);
	}
	log->vmid = vmid;
	return log;
}

void cxl_log_destroy(struct cxl_log *log)
{
	struct cxl_log_shared *s = log->shared;

	/*
	 * Other VMs may still hold references and continue producing into s.
	 * Drop our ref under the registry lock; if we were the last, unlink
	 * (done by the release callback) and run the slow teardown outside
	 * the lock.
	 */
	if (kref_put_mutex(&s->ref, cxl_log_shared_release,
			   &cxl_log_shareds_lock)) {
		mutex_unlock(&cxl_log_shareds_lock);
		cxl_log_shared_teardown(s);
	}

	kfree(log);
}

/* ---- Cache ---- */

void cxl_cache_init(struct kvm_cxl_cache *cache)
{
	memset(cache->sets, 0, sizeof(cache->sets));
	cache->blk_mask = KVM_CXL_BLOCK_SIZE - 1;
	cache->set_mask = ((u64)KVM_CXL_NUM_SETS - 1) << KVM_CXL_BLOCK_BITS;
	cache->tag_mask = ~(cache->set_mask | cache->blk_mask);
}

static inline u64 cxl_extract_tag(struct kvm_cxl_cache *cache, u64 addr)
{
	return (addr & cache->tag_mask) >> (KVM_CXL_SET_BITS + KVM_CXL_BLOCK_BITS);
}

static inline u64 cxl_extract_set(struct kvm_cxl_cache *cache, u64 addr)
{
	return (addr & cache->set_mask) >> KVM_CXL_BLOCK_BITS;
}

static inline u64 cxl_assem_addr(struct kvm_cxl_cache *cache, u64 set, int blk)
{
	struct kvm_cxl_cache_block *block = &cache->sets[set].blocks[blk];

	if (block->state != KVM_CXL_INVALID)
		return (block->tag << (KVM_CXL_SET_BITS + KVM_CXL_BLOCK_BITS)) |
		       (set << KVM_CXL_BLOCK_BITS);
	return 0;
}

static void cxl_update_priority(struct kvm_cxl_cache *cache, u64 set, int blk)
{
	cache->sets[set].priority[blk] = cache->sets[set].priority_count++;
}

static void cxl_update_block(struct kvm_cxl_cache *cache, u64 tag, u64 set,
			     int blk, enum kvm_cxl_cache_state state)
{
	if (state != KVM_CXL_INVALID)
		cxl_update_priority(cache, set, blk);
	cache->sets[set].blocks[blk].tag = tag;
	cache->sets[set].blocks[blk].state = state;
}

static int cxl_find_valid_block(struct kvm_cxl_cache *cache, u64 tag, u64 set)
{
	int i;

	for (i = 0; i < KVM_CXL_ASSOC; i++) {
		if (cache->sets[set].blocks[i].tag == tag &&
		    cache->sets[set].blocks[i].state != KVM_CXL_INVALID)
			return i;
	}
	return -1;
}

static int cxl_find_invalid_block(struct kvm_cxl_cache *cache, u64 set)
{
	int i;

	for (i = 0; i < KVM_CXL_ASSOC; i++) {
		if (cache->sets[set].blocks[i].state == KVM_CXL_INVALID)
			return i;
	}
	return -1;
}

static int cxl_find_replace_block(struct kvm_cxl_cache *cache, u64 set)
{
	u64 min_pri = cache->sets[set].priority[0];
	int min_idx = 0, i;

	for (i = 1; i < KVM_CXL_ASSOC; i++) {
		if (cache->sets[set].priority[i] < min_pri) {
			min_pri = cache->sets[set].priority[i];
			min_idx = i;
		}
	}
	return min_idx;
}

/*
 * Core cache access function.  Mirrors QEMU's __host_hcoh_access().
 * Caller must hold cxl->lock.  Events that should reach the log are
 * recorded into `batch` and pushed by the caller AFTER releasing the
 * lock, so the log can block for space without stalling the hot path.
 */
void cxl_access(struct kvm_cxl_info *cxl, u64 gpa, void *data,
		u32 size, bool is_write, struct cxl_event_batch *batch)
{
	struct kvm_cxl_cache *cache = &cxl->cache;
	struct kvm_cxl_cache_block *block;
	u64 tag, set, block_addr;
	u32 offset;
	int blk;

	tag = cxl_extract_tag(cache, gpa);
	set = cxl_extract_set(cache, gpa);
	blk = cxl_find_valid_block(cache, tag, set);

	if (blk >= 0) {
		/* Cache hit */
		block = &cache->sets[set].blocks[blk];
		offset = gpa & cache->blk_mask;

		if (is_write) {
			memcpy(&block->data[offset], data, size);
			block->state = KVM_CXL_MODIFIED;
		} else {
			memcpy(data, &block->data[offset], size);
		}
		cxl_update_priority(cache, set, blk);
		return;
	}

	/* Cache miss - find a block to use */
	blk = cxl_find_invalid_block(cache, set);
	if (blk < 0) {
		u64 victim_addr;

		blk = cxl_find_replace_block(cache, set);
		block = &cache->sets[set].blocks[blk];

		/* Writeback dirty victim */
		if (block->state == KVM_CXL_MODIFIED) {
			victim_addr = cxl_assem_addr(cache, set, blk);
			memcpy(cxl->mapped + (victim_addr - cxl->base),
			       block->data, KVM_CXL_BLOCK_SIZE);
			cxl_batch_record(batch, victim_addr, true);
		}
	}

	/* Fill cache line from backing memory */
	block = &cache->sets[set].blocks[blk];
	block_addr = gpa & ~((u64)KVM_CXL_BLOCK_SIZE - 1);
	memcpy(block->data, cxl->mapped + (block_addr - cxl->base),
	       KVM_CXL_BLOCK_SIZE);
	cxl_batch_record(batch, block_addr, false);
	cxl_update_block(cache, tag, set, blk, KVM_CXL_EXCLUSIVE);

	/* Perform the actual operation on the now-cached block */
	offset = gpa & cache->blk_mask;
	if (is_write) {
		memcpy(&block->data[offset], data, size);
		block->state = KVM_CXL_MODIFIED;
	} else {
		memcpy(data, &block->data[offset], size);
	}
}
