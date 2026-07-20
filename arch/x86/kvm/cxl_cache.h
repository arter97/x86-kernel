/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KVM_X86_CXL_CACHE_H
#define __KVM_X86_CXL_CACHE_H

#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/fs.h>

/* Cache geometry - matches QEMU's OpenCIS implementation */
#define KVM_CXL_BLOCK_BITS	6
#define KVM_CXL_BLOCK_SIZE	(1 << KVM_CXL_BLOCK_BITS)	/* 64 bytes */
#define KVM_CXL_ASSOC		4				/* 4-way */
#define KVM_CXL_NUM_SETS	8
#define KVM_CXL_SET_BITS	3

enum kvm_cxl_cache_state {
	KVM_CXL_INVALID = 0,
	KVM_CXL_SHARED,
	KVM_CXL_EXCLUSIVE,
	KVM_CXL_MODIFIED,
};

struct kvm_cxl_cache_block {
	u64 tag;
	enum kvm_cxl_cache_state state;
	u8 data[KVM_CXL_BLOCK_SIZE];
};

struct kvm_cxl_cache_set {
	struct kvm_cxl_cache_block blocks[KVM_CXL_ASSOC];
	u64 priority[KVM_CXL_ASSOC];
	u64 priority_count;
};

struct kvm_cxl_cache {
	struct kvm_cxl_cache_set sets[KVM_CXL_NUM_SETS];
	u64 blk_mask;
	u64 set_mask;
	u64 tag_mask;
};

/* ---- Cache-miss log (ring buffer + background flush) ---- */

#define CXL_LOG_BUF_SIZE	(64 * 1024 * 1024)	/* 64 MB ring */
#define CXL_LOG_SCRATCH_SIZE	(64 * 1024)		/* drain batch */

struct cxl_log_entry {
	u32 vmid;
	u32 vcpu_id;
	u8  is_write;
	u64 gpa;
} __packed;

/*
 * A single cxl_access emits up to 2 events (victim writeback + fill).
 * kvm_cxl_handle_mmio runs cxl_access at most
 *   KVM_MAX_MMIO_FRAGMENTS * 2 (line-boundary split)
 * times per MMIO, which gives an upper bound of 8 events.  Round up.
 */
#define CXL_MAX_EVENTS_PER_MMIO	16

struct cxl_log_event {
	u64  gpa;
	bool is_write;
};

struct cxl_event_batch {
	unsigned int n;
	struct cxl_log_event ev[CXL_MAX_EVENTS_PER_MMIO];
};

struct cxl_log_shared;	/* shared ring + file, defined in cxl_cache.c */

/*
 * Per-VM handle into a (possibly shared) cache-miss log.  All ring buffer,
 * consumer, and file state lives in the refcounted cxl_log_shared keyed by
 * LOGBIN path; the per-VM struct holds only the identity needed to stamp
 * outgoing events.
 */
struct cxl_log {
	struct cxl_log_shared *shared;
	pid_t vmid;
};

struct kvm_cxl_info;

static inline void cxl_batch_record(struct cxl_event_batch *batch, u64 gpa,
				    bool is_write)
{
	if (!batch)
		return;
	/* Sized for the worst-case emission per MMIO; cannot overflow. */
	if (WARN_ON_ONCE(batch->n >= ARRAY_SIZE(batch->ev)))
		return;
	batch->ev[batch->n++] = (struct cxl_log_event){
		.gpa = gpa,
		.is_write = is_write,
	};
}

void cxl_cache_init(struct kvm_cxl_cache *cache);
void cxl_access(struct kvm_cxl_info *cxl, u64 gpa, void *data,
		u32 size, bool is_write, struct cxl_event_batch *batch);

struct cxl_log *cxl_log_init(const char *path, pid_t vmid);
void cxl_log_destroy(struct cxl_log *log);
int cxl_log_push(struct cxl_log *log, u32 vcpu_id,
		 const struct cxl_log_event *evs, unsigned int n);

#endif /* __KVM_X86_CXL_CACHE_H */
