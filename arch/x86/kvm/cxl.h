/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KVM_X86_CXL_H
#define __KVM_X86_CXL_H

#include <linux/spinlock.h>

#include "cxl_cache.h"

struct kvm_cxl_info {
	u64 base;			/* GPA base of CXL window */
	u64 size;			/* CXL window size */
	bool cache_enabled;		/* false: bypass cache, write backing directly */
	struct file *backing_file;	/* Kernel file handle */
	void *mapped;			/* vmap'd kernel VA */
	unsigned long nr_pages;		/* Number of base pages in vmap */
	struct page **pages;		/* Page array for cleanup */
	struct cxl_log *log;		/* Cache-miss logger (NULL = disabled) */
	struct kvm_cxl_cache cache;
	spinlock_t lock;
};

struct kvm_vcpu;
struct kvm;

bool kvm_cxl_handle_mmio(struct kvm_vcpu *vcpu, bool is_write);
void kvm_cxl_vm_destroy(struct kvm *kvm);

#endif /* __KVM_X86_CXL_H */
