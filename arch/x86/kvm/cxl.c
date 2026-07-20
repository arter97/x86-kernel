// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM CXL Memory Fast Path
 *
 * Handles CXL MMIO accesses directly in KVM without exiting to userspace.
 * Optionally caches accesses (matching QEMU's OpenCIS implementation) or
 * bypasses the cache and writes the backing file directly.  Backed by a
 * vmap'd hugetlbfs file in either mode.
 *
 * QEMU writes "CACHE_ENABLE,VMID,path,logbin,base,size" to
 * /sys/module/kvm/parameters/cxl_config at boot to register a CXL memory
 * region. The kernel then handles MMIO faults in that range directly,
 * avoiding the KVM exit overhead.
 */

#include <linux/kvm_host.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/hugetlb.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>

#include "cxl.h"

/* ---- MMIO interception ---- */

bool kvm_cxl_handle_mmio(struct kvm_vcpu *vcpu, bool is_write)
{
	struct kvm_cxl_info *cxl = READ_ONCE(vcpu->kvm->arch.cxl);
	struct cxl_event_batch batch = { .n = 0 };
	struct cxl_log *log;
	int i;

	if (!cxl || !cxl->mapped)
		return false;

	/* Verify all fragments fall within the CXL window */
	for (i = 0; i < vcpu->mmio_nr_fragments; i++) {
		struct kvm_mmio_fragment *frag = &vcpu->mmio_fragments[i];

		if (frag->gpa < cxl->base ||
		    frag->gpa + frag->len > cxl->base + cxl->size)
			return false;
	}

	spin_lock(&cxl->lock);
	log = cxl->log;		/* captured under cxl->lock */
	for (i = 0; i < vcpu->mmio_nr_fragments; i++) {
		struct kvm_mmio_fragment *frag = &vcpu->mmio_fragments[i];
		u64 gpa = frag->gpa;
		u8 *data = frag->data;
		u32 remaining = frag->len;

		if (!cxl->cache_enabled) {
			/*
			 * Bypass mode: write straight through to the
			 * vmap'd backing, no block splitting.  One log
			 * event per fragment captures the access; cross-VM
			 * LOGBIN ordering is provided by cxl_log_push's
			 * prod_lock just like in cache mode.
			 */
			void *backing = cxl->mapped + (gpa - cxl->base);

			if (is_write)
				memcpy(backing, data, remaining);
			else
				memcpy(data, backing, remaining);
			cxl_batch_record(&batch, gpa, is_write);
			continue;
		}

		/*
		 * Walk every cache-block sub-range covered by this fragment.
		 * cxl_access() must never receive a (gpa, size) pair that
		 * straddles a 64-byte block boundary; otherwise its memcpy
		 * into block->data overruns the block and corrupts the next
		 * cache slot.  An MMIO fragment can be up to PAGE_SIZE bytes
		 * (e.g. FXSAVE = 416 bytes spans 7 blocks), so 2-block
		 * splitting alone is not enough.
		 */
		while (remaining) {
			u64 next_cb = (gpa + KVM_CXL_BLOCK_SIZE) &
				      ~((u64)KVM_CXL_BLOCK_SIZE - 1);
			u32 chunk = min_t(u32, remaining, (u32)(next_cb - gpa));

			cxl_access(cxl, gpa, data, chunk, is_write, &batch);
			gpa += chunk;
			data += chunk;
			remaining -= chunk;
		}
	}
	spin_unlock(&cxl->lock);

	/* Push log events after releasing cxl->lock; the log path is
	 * sleepable and applies backpressure when the ring is full. */
	if (log && batch.n)
		cxl_log_push(log, (u32)vcpu->vcpu_id, batch.ev, batch.n);

	return true;
}

/* ---- vmap backing file into kernel VA ---- */

static int cxl_vmap_file(struct kvm_cxl_info *cxl)
{
	struct file *file = cxl->backing_file;
	struct address_space *mapping = file->f_mapping;
	unsigned long total_pages, i;
	int ret;

	if (is_file_hugepages(file)) {
		struct hstate *h = hstate_file(file);
		unsigned long hpage_size = huge_page_size(h);
		unsigned long pages_per_hp = hpage_size >> PAGE_SHIFT;
		unsigned long nr_hpages = cxl->size / hpage_size;
		unsigned long hi, j;

		total_pages = nr_hpages * pages_per_hp;
		cxl->pages = kvmalloc_array(total_pages, sizeof(struct page *),
					    GFP_KERNEL);
		if (!cxl->pages)
			return -ENOMEM;

		/*
		 * filemap_get_folio() takes a base-page (PAGE_SIZE) index.
		 * For hugetlbfs every base-page index inside a hugepage maps
		 * to the same folio, so we must step by pages_per_hp to land
		 * on each successive hugepage rather than spinning on the
		 * first one.
		 */
		for (hi = 0; hi < nr_hpages; hi++) {
			struct folio *folio;
			struct page *page;
			pgoff_t idx = hi * pages_per_hp;

			folio = filemap_get_folio(mapping, idx);
			if (IS_ERR(folio)) {
				ret = PTR_ERR(folio);
				pr_err("kvm_cxl: folio lookup failed at index %lu: %d\n",
				       idx, ret);
				goto err;
			}

			page = folio_page(folio, 0);
			for (j = 0; j < pages_per_hp; j++)
				cxl->pages[hi * pages_per_hp + j] = page + j;
			folio_put(folio);
		}
	} else {
		total_pages = cxl->size >> PAGE_SHIFT;
		cxl->pages = kvmalloc_array(total_pages, sizeof(struct page *),
					    GFP_KERNEL);
		if (!cxl->pages)
			return -ENOMEM;

		for (i = 0; i < total_pages; i++) {
			struct folio *folio;

			folio = filemap_get_folio(mapping, i);
			if (IS_ERR(folio)) {
				ret = PTR_ERR(folio);
				pr_err("kvm_cxl: folio lookup failed at index %lu: %d\n",
				       i, ret);
				goto err;
			}

			cxl->pages[i] = folio_page(folio,
						   i - folio->index);
			folio_put(folio);
		}
	}

	cxl->nr_pages = total_pages;
	cxl->mapped = vmap(cxl->pages, total_pages, VM_MAP, PAGE_KERNEL);
	if (!cxl->mapped) {
		pr_err("kvm_cxl: vmap failed for %lu pages\n", total_pages);
		ret = -ENOMEM;
		goto err;
	}

	pr_info("kvm_cxl: mapped %lu pages (%llu bytes) at %p\n",
		total_pages, cxl->size, cxl->mapped);
	return 0;

err:
	kvfree(cxl->pages);
	cxl->pages = NULL;
	return ret;
}

static void cxl_cleanup(struct kvm_cxl_info *cxl)
{
	struct cxl_log *log;

	/* Detach the log first so any subsequent MMIO that grabs cxl->lock
	 * sees cxl->log == NULL and skips the push entirely. */
	spin_lock(&cxl->lock);
	log = cxl->log;
	cxl->log = NULL;
	spin_unlock(&cxl->lock);

	if (log)
		cxl_log_destroy(log);
	if (cxl->mapped)
		vunmap(cxl->mapped);
	kvfree(cxl->pages);
	if (cxl->backing_file)
		filp_close(cxl->backing_file, NULL);
	kfree(cxl);
}

/* ---- sysfs parameter: /sys/module/kvm/parameters/cxl_config ---- */

static int cxl_config_set(const char *val, const struct kernel_param *kp)
{
	char path[256], logbin[256];
	u64 base, size;
	pid_t vmid;
	int cache_enable;
	struct kvm *kvm;
	struct kvm_cxl_info *cxl;
	int ret, n;

	/*
	 * Register format: CACHE_ENABLE,VMID,backing_file,logbin,0xBASE,0xSIZE
	 *   - CACHE_ENABLE: 1 enables the software cache, 0 bypasses it
	 *   - logbin may be empty (two consecutive commas)
	 * Unregister: VMID alone (no commas).
	 */
	if (!strchr(val, ',')) {
		/* Unregister: just VMID */
		if (sscanf(val, "%d", &vmid) != 1) {
			pr_err("kvm_cxl: expected VMID for unregister\n");
			return -EINVAL;
		}
		mutex_lock(&kvm_lock);
		list_for_each_entry(kvm, &vm_list, vm_list) {
			if (kvm->userspace_pid == vmid && kvm->arch.cxl) {
				cxl = kvm->arch.cxl;
				WRITE_ONCE(kvm->arch.cxl, NULL);
				mutex_unlock(&kvm_lock);
				cxl_cleanup(cxl);
				pr_info("kvm_cxl: unregistered VM %d\n", vmid);
				return 0;
			}
		}
		mutex_unlock(&kvm_lock);
		pr_err("kvm_cxl: VM %d not found\n", vmid);
		return -ENOENT;
	}

	logbin[0] = '\0';
	n = sscanf(val, "%d,%d,%255[^,],%255[^,],0x%llx,0x%llx",
		   &cache_enable, &vmid, path, logbin, &base, &size);

	/*
	 * Empty logbin: sscanf stops at ",," giving fewer fields.
	 * Reparse without the logbin field.
	 */
	if (n < 6) {
		logbin[0] = '\0';
		n = sscanf(val, "%d,%d,%255[^,],,0x%llx,0x%llx",
			   &cache_enable, &vmid, path, &base, &size);
		if (n != 5) {
			pr_err("kvm_cxl: expected CACHE_ENABLE,VMID,path,logbin,0xBASE,0xSIZE\n");
			return -EINVAL;
		}
	}

	if (cache_enable != 0 && cache_enable != 1) {
		pr_err("kvm_cxl: cache_enable must be 0 or 1, got %d\n",
		       cache_enable);
		return -EINVAL;
	}

	/* Find KVM instance by PID */
	mutex_lock(&kvm_lock);
	list_for_each_entry(kvm, &vm_list, vm_list) {
		if (kvm->userspace_pid == vmid)
			goto found;
	}
	mutex_unlock(&kvm_lock);
	pr_err("kvm_cxl: VM with PID %d not found\n", vmid);
	return -ENOENT;

found:
	mutex_unlock(&kvm_lock);

	if (READ_ONCE(kvm->arch.cxl)) {
		pr_err("kvm_cxl: VM %d already configured\n", vmid);
		return -EEXIST;
	}

	if (!size || !IS_ALIGNED(size, PAGE_SIZE)) {
		pr_err("kvm_cxl: invalid size 0x%llx\n", size);
		return -EINVAL;
	}

	cxl = kzalloc(sizeof(*cxl), GFP_KERNEL);
	if (!cxl)
		return -ENOMEM;

	cxl->base = base;
	cxl->size = size;
	cxl->cache_enabled = cache_enable;
	spin_lock_init(&cxl->lock);
	cxl_cache_init(&cxl->cache);

	/* Optional cache-miss log */
	if (logbin[0]) {
		cxl->log = cxl_log_init(logbin, vmid);
		if (IS_ERR(cxl->log)) {
			ret = PTR_ERR(cxl->log);
			pr_err("kvm_cxl: failed to open log %s: %d\n",
			       logbin, ret);
			cxl->log = NULL;
			kfree(cxl);
			return ret;
		}
		pr_info("kvm_cxl: logging cache misses to %s\n", logbin);
	}

	cxl->backing_file = filp_open(path, O_RDWR | O_LARGEFILE, 0);
	if (IS_ERR(cxl->backing_file)) {
		ret = PTR_ERR(cxl->backing_file);
		pr_err("kvm_cxl: failed to open %s: %d\n", path, ret);
		cxl->backing_file = NULL;
		if (cxl->log)
			cxl_log_destroy(cxl->log);
		kfree(cxl);
		return ret;
	}

	ret = cxl_vmap_file(cxl);
	if (ret) {
		filp_close(cxl->backing_file, NULL);
		if (cxl->log)
			cxl_log_destroy(cxl->log);
		kfree(cxl);
		return ret;
	}

	WRITE_ONCE(kvm->arch.cxl, cxl);
	pr_info("kvm_cxl: VM %d: cache=%d base=0x%llx size=0x%llx file=%s\n",
		vmid, cache_enable, base, size, path);
	return 0;
}

static int cxl_config_get(char *buffer, const struct kernel_param *kp)
{
	struct kvm *kvm;
	int len = 0;

	mutex_lock(&kvm_lock);
	list_for_each_entry(kvm, &vm_list, vm_list) {
		struct kvm_cxl_info *cxl = kvm->arch.cxl;

		if (cxl)
			len += scnprintf(buffer + len, PAGE_SIZE - len,
					 "vm=%d cache=%d base=0x%llx size=0x%llx\n",
					 kvm->userspace_pid,
					 cxl->cache_enabled,
					 cxl->base, cxl->size);
	}
	mutex_unlock(&kvm_lock);

	if (!len)
		len = scnprintf(buffer, PAGE_SIZE, "(none)\n");
	return len;
}

static const struct kernel_param_ops cxl_config_ops = {
	.set = cxl_config_set,
	.get = cxl_config_get,
};
module_param_cb(cxl_config, &cxl_config_ops, NULL, 0644);

/* ---- VM teardown ---- */

void kvm_cxl_vm_destroy(struct kvm *kvm)
{
	struct kvm_cxl_info *cxl = kvm->arch.cxl;

	if (!cxl)
		return;

	kvm->arch.cxl = NULL;
	cxl_cleanup(cxl);
	pr_info("kvm_cxl: cleaned up VM %d\n", kvm->userspace_pid);
}
