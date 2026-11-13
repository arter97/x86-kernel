/* SPDX-License-Identifier: GPL-2.0 */
/*
 * arm64 KMSAN support.
 */

#ifndef __ASM_KMSAN_H
#define __ASM_KMSAN_H

#ifndef MODULE

#include <asm/memory.h>
#include <asm/sections.h>
#include <linux/kmsan.h>
#include <linux/mmzone.h>
#include <linux/preempt.h>

/*
 * Functions below are declared in the header to make sure they are inlined.
 * They all are called from kmsan_get_metadata() for every memory access in
 * the kernel, so speed is important here.
 */

/*
 * The kernel image is mapped inside the vmalloc area, but, unlike vmalloc()
 * memory, it has no metadata mapped at the corresponding vmalloc shadow and
 * origin addresses. Its metadata belongs to the struct pages backing the
 * image, so look it up via the linear map alias instead. Avoid lm_alias(),
 * which may call into the instrumented __phys_addr_symbol().
 */
static inline void *arch_kmsan_get_meta_or_null(void *addr, bool is_origin)
{
	unsigned long addr64 = (unsigned long)addr;

	if (addr64 - (unsigned long)_text >=
	    (unsigned long)_end - (unsigned long)_text)
		return NULL;

	addr64 = __phys_to_virt(__kimg_to_phys(addr64));
	return kmsan_get_metadata((void *)addr64, is_origin);
}

/*
 * Only addresses in the linear map are backed by struct pages that can be
 * found with virt_to_page(). Use the non-debug helpers, which do not call
 * into instrumented code.
 */
static inline bool kmsan_virt_addr_valid(void *addr)
{
	unsigned long addr64 = (unsigned long)addr;
	bool ret;

	if (!__is_lm_address(addr64))
		return false;

	/*
	 * pfn_valid() relies on RCU, and may call into the scheduler on exiting
	 * the critical section. However, this would result in recursion with
	 * KMSAN. Therefore, disable preemption here, and re-enable preemption
	 * below while suppressing reschedules to avoid recursion.
	 *
	 * Note, this sacrifices occasionally breaking scheduling guarantees.
	 * Although, a kernel compiled with KMSAN has already given up on any
	 * performance guarantees due to being heavily instrumented.
	 */
	preempt_disable();
	ret = pfn_valid(__phys_to_pfn(__lm_to_phys(addr64)));
	preempt_enable_no_resched();

	return ret;
}

#endif /* !MODULE */

#endif /* __ASM_KMSAN_H */
