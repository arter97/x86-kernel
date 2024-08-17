// SPDX-License-Identifier: MIT
/*
 * Copyright © 2024 Intel Corporation
 */

#include "i915_drv.h"
#include "intel_gt_ccs_mode.h"
#include "intel_gt_print.h"
#include "intel_gt_regs.h"
#include "intel_gt_sysfs.h"

static void intel_gt_apply_ccs_mode(struct intel_gt *gt)
{
	unsigned long cslices_mask = CCS_MASK(gt);
	unsigned long ccs_mask = gt->ccs.id_mask;
	u32 mode_val = 0;
	/* CCS engine id, i.e. the engines position in the engine's bitmask */
	int engine;
	int cslice;

	/*
	 * The mode has two bit dedicated for each engine
	 * that will be used for the CCS balancing algorithm:
	 *
	 *    BIT | CCS slice
	 *   ------------------
	 *     0  | CCS slice
	 *     1  |     0
	 *   ------------------
	 *     2  | CCS slice
	 *     3  |     1
	 *   ------------------
	 *     4  | CCS slice
	 *     5  |     2
	 *   ------------------
	 *     6  | CCS slice
	 *     7  |     3
	 *   ------------------
	 *
	 * When a CCS slice is not available, then we will write 0x7,
	 * oterwise we will write the user engine id which load will
	 * be forwarded to that slice.
	 *
	 * The possible configurations are:
	 *
	 * 1 engine (ccs0):
	 *   slice 0, 1, 2, 3: ccs0
	 *
	 * 2 engines (ccs0, ccs1):
	 *   slice 0, 2: ccs0
	 *   slice 1, 3: ccs1
	 *
	 * 4 engines (ccs0, ccs1, ccs2, ccs3):
	 *   slice 0: ccs0
	 *   slice 1: ccs1
	 *   slice 2: ccs2
	 *   slice 3: ccs3
	 */
	engine = __ffs(ccs_mask);

	for (cslice = 0; cslice < I915_MAX_CCS; cslice++) {
		if (!(cslices_mask & BIT(cslice))) {
			/*
			 * If not available, mark the slice as unavailable
			 * and no task will be dispatched here.
			 */
			mode_val |= XEHP_CCS_MODE_CSLICE(cslice,
						     XEHP_CCS_MODE_CSLICE_MASK);
			continue;
		}

		mode_val |= XEHP_CCS_MODE_CSLICE(cslice, engine);

		engine = find_next_bit(&cslices_mask, I915_MAX_CCS, engine + 1);
		/*
		 * If "engine" has reached the I915_MAX_CCS value it means that
		 * we have gone through all the unfused engines and now we need
		 * to reset its value to the first engine.
		 *
		 * From the find_next_bit() description:
		 *
		 * "Returns the bit number for the next set bit
		 * If no bits are set, returns @size."
		 */
		if (engine == I915_MAX_CCS) {
			/*
			 * CCS mode, will be used later to
			 * reset to a flexible value
			 */
			engine = __ffs(ccs_mask);
			continue;
		}
	}

	gt->ccs.mode_reg_val = mode_val;
}

static void __update_ccs_mask(struct intel_gt *gt, u32 ccs_mode)
{
	unsigned long cslices_mask = CCS_MASK(gt);
	int i;

	/* Mask off all the CCS engines */
	gt->ccs.id_mask = 0;

	for_each_set_bit(i, &cslices_mask, I915_MAX_CCS) {
		gt->ccs.id_mask |= BIT(i);

		ccs_mode--;
		if (!ccs_mode)
			break;
	}

	/*
	 * It's impossible for 'ccs_mode' to be zero at this point.
	 * This scenario would only occur if the 'ccs_mode' provided by
	 * the caller exceeded the total number of CCS engines, a condition
	 * we check before calling the 'update_ccs_mask()' function.
	 */
	GEM_BUG_ON(ccs_mode);

	/* Initialize the CCS mode setting */
	intel_gt_apply_ccs_mode(gt);
}

void intel_gt_ccs_mode_init(struct intel_gt *gt)
{
	if (!IS_DG2(gt->i915))
		return;

	/*
	 * Set CCS balance mode 1 in the ccs_mask.
	 *
	 * During init the workaround are not set up yet.
	 */
	__update_ccs_mask(gt, 1);
}

static ssize_t num_cslices_show(struct device *dev,
				struct device_attribute *attr,
				char *buff)
{
	struct intel_gt *gt = kobj_to_gt(&dev->kobj);
	u32 num_slices;

	num_slices = hweight32(CCS_MASK(gt));

	return sysfs_emit(buff, "%u\n", num_slices);
}
static DEVICE_ATTR_RO(num_cslices);

void intel_gt_sysfs_ccs_init(struct intel_gt *gt)
{
	if (sysfs_create_file(&gt->sysfs_gt, &dev_attr_num_cslices.attr))
		gt_warn(gt, "Failed to create sysfs num_cslices files\n");
}
