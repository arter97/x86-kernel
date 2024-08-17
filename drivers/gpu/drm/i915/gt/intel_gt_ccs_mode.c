// SPDX-License-Identifier: MIT
/*
 * Copyright © 2024 Intel Corporation
 */

#include "i915_drv.h"
#include "intel_gt.h"
#include "intel_gt_ccs_mode.h"
#include "intel_gt_regs.h"

static void intel_gt_apply_ccs_mode(struct intel_gt *gt)
{
	int cslice;
	u32 mode = 0;
	int first_ccs = __ffs(CCS_MASK(gt));

	/* Build the value for the fixed CCS load balancing */
	for (cslice = 0; cslice < I915_MAX_CCS; cslice++) {
		if (gt->ccs.cslices & BIT(cslice))
			/*
			 * If available, assign the cslice
			 * to the first available engine...
			 */
			mode |= XEHP_CCS_MODE_CSLICE(cslice, first_ccs);

		else
			/*
			 * ... otherwise, mark the cslice as
			 * unavailable if no CCS dispatches here
			 */
			mode |= XEHP_CCS_MODE_CSLICE(cslice,
						     XEHP_CCS_MODE_CSLICE_MASK);
	}

	gt->ccs.mode_reg_val = mode;
}

void intel_gt_ccs_mode_init(struct intel_gt *gt)
{
	if (!IS_DG2(gt->i915))
		return;

	/* Initialize the CCS mode setting */
	intel_gt_apply_ccs_mode(gt);
}
