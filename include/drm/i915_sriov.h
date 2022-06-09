/* SPDX-License-Identifier: MIT */

#ifndef _DRM_I915_SRIOV_H_
#define _DRM_I915_SRIOV_H_

#include <linux/pci.h>
#include <linux/types.h>

/*
 * Namespace for i915 SR-IOV exported symbols.
 *
 * Note: EXPORT_SYMBOL_NS* expects the namespace argument to be a string
 * literal (or a macro expanding to one).
 */
#define I915_SRIOV_NS "I915_SRIOV"

int i915_sriov_pause_vf(struct pci_dev *pdev, unsigned int vfid);
int i915_sriov_resume_vf(struct pci_dev *pdev, unsigned int vfid);

int i915_sriov_wait_vf_flr_done(struct pci_dev *pdev, unsigned int vfid);

size_t
i915_sriov_ggtt_size(struct pci_dev *pdev, unsigned int vfid, unsigned int tile);
ssize_t i915_sriov_ggtt_save(struct pci_dev *pdev, unsigned int vfid, unsigned int tile,
			     void *buf, size_t size);
int
i915_sriov_ggtt_load(struct pci_dev *pdev, unsigned int vfid, unsigned int tile,
		     const void *buf, size_t size);

size_t
i915_sriov_fw_state_size(struct pci_dev *pdev, unsigned int vfid,
			 unsigned int tile);
ssize_t
i915_sriov_fw_state_save(struct pci_dev *pdev, unsigned int vfid, unsigned int tile,
			 void *buf, size_t size);
int
i915_sriov_fw_state_load(struct pci_dev *pdev, unsigned int vfid, unsigned int tile,
			 const void *buf, size_t size);

ssize_t
i915_sriov_lmem_size(struct pci_dev *pdev, unsigned int vfid, unsigned int tile);
void *i915_sriov_lmem_map(struct pci_dev *pdev, unsigned int vfid, unsigned int tile);
void
i915_sriov_lmem_unmap(struct pci_dev *pdev, unsigned int vfid, unsigned int tile);

#endif /* _DRM_I915_SRIOV_H_ */
