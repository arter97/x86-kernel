/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ARM64_KVM_HYP_NVHE_ARM_SMCCC_H__
#define __ARM64_KVM_HYP_NVHE_ARM_SMCCC_H__

#include <asm/kvm_hypevents.h>

#include <linux/arm-smccc.h>

#define hyp_smccc_1_1_smc(...)					\
	do {							\
		trace_hyp_exit(NULL, HYP_REASON_SMC);		\
		arm_smccc_1_1_smc(__VA_ARGS__);			\
		trace_hyp_enter(NULL, HYP_REASON_SMC);		\
	} while (0)

/*
 * Use __arm_smccc_1_2_smc() directly: the wrapper notifies KMSAN about the
 * results, which is not possible (nor needed) at EL2.
 */
#define hyp_smccc_1_2_smc(...)					\
	do {							\
		trace_hyp_exit(NULL, HYP_REASON_SMC);		\
		__arm_smccc_1_2_smc(__VA_ARGS__);		\
		trace_hyp_enter(NULL, HYP_REASON_SMC);		\
	} while (0)

#endif /* __ARM64_KVM_HYP_NVHE_ARM_SMCCC_H__ */
