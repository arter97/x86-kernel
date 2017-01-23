#include <linux/mman.h>
#include <linux/sysctl.h>

int sysctl_kvm_madv_instant_free;

int kvm_ret_mem_advice = MADV_DONTNEED;
EXPORT_SYMBOL_GPL(kvm_ret_mem_advice);

int kvm_madv_instant_free_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos)
{
	int ret;

	ret = proc_dointvec(table, write, buffer, length, ppos);
	if (ret)
		return ret;

#ifdef MADV_FREE
	if (sysctl_kvm_madv_instant_free > 0)
		kvm_ret_mem_advice = MADV_FREE;
	else
		kvm_ret_mem_advice = MADV_DONTNEED;
#endif

	return 0;
}
