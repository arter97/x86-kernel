#include <linux/slab.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include "proc_fs.h"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("pr0gr4m");
MODULE_DESCRIPTION("proc list add driver");

DEFINE_MUTEX(m_lock);
LIST_HEAD(m_list);

static int add_data(int a, int b)
{
	struct m_info *info;
	printk("%s %d, %d\n", __func__, a, b);

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	INIT_LIST_HEAD(&info->list);
	info->a = a;
	info->b = b;

	mutex_lock(&m_lock);
	list_add(&info->list, &m_list);
	mutex_unlock(&m_lock);

	return 0;
}

static int add_sample_data(void)
{
	if (add_data(10, 20))
		return -ENOMEM;
	if (add_data(30, 40))
		return -ENOMEM;
	return 0;
}

static int remove_sample_data(void)
{
	struct m_info *tmp;
	struct list_head *node, *q;
	list_for_each_safe(node, q, &m_list) {
		tmp = list_entry(node, struct m_info, list);
		list_del(node);
		kfree(tmp);
	}

	return 0;
}


#ifdef USE_SINGLE_OPEN
static int simple_show(struct seq_file *s, void *v)
{
	struct m_info *info;
	printk("%s", __func__);
	list_for_each_entry(info, &m_list, list)
		seq_printf(s, "%d + %d = %d\n", info->a, info->b,
				info->a + info->b);
	return 0;
}
#else
static void *seq_start(struct seq_file *s, loff_t *pos)
{
	printk("%s", __func__);
	mutex_lock(&m_lock);
	s->private = "";

	return seq_list_start(&m_list, *pos);
}

static void *seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	printk("%s", __func__);
	s->private = "\n";

	return seq_list_next(v, &m_list, pos);
}

static void seq_stop(struct seq_file *s, void *v)
{
	mutex_unlock(&m_lock);
	printk("%s", __func__);
}

static int seq_show(struct seq_file *m, void *v)
{
	struct m_info *info = list_entry(v, struct m_info, list);
	printk("%s", __func__);
	seq_printf(m, "%d + %d = %d\n", info->a, info->b, info->a + info->b);
	return 0;
}

static const struct seq_operations seq_ops = {
	.start = seq_start,
	.next = seq_next,
	.stop = seq_stop,
	.show = seq_show
};
#endif

static int proc_open(struct inode *inode, struct file *file)
{
#ifdef USE_SINGLE_OPEN
	return single_open(file, simple_show, NULL);
#else
	return seq_open(file, &seq_ops);
#endif
}

static ssize_t proc_write(struct file *seq, const char __user *data,
		size_t len, loff_t *off)
{
	char buf[128];
	int a, b;
	static int finished = 0;

	if (finished) {
		printk("m_write end\n");
		finished = 0;
		return 0;
	}
	finished = 1;

	if (copy_from_user(buf, data, len)) {
		printk(KERN_ERR "copy from user error");
		return -EFAULT;
	}

	sscanf(buf, "%d %d", &a, &b);

	if (add_data(a, b)) {
		printk(KERN_ERR "add_data in m_wrtie\n");
		return -EFAULT;
	}

	return len;
}

static const struct proc_ops proc_ops = {
	.proc_open = proc_open,
	.proc_read = seq_read,
	.proc_write = proc_write,
	.proc_lseek = seq_lseek,
	.proc_release = seq_release
};

#define M_DIR	"pr0gr4m-dir"
#define M_FILE	"pr0gr4m"

static struct proc_dir_entry *proc_dir = NULL;
static struct proc_dir_entry *proc_file = NULL;

int proc_init(void)
{
	if ((proc_dir = proc_mkdir(M_DIR, NULL)) == NULL) {
		printk(KERN_ERR "Unable to create /proc/%s\n", M_DIR);
		return -1;
	}

	if ((proc_file = proc_create(M_FILE, 0666, proc_dir, &proc_ops)) == NULL) {
		printk(KERN_ERR "Unable to create /proc/%s/%s\n", M_DIR, M_FILE);
		remove_proc_entry(M_DIR, NULL);
		return -1;
	}

	printk(KERN_INFO "Created /proc/%s/%s\n", M_DIR, M_FILE);
	return 0;
}

void proc_exit(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
	remove_proc_entry(M_FILE, proc_dir);
	remove_proc_entry(M_DIR,, NULL);
#else
	remove_proc_subtree(M_DIR, NULL);
#endif

	proc_remove(proc_file);
	proc_remove(proc_dir);

	printk(KERN_INFO "Removed /proc/%s/%s\n", M_DIR, M_FILE);
}

static int __init proc_dev_init(void)
{
	if (add_sample_data()) {
		printk(KERN_ERR "add_sample_data() failed\n");
		return -ENOMEM;
	}
	return proc_init();
}

static void __exit proc_dev_exit(void)
{
	remove_sample_data();
	proc_exit();

	return;
}

module_init(proc_dev_init);
module_exit(proc_dev_exit);
