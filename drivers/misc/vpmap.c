#include <linux/slab.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <linux/uaccess.h>
//#include <stdlib.h>
//#include <string.h>
#include "proc_fs.h"
#include <linux/math64.h>
#include <linux/time64.h>

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("vpmap");
MODULE_DESCRIPTION("record vpmap");

DEFINE_MUTEX(m_lock);
LIST_HEAD(m_list);

#define M (1024*1024)
#define G (1024*1024*1024)
#define M_DIR	"vpmap"
#define M_FILE	"vpmap"

static int vpmap_ofs;
static char *vpmap_mem;
static int vpmap_dump_cnt;

struct vpmap_elem *vpmap_buf;
int vpmap_elem_cnt;

#define NUM_VPMAP_ELEM  (32*M)

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


static int vpmap_show(struct seq_file *s, void *v) {
	printk(KERN_INFO "Show vpmap_mem. vpmap_elem_cnt: %d\n", vpmap_elem_cnt);
	char buf[128];
	int i;
	for (i=0; i<vpmap_elem_cnt; i++) {
		memset(buf, 0, 128);
		sprintf(buf, "{%d %c %lx %llx %lld.%.09ld}\n",
				vpmap_buf[i].pid,
				vpmap_buf[i].ftype,
				vpmap_buf[i].vpn,
				vpmap_buf[i].pfn,
				vpmap_buf[i].tv_sec,
				vpmap_buf[i].tv_nsec);
		seq_printf(s, "%s", buf);
	}
	//seq_printf(s, "%s", vpmap_mem);

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
	return single_open(file, vpmap_show, NULL);
#if 0
#ifdef USE_SINGLE_OPEN
	return single_open(file, simple_show, NULL);
#else
	return seq_open(file, &seq_ops);
#endif
#endif
}

/*
   미리 일정량의 메모리를 할당해 두고
   다 찰 때마다 스토리지에 파일로 dump
   app 실행 후에는 va trace + dumps 모아서 pa trace로 변환
 */
// mj_msg, len
/* called when 'echo 0 > /proc/vpmap/vpmap' */
static ssize_t vpmap_write(struct file *seq, const char *msg, size_t len, loff_t *off) {
	printk(KERN_INFO "call vpmap_write\n");
	char buf[128];
	static int finished = 0;

	if (finished) {
		printk("m_write end\n");
		finished = 0;
		return 0;
	}
	finished = 1;

	if (copy_from_user(buf, msg, len)) {
		printk(KERN_ERR "copy from user error");
		return -EFAULT;
	}
	memset(vpmap_buf, 0, sizeof(vpmap_elem) * NUM_VPMAP_ELEM);
	memcpy(vpmap_buf, buf, len);
	vpmap_elem_cnt = 0;
	return len;
}


static ssize_t vpmap_write_old(struct file *seq, const char *msg, size_t len, loff_t *off) {
	printk(KERN_INFO "call vpmap_write\n");
	if ((vpmap_ofs + len) >= 1*G) {
		/* dump */
#if 0
		char path[32];
		int fd;
		char *region;

		sprintf(path, "/var/tmp/vpmap%d", vpmap_dump_cnt++);
		if ((fd = open(path, O_WRONLY|O_CREAT)) < 0) {
			perror("File open error");
			exit(1);
		}
		if ((region = mmap(NULL, 1*G, PROT_WRITE, MAP_FILE|MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
			perror("mmap error");
			exit(1);
		}
		memcpy(region, vpmap_mem, vpmap_ofs);
		if ((munmap(region, 1*G)) == -1) {
			perror("munmap error");
			exit(1);
		}
		close(fd);
#endif
		/* !dump */

		vpmap_mem = (char*)kvrealloc(vpmap_mem, 2*(unsigned long)G, GFP_KERNEL);
		//memset(vpmap_mem, 0, 1*G);
		//vpmap_ofs = 0;
	}

	memcpy(vpmap_mem + vpmap_ofs, msg, len);
	vpmap_ofs += len;

	return len;
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
	.proc_write = vpmap_write,
	.proc_lseek = seq_lseek,
	.proc_release = seq_release
};


static struct proc_dir_entry *proc_dir = NULL;
static struct proc_dir_entry *proc_file = NULL;

static int proc_init(void)
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
	/*
	vpmap_mem = (char*)kvmalloc(1*G, GFP_KERNEL);
	memset(vpmap_mem, 0, 1*G);
	vpmap_dump_cnt = 1;
	*/
	// TODO: use kmalloc
	if ((vpmap_buf = (vpmap_elem*)kvmalloc(NUM_VPMAP_ELEM * sizeof(struct vpmap_elem), GFP_KERNEL)) == NULL) {
		printk(KERN_ERR "Unable to kvmalloc vpmap_buf\n");
		return -1;
	}
	vpmap_elem_cnt = 0;

	printk(KERN_INFO "Created /proc/%s/%s\n", M_DIR, M_FILE);
	return 0;
}

static void proc_exit(void)
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

	kvfree(vpmap_mem);

	return;
}

module_init(proc_dev_init);
module_exit(proc_dev_exit);
