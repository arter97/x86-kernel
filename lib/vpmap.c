#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/power_supply.h>
#include <linux/uaccess.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#define VPMAP_DEV "vpmap"
static dev_t vpmap_device_no;

static int vpmap_open(struct inode *inode, struct file *filp) {
	pr_info("vpmap_open called\n");
	return 0;
}
static int vpmap_release(struct inode *inode, struct file *filp)
{
	pr_info("vpmap_release called\n");
	return 0;
}
static ssize_t vpmap_read(struct file *filp, char __user *ubuf, size_t count, loff_t * offset) {
	pr_info("vpmap_read called\n");
	return 0;
}
static ssize_t vpmap_write(struct file *filp, const char __user * buf, size_t count, loff_t * offset) {
	pr_info("vpmap_write called\n");
	return 0;
}

static const struct file_operations vpmap_fops = {
	.open = vpmap_open,
	.release = vpmap_release,
	.read = vpmap_read,
	.write = vpmap_write,
};


static const struct class vpmap_class = {
	.name = VPMAP_DEV,
};
static struct device *vpmap_device;
static struct cdev cdev;
static int vpmap_init_module(void) {
	int ret;

	ret = class_register(&vpmap_class);
	if (ret) {
		pr_warn("Failed to register class vpmap\n");
		goto error0;
	}

	ret = alloc_chrdev_region(&vpmap_device_no, 0, 1, VPMAP_DEV);
	if (ret < 0) {
		pr_err("alloc_chrdev_region failed %d\n", ret);
		goto error1;
	}

	cdev_init(&cdev, &vpmap_fops);
	cdev.owner = THIS_MODULE;
	ret = cdev_add(&cdev, MKDEV(MAJOR(vpmap_device_no), 0), 1);
	if (ret) {
		pr_warn("Faield to add cdev for /dev/vpmap\n");
		goto error2;
	}

	vpmap_device = device_create(&vpmap_class, NULL, vpmap_device_no, NULL, VPMAP_DEV);
	if (IS_ERR(vpmap_device)) {
		pr_warn("failed to create qtipm device\n");
		goto error3;
	}

	pr_info("vpmap registered\n");
	return 0;

error3:
	cdev_del(&cdev);
error2:
	unregister_chrdev_region(vpmap_device_no, 1);
error1:
	class_unregister(&vpmap_class);
error0:

	return ret;
}

module_init(vpmap_init_module);
