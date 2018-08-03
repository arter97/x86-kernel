/*
 * Author: Park Ju Hyung <qkrwngud825@gmail.com>
 *
 * Copyright 2018 Park Ju Hyung
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

struct __read_mostly vfs_throttler_type vfs_delay;
struct vfs_throttler_type vfs_count;
#define VFS_DELAY_PARAM(x) module_param_named(x, vfs_delay.x, ulong, 0644)

// Expose module parameters for controlling delay
VFS_DELAY_PARAM(llseek);
VFS_DELAY_PARAM(read);
VFS_DELAY_PARAM(write);
VFS_DELAY_PARAM(read_iter);
VFS_DELAY_PARAM(write_iter);
VFS_DELAY_PARAM(iterate);
VFS_DELAY_PARAM(iterate_shared);
VFS_DELAY_PARAM(poll);
VFS_DELAY_PARAM(mmap);
VFS_DELAY_PARAM(open);
VFS_DELAY_PARAM(flush);
VFS_DELAY_PARAM(release);
VFS_DELAY_PARAM(fsync);
VFS_DELAY_PARAM(fasync);
VFS_DELAY_PARAM(lock);
VFS_DELAY_PARAM(flock);
VFS_DELAY_PARAM(splice_write);
VFS_DELAY_PARAM(splice_read);
VFS_DELAY_PARAM(fallocate);
VFS_DELAY_PARAM(show_fdinfo);
VFS_DELAY_PARAM(lookup);
VFS_DELAY_PARAM(get_link);
VFS_DELAY_PARAM(readlink);
VFS_DELAY_PARAM(create);
VFS_DELAY_PARAM(link);
VFS_DELAY_PARAM(unlink);
VFS_DELAY_PARAM(symlink);
VFS_DELAY_PARAM(mkdir);
VFS_DELAY_PARAM(rmdir);
VFS_DELAY_PARAM(mknod);
VFS_DELAY_PARAM(rename);

static int param_get_vfs_count(char *buffer, const struct kernel_param *kp)
{
	int result = 0;

	result += sprintf(buffer + result, "%16s %8s\n", "VFS operation", "Count");

#define VFS_COUNT_PRINTF(x) result += sprintf(buffer + result, "%16s %8ld\n", #x, vfs_count.x)

	VFS_COUNT_PRINTF(llseek);
	VFS_COUNT_PRINTF(read);
	VFS_COUNT_PRINTF(write);
	VFS_COUNT_PRINTF(read_iter);
	VFS_COUNT_PRINTF(write_iter);
	VFS_COUNT_PRINTF(iterate);
	VFS_COUNT_PRINTF(iterate_shared);
	VFS_COUNT_PRINTF(poll);
	VFS_COUNT_PRINTF(mmap);
	VFS_COUNT_PRINTF(open);
	VFS_COUNT_PRINTF(flush);
	VFS_COUNT_PRINTF(release);
	VFS_COUNT_PRINTF(fsync);
	VFS_COUNT_PRINTF(fasync);
	VFS_COUNT_PRINTF(lock);
	VFS_COUNT_PRINTF(flock);
	VFS_COUNT_PRINTF(splice_write);
	VFS_COUNT_PRINTF(splice_read);
	VFS_COUNT_PRINTF(fallocate);
	VFS_COUNT_PRINTF(show_fdinfo);
	VFS_COUNT_PRINTF(lookup);
	VFS_COUNT_PRINTF(get_link);
	VFS_COUNT_PRINTF(readlink);
	VFS_COUNT_PRINTF(create);
	VFS_COUNT_PRINTF(link);
	VFS_COUNT_PRINTF(unlink);
	VFS_COUNT_PRINTF(symlink);
	VFS_COUNT_PRINTF(mkdir);
	VFS_COUNT_PRINTF(rmdir);
	VFS_COUNT_PRINTF(mknod);
	VFS_COUNT_PRINTF(rename);

	return result;
}

static const struct kernel_param_ops vfs_count_param_ops = {
	.set = NULL,
	.get = param_get_vfs_count,
};

// View count statistics
module_param_cb(count, &vfs_count_param_ops, NULL, 0444);

static __init int vfs_throttler_init(void)
{
	// Initialize structs
	memset(&vfs_delay, 0, sizeof(vfs_delay));
	memset(&vfs_count, 0, sizeof(vfs_count));

	return 0;
}

fs_initcall(vfs_throttler_init)
