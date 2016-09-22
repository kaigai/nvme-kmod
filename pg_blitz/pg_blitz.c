/*
 * pg_blitz.c
 *
 * Linux kernel module portion of PG-Blitz; that allows to map DMA buffer on
 * userspace applications, and also allows to write out the blocks to files
 * using raw NVMe commands.
 *
 * Copyright 2016 (C) KaiGai Kohei <kaigai@kaigai.gr.jp>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <linux/device.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/kallsyms.h>
#include <linux/magic.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/nvme.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include "pg_blitz.h"

/* number of PG-Blitz device entries */
#define PGBLITZ_MAX_BUFFERS		64
static int		pgblitz_num_buffers = 1;
module_param(pgblitz_num_buffers, int, 0644);
MODULE_PARM_DESC(pgblitz_num_buffers, "Number of PG-Blitz buffers");

/* length of PG-Blitz DMA buffers */
static ulong	pgblitz_buffer_size = (32 << 20);	/* 32MB */
module_param(pgblitz_buffer_size, ulong, 0644);
MODULE_PARM_DESC(pgblitz_buffer_size, "Size of PG-Blitz buffer");

/* turn on/off debug output */
static bool		pgblitz_debug = false;
module_param(pgblitz_debug, bool, 0644);
MODULE_PARM_DESC(pgblitz_debug, "turn on/off debug messages");

/* convenient macros */
#define prDebug(fmt, ...)									\
	do {													\
		if (pgblitz_debug)									\
			printk(KERN_ALERT "pg_blitz(%s:%d): " fmt "\n",	\
				   __FUNCTION__, __LINE__, ##__VA_ARGS__);	\
	} while(0)
#define prInfo(fmt, ...)									\
	printk(KERN_INFO "pg_blitz: " fmt "\n", ##__VA_ARGS__)
#define prNotice(fmt, ...)									\
	printk(KERN_NOTICE "pg_blitz: " fmt "\n", ##__VA_ARGS__)
#define prWarn(fmt, ...)									\
	printk(KERN_WARN "pg_blitz: " fmt "\n", ##__VA_ARGS__)
#define prError(fmt, ...)						\
	printk(KERN_ERR "pg_blitz: " fmt "\n", ##__VA_ARGS__)

#define Assert(cond)												\
	do {															\
		if (!(cond)) {												\
			panic("assertion failure (" #cond ") at %s:%d, %s\n",	\
				  __FILE__, __LINE__, __FUNCTION__);				\
		}															\
	} while(0)
#define lengthof(array)	(sizeof (array) / sizeof ((array)[0]))
#define Max(a,b)		((a) > (b) ? (a) : (b))
#define Min(a,b)		((a) < (b) ? (a) : (b))

/* routines for extra symbols */
#include "../common/extra_ksyms.c"
#include "../common/nvme_misc.c"

/*
 * pgblitz_buffer_state
 */
typedef struct pgblitz_buffer_state
{
	rwlock_t		lock;
	int				nr_pages;
	struct page	  **pages;
} pgblitz_buffer_state;

static pgblitz_buffer_state	pgblitz_buffer_array[PGBLITZ_MAX_BUFFERS];
static struct device	   *pgblitz_buffer_devices[PGBLITZ_MAX_BUFFERS];
#define PGBLITZ_DEVNAME		"pg_blitz"
static int				pgblitz_chrdev_major = -1;
static struct class	   *pgblitz_sys_class = NULL;

static inline pgblitz_buffer_state *
pgblitz_get_buffer(struct file *filp)
{
	int		minor = MINOR(filp->f_inode->i_rdev);

  	if (minor < pgblitz_num_buffers)
		return &pgblitz_buffer_array[minor];
	return NULL;
}

/*
 * ioctl(2) handler of BLITZ_IOCTL__BUFFER_SIZE
 */
static long
pgblitz_ioctl__buffer_size(BlitzCmd__BufferSize __user *uarg)
{
	size_t		length = pgblitz_buffer_size;

	if (put_user(length, &uarg->length))
		return -EFAULT;
	return 0;
}

/*
 * ioctl(2) handler of BLITZ_IOCTL__CHECK_FILE
 */
static long
pgblitz_ioctl__check_file(BlitzCmd__CheckFile __user *uarg)
{
	BlitzCmd__CheckFile	karg;
	struct file	   *filp;
	long			retval;

	if (copy_from_user(&karg, uarg, sizeof(BlitzCmd__CheckFile)))
		return -EFAULT;

	filp = fget(karg.fdesc);
	if (!filp)
		return -EBADF;

	retval = file_is_supported_nvme(filp, true, NULL);

	fput(filp);

	return retval;
}

/*
 * ioctl(2) handler of BLITZ_IOCTL__WRITE_FILE
 */
static long
pgblitz_ioctl__write_file(BlitzCmd__WriteFile __user *uarg)
{
	return -ENOTSUPP;
}

/*
 * ioctl(2) handler of BLITZ_IOCTL__FLUSH_FILE
 */
static long
pgblitz_ioctl__flush_file(BlitzCmd__FlushFile __user *uarg)
{
	return -ENOTSUPP;
}

/*
 * open(2) handler
 */
static int
pgblitz_file_open(struct inode *inode, struct file *filp)
{
	Assert(MAJOR(inode->i_rdev) == pgblitz_chrdev_major);
	if (MINOR(inode->i_rdev) < pgblitz_num_buffers)
		return 0;
	return -ENODEV;
}

/*
 * read(2) handler
 */
static ssize_t
pgblitz_file_read(struct file *filp, char __user *buf, size_t len, loff_t *pos)
{
	pgblitz_buffer_state *bstate = pgblitz_get_buffer(filp);
	loff_t			cur = *pos;
	loff_t			end;
	ssize_t			nread = 0;
	struct page	   *page;

	end = Min(cur + len, PAGE_SIZE * bstate->nr_pages);
	while (cur < end)
	{
		loff_t		base = (cur & PAGE_MASK);
		size_t		page_ofs = (cur & (PAGE_SIZE - 1));
		size_t		page_len;
		char	   *kaddr;
		size_t		left;

		page = bstate->pages[(cur >> PAGE_SHIFT)];
		page_len = (end - base > PAGE_SIZE
					? PAGE_SIZE
					: end - base) - page_ofs;

		/* see logic in file_read_actor() */
		if (!fault_in_pages_writeable(buf, page_len))
		{
			kaddr = kmap_atomic(page);
			left = __copy_to_user_inatomic(buf, kaddr + page_ofs, page_len);
			kunmap_atomic(kaddr);
			if (left == 0)
				goto success;
		}
		/* fallback if fast-path is not available */
		kaddr = kmap(page);
		left = __copy_to_user(buf, kaddr + page_ofs, page_len);
		kunmap(page);
		if (left)
			return -EFAULT;

	success:
		buf += page_len;
		cur += page_len;
		nread += page_len;
	}
	*pos = cur;
	return nread;
}

/*
 * write(2) handler
 */
static ssize_t
pgblitz_file_write(struct file *filp, const char __user *buf, size_t len,
				   loff_t *pos)
{
	pgblitz_buffer_state *bstate = pgblitz_get_buffer(filp);
	loff_t			cur = *pos;
	loff_t			end;
	ssize_t			nwritten = 0;
	struct page	   *page;

	end = Min(cur + len, PAGE_SIZE * bstate->nr_pages);
	while (cur < end)
	{
		loff_t		base = (cur & PAGE_MASK);
		size_t		page_ofs = (cur & (PAGE_SIZE - 1));
		size_t		page_len;
		char	   *kaddr;
		size_t		left;

		page = bstate->pages[(cur >> PAGE_SHIFT)];
		page_len = (end - base > PAGE_SIZE
					? PAGE_SIZE
					: end - base) - page_ofs;

		/* see logic in copy_page_from_iter */
		if (!fault_in_pages_readable(buf, page_len))
		{
			kaddr = kmap_atomic(page);
			left = __copy_from_user_inatomic(kaddr + page_ofs, buf, page_len);
			kunmap_atomic(kaddr);

			if (left == 0)
				goto success;
		}
		/* fallback if fast-path was not available */
		kaddr = kmap(page);
		left = __copy_from_user(kaddr + page_ofs, buf, page_len);
		kunmap(page);
		if (left)
		{
			nwritten = -EFAULT;
			break;
		}
	success:
		buf += page_len;
		cur += page_len;
		nwritten += page_len;
	}
	*pos = cur;
	return nwritten;
}

/*
 * mmap(2) handler
 */
static int
pgblitz_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	pgblitz_buffer_state *bstate;
	struct file	   *filp = vma->vm_file;
	struct inode   *f_inode = filp->f_inode;
	struct page	   *page;
	pgoff_t			pgoff = vma->vm_pgoff + vmf->pgoff;
	int				minor;

	Assert(MAJOR(f_inode->i_rdev) == pgblitz_chrdev_major);
	minor = MINOR(f_inode->i_rdev);

	if (minor >= pgblitz_num_buffers)
		return VM_FAULT_NOPAGE;

	bstate = &pgblitz_buffer_array[minor];
	if (pgoff >= (pgblitz_buffer_size >> PAGE_SHIFT))
		return VM_FAULT_SIGBUS;

	page = bstate->pages[pgoff];
	get_page(page);
	vmf->page = page;

	return 0;
}

static struct vm_operations_struct pgblitz_vm_ops =
{
	.fault = pgblitz_vm_fault
};

static int
pgblitz_file_mmap(struct file *filp, struct vm_area_struct* vma)
{
	if (PAGE_SIZE * vma->vm_pgoff +
		(vma->vm_end - vma->vm_start) > pgblitz_buffer_size)
		return -EINVAL;

	file_accessed(filp);
	vma->vm_ops = &pgblitz_vm_ops;
	return 0;
}

/*
 * close(2) handler
 */
static int
pgblitz_file_release(struct inode *inode, struct file *filp)
{
	return 0;
}

/*
 * ioctl(2) handler
 */
static long
pgblitz_file_ioctl(struct file *ioctl_filp,
                 unsigned int cmd,
                 unsigned long uarg)
{
	long	retval;

	switch (cmd)
	{
		case BLITZ_IOCTL__BUFFER_SIZE:
			retval = pgblitz_ioctl__buffer_size((void __user *)uarg);
			break;
		case BLITZ_IOCTL__CHECK_FILE:
			retval = pgblitz_ioctl__check_file((void __user *)uarg);
			break;
		case BLITZ_IOCTL__WRITE_FILE:
			retval = pgblitz_ioctl__write_file((void __user *)uarg);
			break;
		case BLITZ_IOCTL__WRITE_FILE_ASYNC:
			retval = -ENOTSUPP;
			break;
		case BLITZ_IOCTL__FLUSH_FILE:
			retval = pgblitz_ioctl__flush_file((void __user *)uarg);
			break;
		default:
			retval = -EINVAL;
			break;
	}
	return retval;
}

/* device file operations */
static const struct file_operations pgblitz_file_ops = {
	.owner			= THIS_MODULE,
	.open			= pgblitz_file_open,
	.read			= pgblitz_file_read,
	.write			= pgblitz_file_write,
	.mmap			= pgblitz_file_mmap,
	.release		= pgblitz_file_release,
	.unlocked_ioctl	= pgblitz_file_ioctl,
	.compat_ioctl	= pgblitz_file_ioctl,
};

void
pgblitz_exit_module(void)
{
	int		i, j;

	for (i=0; i < pgblitz_num_buffers; i++)
	{
		pgblitz_buffer_state *bstate = &pgblitz_buffer_array[i];

		if (!bstate->pages)
			continue;
		for (j=0; j < bstate->nr_pages; j++)
		{
			if (bstate->pages[j])
				__free_page(bstate->pages[j]);
		}
		if (pgblitz_buffer_devices[i])
			device_destroy(pgblitz_sys_class,
						   MKDEV(pgblitz_chrdev_major, i));
	}
	unregister_chrdev(pgblitz_chrdev_major, PGBLITZ_DEVNAME);
	class_destroy(pgblitz_sys_class);
	strom_exit_extra_symbols();
}
module_exit(pgblitz_exit_module);

int __init
pgblitz_init_module(void)
{
	int		nr_pages;
	int		i, j;

	/* sanity checks */
	if (pgblitz_num_buffers < 1 ||
		pgblitz_num_buffers > PGBLITZ_MAX_BUFFERS)
	{
		prError("Invalid number of PG-Blitz buffers: %d",
				pgblitz_num_buffers);
		return -EINVAL;
	}

	if (pgblitz_buffer_size < PAGE_SIZE)
	{
		prError("Buffer size must be larger than PAGE_SIZE: %zu",
				(size_t)pgblitz_buffer_size);
		return -EINVAL;
	}
	if (pgblitz_buffer_size & (PAGE_SIZE - 1))
	{
		prError("Buffer size must be multiple of PAGE_SIZE: %zu",
				(size_t)pgblitz_buffer_size);
		return -EINVAL;
	}
	nr_pages = pgblitz_buffer_size >> PAGE_SHIFT;

	/* find out extra symbols */
	strom_init_extra_symbols();

	/* registration of character device */
	pgblitz_chrdev_major = register_chrdev(0, PGBLITZ_DEVNAME,
										   &pgblitz_file_ops);
	if (pgblitz_chrdev_major < 0)
	{
		strom_exit_extra_symbols();
		return pgblitz_chrdev_major;
	}

	/* registration of udev class */
	pgblitz_sys_class = class_create(THIS_MODULE, PGBLITZ_DEVNAME);
	if (IS_ERR(pgblitz_sys_class))
	{
		unregister_chrdev(pgblitz_chrdev_major, PGBLITZ_DEVNAME);
		strom_exit_extra_symbols();
		return PTR_ERR(pgblitz_sys_class);
	}

	/* init buffers */
	memset(pgblitz_buffer_array, 0, sizeof(pgblitz_buffer_array));
	for (i=0; i < pgblitz_num_buffers; i++)
	{
		pgblitz_buffer_state *bstate = &pgblitz_buffer_array[i];
		struct device  *device;

		rwlock_init(&bstate->lock);
		bstate->nr_pages = nr_pages;
		bstate->pages = kzalloc(sizeof(struct page *) * nr_pages,
								GFP_KERNEL);
		if (!bstate->pages)
			goto out_of_memory;
		for (j=0; j < nr_pages; j++)
		{
			bstate->pages[j] = alloc_page(GFP_KERNEL | GFP_DMA32 | __GFP_ZERO);
			if (!bstate->pages[j])
				goto out_of_memory;
		}

		device = device_create(pgblitz_sys_class, NULL,
							   MKDEV(pgblitz_chrdev_major, i),
							   NULL,
							   PGBLITZ_DEVNAME "%d", i);
		if (IS_ERR(device))
		{
			pgblitz_exit_module();
			return PTR_ERR(device);
		}
		pgblitz_buffer_devices[i] = device;
	}
	return 0;

out_of_memory:
	pgblitz_exit_module();
	return -ENOMEM;
}
module_init(pgblitz_init_module);

MODULE_AUTHOR("KaiGai Kohei <kaigai@kaigai.gr.jp>");
MODULE_DESCRIPTION("Zero-Copy NVMe-SSD Block Write Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0devel");
