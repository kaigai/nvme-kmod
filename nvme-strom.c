/*
 * NVMe-Strom
 *
 * A Linux kernel driver to support SSD-to-GPU direct stream.
 *
 *
 *
 *
 */
#include <asm/uaccess.h>
#include <linux/crc32c.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/magic.h>
#include <linux/major.h>
#include <linux/module.h>
#include <linux/nvme.h>
#include <linux/notifier.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/version.h>
#include "nv-p2p.h"
#include "nvme-strom.h"

/*
 * for boundary alignment requirement
 */
#define GPU_BOUND_SHIFT		16
#define GPU_BOUND_SIZE		((u64)1 << GPU_BOUND_SHIFT)
#define GPU_BOUND_OFFSET	(GPU_BOUND_SIZE-1)
#define GPU_BOUND_MASK		(~GPU_BOUND_OFFSET)

/* prefix of printk */
#define NVME_STROM_PREFIX "nvme-strom: "

/* procfs entry of "/proc/nvme-strom" */
static struct proc_dir_entry  *nvme_strom_proc = NULL;

/*
 * Pointers of symbols not exported.
 */
#ifndef CONFIG_KALLSYMS
#error Linux kernel has to be built with CONFIG_KALLSYMS
#endif
/* nvidia_p2p_get_pages */
static struct module *mod_nvidia_p2p_get_pages = NULL;
static int (* p_nvidia_p2p_get_pages)(uint64_t p2p_token,
									  uint32_t va_space,
									  uint64_t virtual_address,
									  uint64_t length,
									  struct nvidia_p2p_page_table **p_table,
									  void (*free_callback)(void *data),
									  void *data);
inline int
__nvidia_p2p_get_pages(uint64_t p2p_token,
					   uint32_t va_space,
					   uint64_t virtual_address,
					   uint64_t length,
					   struct nvidia_p2p_page_table **page_table,
					   void (*free_callback)(void *data),
					   void *data)
{
	if (unlikely(!p_nvidia_p2p_get_pages))
		return -EINVAL;
	return p_nvidia_p2p_get_pages(p2p_token,
								  va_space,
								  virtual_address,
								  length,
								  page_table,
								  free_callback,
								  data);
}

/* nvidia_p2p_put_pages */
static struct module *mod_nvidia_p2p_put_pages = NULL;
static int (* p_nvidia_p2p_put_pages)(uint64_t p2p_token,
									  uint32_t va_space,
									  uint64_t virtual_address,
									  struct nvidia_p2p_page_table *p_table);
static inline int
__nvidia_p2p_put_pages(uint64_t p2p_token, 
					   uint32_t va_space,
					   uint64_t virtual_address,
					   struct nvidia_p2p_page_table *page_table)
{
	if (unlikely(!p_nvidia_p2p_put_pages))
		return -EINVAL;
	return p_nvidia_p2p_put_pages(p2p_token,
								  va_space,
								  virtual_address,
								  page_table);
}

/* ext4_get_block */
static struct module *mod_ext4_get_block = NULL;
static int (* p_ext4_get_block)(struct inode *inode, sector_t offset,
								struct buffer_head *bh, int create) = NULL;
static inline int
ext4_get_block(struct inode *inode, sector_t offset,
			   struct buffer_head *bh, int create)
{
	if (unlikely(!p_ext4_get_block))
		return -EINVAL;
	return p_ext4_get_block(inode, offset, bh, create);
}

/* xfs_get_blocks */
static struct module *mod_xfs_get_blocks = NULL;
static int (* p_xfs_get_blocks)(struct inode *inode, sector_t offset,
								struct buffer_head *bh, int create) = NULL;
static inline int
xfs_get_blocks(struct inode *inode, sector_t offset,
			   struct buffer_head *bh, int create)
{
	if (unlikely(!p_xfs_get_blocks))
		return -EINVAL;
	return p_xfs_get_blocks(inode, offset, bh, create);
}

/* ================================================================
 *
 * features to pin/unpin device memory for P2P DMA stuff
 *
 *
 *
 *
 *
 *
 *
 * strom_on_release_gpu_memory - callback when device memory is released
 * strom_ioctl_pin_gpu_memory - ioctl(2) handler to pin device memory
 * strom_ioctl_unpin_gpu_memory - ioctl(2) handler to unpin device memory
 *
 * ================================================================
 */
#define PINNED_GPU_MEMORY_NSLOTS		100
static spinlock_t		strom_pgmem_locks[PINNED_GPU_MEMORY_NSLOTS];
static struct list_head	strom_pgmem_slots[PINNED_GPU_MEMORY_NSLOTS];

typedef struct pinned_gpu_memory
{
	int					refcnt;			/* reference counter */
	struct list_head	chain;			/* chain to the pgmem_slot */
	unsigned long		handle;			/* identifier of this entry */
	uint64_t			base_address;	/* aligned device virtual address */
	uint64_t			base_offset;	/* offset to user given address */
	struct nvidia_p2p_page_table *page_table;
} pinned_gpu_memory;

static pinned_gpu_memory *
strom_get_pinned_memory(unsigned long handle)
{
	int					index = handle % PINNED_GPU_MEMORY_NSLOTS;
	spinlock_t		   *lock = &strom_pgmem_locks[index];
	struct list_head   *slot = &strom_pgmem_slots[index];
	unsigned long		flags;
	pinned_gpu_memory  *pgmem;

	spin_lock_irqsave(lock, flags);
	list_for_each_entry(pgmem, slot, chain)
	{
		if (pgmem->handle != handle)
			continue;
		BUG_ON((unsigned long)pgmem != handle);

		/* is it still valid? */
		if (!pgmem->page_table)
			goto not_found;

		pgmem->refcnt++;

		spin_unlock_irqrestore(lock, flags);
		return pgmem;
	}
not_found:
	spin_unlock_irqrestore(lock, flags);
	return NULL;
}

static void
strom_put_pinned_memory(pinned_gpu_memory *pgmem)
{
	int					index = pgmem->handle % PINNED_GPU_MEMORY_NSLOTS;
	spinlock_t		   *lock = &strom_pgmem_locks[index];
	unsigned long		flags;

	spin_lock_irqsave(lock, flags);
	if (--pgmem->refcnt > 0)
	{
		/* quick bailout if this pinned gpu memory is still valid  */
		spin_unlock_irqrestore(lock, flags);
		return;
	}

	/* once detached, never acquired again */
	list_del(&pgmem->chain);
	spin_unlock_irqrestore(lock, flags);
	/*
	 * MEMO: nvidia_p2p_put_pages() is implemented in the proprietary
	 * driver portion, thus, we cannot ensure whether it is workable
	 * under the spinlock. So, we choose a safe design.
	 */

	/* is the page_table still valid? */
	if (pgmem->page_table)
	{
		int		rc = __nvidia_p2p_put_pages(0,	/* p2p_token */
											0,	/* va_space_token */
											pgmem->base_address,
											pgmem->page_table);
		if (rc)
			printk(KERN_ERR NVME_STROM_PREFIX
				   "failed on nvidia_p2p_put_pages: %d\n", rc);
	}
	printk(KERN_INFO NVME_STROM_PREFIX
		   "Pinned GPU Memory Handle %lu was released", pgmem->handle);
	kfree(pgmem);
}

/*
 * strom_on_release_gpu_memory
 *
 * callback handler to release P2P page tables when GPU device memory block
 * is released.
 */
static void
strom_on_release_gpu_memory(void *data)
{
	unsigned long		handle = (unsigned long) data;
	int					index = handle % PINNED_GPU_MEMORY_NSLOTS;
	spinlock_t		   *lock = &strom_pgmem_locks[index];
	struct list_head   *slot = &strom_pgmem_slots[index];
	unsigned long		flags;
	pinned_gpu_memory  *pgmem;
	struct nvidia_p2p_page_table *page_table = NULL;

	/* find by handle */
	spin_lock_irqsave(lock, flags);
	list_for_each_entry(pgmem, slot, chain)
	{
		if (pgmem->handle != handle)
			continue;

		/* sanity check */
		BUG_ON((unsigned long)pgmem != handle);

		/* page table has to be still valid */
		if (!pgmem->page_table)
			panic(NVME_STROM_PREFIX
				  "nvidia_p2p_page_table is invalid on free callback\n");
		page_table = pgmem->page_table;
		pgmem->page_table = NULL;

		/* someone still reference? */
		if (--pgmem->refcnt == 0)
		{
			list_del(&pgmem->chain);
			kfree(pgmem);
		}
	}
	spin_unlock_irqrestore(lock, flags);

	/*
	 * release nvidia_p2p_page_table out of the spinlock
	 *
	 * MEMO: nvidia_p2p_put_pages() is implemented in the proprietary
	 * driver portion, thus, we cannot ensure whether it is workable
	 * under the spinlock. So, we choose a safe design.
	 */
	if (page_table)
	{
		int		rc = __nvidia_p2p_put_pages(0,	/* p2p_token */
											0,	/* va_space_token */
											pgmem->base_address,
											pgmem->page_table);
		if (rc)
			printk(KERN_ERR NVME_STROM_PREFIX
				   "failed on nvidia_p2p_put_pages: %d\n", rc);
	}
}

/*
 * strom_ioctl_check_supported
 *
 * ioctl(2) handler for STROM_IOCTL_CHECK_SUPPORTED
 */


static int
source_file_is_supported(struct file *filp)
{
	struct inode		   *f_inode = filp->f_inode;
	struct super_block	   *i_sb = f_inode->i_sb;
	struct block_device	   *s_bdev = i_sb->s_bdev;
	struct file_system_type *s_type = i_sb->s_type;
	struct gendisk		   *bd_disk = s_bdev->bd_disk;
	const char			   *dname;
	int						rc;

	/*
	 * must have READ permission of the source file
	 */
	if ((filp->f_mode & FMODE_READ) == 0)
	{
		printk(KERN_ERR NVME_STROM_PREFIX
			   "process (pid=%u) has no permission to read file\n",
			   current->pid);
		return -EACCES;
	}


	/*
	 * check whether it is on supported filesystem
	 *
	 * MEMO: Linux VFS has no reliable way to lookup underlying block
	 *   number of individual files (and, may be impossible in some
	 *   filesystems), so our module solves file offset <--> block number
	 *   on a part of supported filesystems.
	 *
	 * supported: ext4, xfs
	 */
	if (!((strcmp(s_type->name, "ext4") == 0 &&
		   s_type->owner == mod_ext4_get_block) ||
		  (strcmp(s_type->name, "xfs") == 0 &&
		   s_type->owner == mod_xfs_get_blocks)))
	{
		printk(KERN_INFO NVME_STROM_PREFIX
			   "file_system_type name=%s, not supported", s_type->name);
		return 1;	/* not supported filesystem */
	}

	/*
	 * check whether underlying block device is NVMe-SSD
	 *
	 * MEMO: Our assumption is, the supplied file is located on NVMe-SSD,
	 * with other software layer (like dm-based RAID1).
	 */

	/* 'devext' shall wrap NVMe-SSD device */
	if (bd_disk->major != BLOCK_EXT_MAJOR)
	{
		printk(KERN_INFO NVME_STROM_PREFIX
			   "block device major number = %d, not 'blkext'\n",
			   bd_disk->major);
		return 1;
	}

	/* disk_name should be 'nvme%dn%d' */
	dname = bd_disk->disk_name;
	if (dname[0] == 'n' &&
		dname[1] == 'v' &&
		dname[2] == 'm' &&
		dname[3] == 'e')
	{
		const char *pos = dname + 4;
		const char *pos_saved = pos;

		while (*pos >= '0' && *pos <= '9')
			pos++;
		if (pos != pos_saved && *pos == 'n')
		{
			pos_saved = ++pos;

			while (*pos >= '0' && *pos <= '9')
				pos++;
			if (pos != pos_saved && *pos == '\0')
				dname = NULL;	/* OK, it is NVMe-SSD */
		}
	}

	if (dname)
	{
		printk(KERN_INFO NVME_STROM_PREFIX
			   "block device '%s' is not supported", dname);
		return 1;
	}

	/* try to call ioctl */
	if (!bd_disk->fops->ioctl)
	{
		printk(KERN_INFO NVME_STROM_PREFIX
			   "block device '%s' does not provide ioctl\n",
			   bd_disk->disk_name);
		return 1;
	}

	rc = bd_disk->fops->ioctl(s_bdev, 0, NVME_IOCTL_ID, 0UL);
	if (rc < 0)
	{
		printk(KERN_INFO NVME_STROM_PREFIX
			   "ioctl(NVME_IOCTL_ID) on '%s' returned an error: %d\n",
			   bd_disk->disk_name, rc);
		return 1;
	}

	/* OK, we assume the underlying device is supported NVMe-SSD */
	return 0;
}

static int
strom_ioctl_check_supported(StromCmd__CheckSupported __user *uarg)
{
	StromCmd__CheckSupported karg;
	struct file	   *filp;
	int				rc;

	if (copy_from_user(&karg, uarg, sizeof(karg)))
		return -EFAULT;

	filp = fget(karg.fdesc);
	if (!filp)
		return -EBADF;

	rc = source_file_is_supported(filp);

	fput(filp);

	return rc;
}

/*
 * strom_ioctl_pin_gpu_memory
 *
 * ioctl(2) handler for STROM_IOCTL_PIN_GPU_MEMORY
 */
static int
strom_ioctl_pin_gpu_memory(StromCmd__PinGpuMemory __user *uarg)
{
	StromCmd__PinGpuMemory karg;
	pinned_gpu_memory  *gmem;
	size_t				pin_size;
	int					index;
	spinlock_t		   *lock;
	struct list_head   *slot;
	unsigned long		flags;
	int					rc;

	if (copy_from_user(&karg, uarg, sizeof(karg)))
		return -EFAULT;

	gmem = kmalloc(sizeof(pinned_gpu_memory), GFP_KERNEL);
	if (!gmem)
		return -ENOMEM;

	gmem->refcnt = 1;
	INIT_LIST_HEAD(&gmem->chain);
	gmem->handle = (unsigned long) gmem;	/* pointer as unique identifier */
	gmem->base_address = karg.address & GPU_BOUND_MASK;
	gmem->base_offset = karg.address - gmem->base_address;

	pin_size = karg.address + karg.length - gmem->base_address;
	rc = __nvidia_p2p_get_pages(0,	/* p2p_token; deprecated */
								0,	/* va_space_token; deprecated */
								gmem->base_address,
								pin_size,
								&gmem->page_table,
								strom_on_release_gpu_memory,
								gmem);
	if (rc)
		goto error_1;

	/*
	 * return handle of pinned_gpu_memory
	 */
	rc = put_user(gmem->handle, &uarg->handle);
	if (rc)
		goto error_2;

	/*
	 * attach this pinned_gpu_memory
	 */
	index = gmem->handle % PINNED_GPU_MEMORY_NSLOTS;
	lock = &strom_pgmem_locks[index];
	slot = &strom_pgmem_slots[index];

	spin_lock_irqsave(lock, flags);
	list_add(slot, &gmem->chain);
	spin_unlock_irqrestore(lock, flags);

	return 0;

error_2:
	__nvidia_p2p_put_pages(0, 0, gmem->base_address, gmem->page_table);
error_1:
	kfree(gmem);

	return rc;
}

/*
 * strom_ioctl_unpin_gpu_memory
 *
 * ioctl(2) handler for STROM_IOCTL_UNPIN_GPU_MEMORY
 */
static int
strom_ioctl_unpin_gpu_memory(StromCmd__UnpinGpuMemory __user *uarg)
{
	StromCmd__UnpinGpuMemory karg;
	int					index;
	spinlock_t		   *lock;
	struct list_head   *slot;
	unsigned long		flags;
	pinned_gpu_memory *pgmem;

	if (copy_from_user(&karg, uarg, sizeof(karg)))
		return -EFAULT;

	index = karg.handle % PINNED_GPU_MEMORY_NSLOTS;
	lock = &strom_pgmem_locks[index];
	slot = &strom_pgmem_slots[index];

	spin_lock_irqsave(lock, flags);
	list_for_each_entry(pgmem, slot, chain)
	{
		if (pgmem->handle != karg.handle)
			continue;
		BUG_ON((unsigned long)pgmem != karg.handle);

		/* quick bailout if this pinned gpu memory is still valid  */
		if (--pgmem->refcnt > 0)
		{
			spin_unlock_irqrestore(lock, flags);
			return 0;
		}

		/* once detached, never acquired again */
		list_del(&pgmem->chain);
		spin_unlock_irqrestore(lock, flags);

		/* is the page_table still valid? */
		if (pgmem->page_table)
		{
			int		rc = __nvidia_p2p_put_pages(0,	/* p2p_token */
												0,	/* va_space_token */
												pgmem->base_address,
												pgmem->page_table);
			if (rc)
				printk(KERN_ERR NVME_STROM_PREFIX
					   "failed on nvidia_p2p_put_pages: %d\n", rc);
		}
		printk(KERN_INFO NVME_STROM_PREFIX
			   "Pinned GPU Memory Handle %lu was released", pgmem->handle);
		kfree(pgmem);

		return 0;
	}
	spin_unlock_irqrestore(lock, flags);

	return -ENOENT;
}

/* ================================================================
 *
 * Main part of SSD-to-GPU P2P DMA
 *
 * ================================================================
 */

#if defined(RHEL_MAJOR) && (RHEL_MAJOR == 7)






#else
#error "not supported distribution"
#endif







static int
strom_ioctl_dma_ssd2gpu(StromCmd__MemcpySsd2Gpu __user *uarg)
{
	StromCmd__MemcpySsd2Gpu karg;
	pinned_gpu_memory  *pgmem;
	struct file		   *filp;
	int					rc = 0;

	if (copy_from_user(&karg, uarg,
					   offsetof(StromCmd__MemcpySsd2Gpu, chunks)))
		return -EFAULT;

	pgmem = strom_get_pinned_memory(karg.handle);
	if (!pgmem)
	{
		printk(KERN_ERR NVME_STROM_PREFIX
			   "Pinned GPU Memory (handle=%lu) not found\n", karg.handle);
		return -ENOENT;
	}

	filp = fget(karg.fdesc);
	if (!filp)
	{
		printk(KERN_ERR NVME_STROM_PREFIX
			   "File descriptor %d not found\n", karg.fdesc);
		rc = -EBADF;
		goto out_1;
	}

	rc = source_file_is_supported(filp);
	if (rc)
		goto out_2;

	/* OK, try to kick P2P DMA */



	/* release resources */
out_2:
	fput(filp);
out_1:
	strom_put_pinned_memory(pgmem);

	return rc;
}

/* ================================================================
 *
 * For debug
 *
 * ================================================================
 */
#include <linux/genhd.h>

static int strom_ioctl_debug(StromCmd__Debug __user *uarg)
{
	StromCmd__Debug		karg;
	struct file		   *filp;
	struct inode	   *f_inode;
	struct super_block *i_sb;
    struct address_space *i_mapping;
	struct block_device *s_bdev;
	struct gendisk	   *bd_disk;

	if (copy_from_user(&karg, uarg, sizeof(StromCmd__Debug)))
		return -EFAULT;

	filp = fget(karg.fdesc);
	printk(KERN_INFO "filp = %p\n", filp);
	if (!filp)
		return 0;

	f_inode = filp->f_inode;
	printk(KERN_INFO "filp->f_inode = %p\n", f_inode);
	if (!f_inode)
		goto out;

	i_sb = f_inode->i_sb;
	i_mapping = f_inode->i_mapping;

	printk(KERN_INFO "f_inode {i_sb = %p, i_mapping = %p}\n", i_sb, i_mapping);
	if (!i_sb)
		goto out;

	s_bdev = i_sb->s_bdev;
	printk(KERN_INFO "i_sb {s_dev = %x s_bdev = %p}\n", i_sb->s_dev, s_bdev);

	if (!s_bdev)
		goto out;
	printk(KERN_INFO "s_bdev {bd_inode=%p bd_block_size=%u bd_disk=%p}\n",
		   s_bdev->bd_inode, s_bdev->bd_block_size, s_bdev->bd_disk);

	bd_disk = s_bdev->bd_disk;
	if (!bd_disk)
		goto out;

	printk(KERN_INFO "bd_disk {major=%d first_minor=%d minors=%d disk_name=%s fops=%p",
		   bd_disk->major, bd_disk->first_minor, bd_disk->minors, bd_disk->disk_name, bd_disk->fops);
		   

out:
	fput(filp);

	return 0;
}

/* ================================================================
 *
 * file_operations of '/proc/nvme-strom' entry
 *
 * ================================================================
 */
static int
strom_proc_open(struct inode *inode, struct file *file)
{
	// TODO: print all the mapped GPU memory region using seq_read
	return 0;
}

static int
strom_proc_release(struct inode *inode, struct file *file)
{
	return 0;
}

static long
strom_proc_ioctl(struct file *file,
				 unsigned int cmd,
				 unsigned long arg)
{
	int		rc;

	switch (cmd)
	{
		case STROM_IOCTL_CHECK_SUPPORTED:
			rc = strom_ioctl_check_supported((void __user *) arg);
			break;
		case STROM_IOCTL_PIN_GPU_MEMORY:
			rc = strom_ioctl_pin_gpu_memory((void __user *) arg);
			break;
		case STROM_IOCTL_UNPIN_GPU_MEMORY:
			rc = strom_ioctl_unpin_gpu_memory((void __user *) arg);
			break;
		case STROM_IOCTL_DMA_SSD2GPU:
			rc = strom_ioctl_dma_ssd2gpu((void __user *) arg);
			break;
		case STROM_IOCTL_DEBUG:
			rc = strom_ioctl_debug((void __user *) arg);
			break;
		default:
			rc = -EINVAL;
			break;
	}
	return rc;
}

/*
 * strom_solve_extra_symbols
 *
 * solve the mandatory symbols on module load time
 */
static int __init
strom_solve_extra_symbols(void)
{
	unsigned long	addr;

	/* nvidia_p2p_get_pages */
	addr = kallsyms_lookup_name("nvidia_p2p_get_pages");
	if (!addr)
	{
		printk(KERN_ERR NVME_STROM_PREFIX
			   "could not solve the symbol: nvidia_p2p_get_pages\n");
		return -ENOENT;
	}
	p_nvidia_p2p_get_pages = (void *) addr;
	mod_nvidia_p2p_get_pages = __module_text_address(addr);
	if (mod_nvidia_p2p_get_pages)
		__module_get(mod_nvidia_p2p_get_pages);
	else
		printk(KERN_NOTICE NVME_STROM_PREFIX
			   "nvidia_p2p_get_pages is defined at core kernel?\n");

	/* nvidia_p2p_put_pages */
	addr = kallsyms_lookup_name("nvidia_p2p_put_pages");
	if (!addr)
	{
		printk(KERN_ERR NVME_STROM_PREFIX
			   "could not solve the symbol: nvidia_p2p_put_pages\n");
		return -ENOENT;
	}
	p_nvidia_p2p_put_pages = (void *) addr;
	mod_nvidia_p2p_put_pages = __module_text_address(addr);
	if (mod_nvidia_p2p_put_pages)
		__module_get(mod_nvidia_p2p_put_pages);
	else
		printk(KERN_NOTICE NVME_STROM_PREFIX
			   "nvidia_p2p_put_pages is defined at core kernel?\n");
	return 0;
}

/*
 * strom_update_extra_symbols
 *
 * update address of symbols that are not (officially) exported to module
 */
static int
strom_update_extra_symbols(struct notifier_block *nb,
						   unsigned long action, void *data)
{
	unsigned long	addr;

	if (!p_ext4_get_block)
	{
		addr = kallsyms_lookup_name("ext4_get_block");
		if (addr)
		{
			mod_ext4_get_block = __module_text_address(addr);
			if (mod_ext4_get_block)
				__module_get(mod_ext4_get_block);
			p_ext4_get_block = (void *) addr;
			printk(KERN_INFO NVME_STROM_PREFIX
				   "found ext4_get_block = %p\n", p_ext4_get_block);
		}
	}

	if (!p_xfs_get_blocks)
	{
		addr = kallsyms_lookup_name("xfs_get_blocks");
		if (addr)
		{
			mod_xfs_get_blocks = __module_text_address(addr);
			if (mod_xfs_get_blocks)
				__module_get(mod_xfs_get_blocks);
			p_xfs_get_blocks = (void *) addr;
			printk(KERN_INFO NVME_STROM_PREFIX
				   "found xfs_get_blocks = %p\n", p_xfs_get_blocks);
		}
	}
	return 0;
}

/* device file operations */
static const struct file_operations nvme_strom_fops = {
	.owner			= THIS_MODULE,
	.open			= strom_proc_open,
	.release		= strom_proc_release,
	.unlocked_ioctl	= strom_proc_ioctl,
	.compat_ioctl	= strom_proc_ioctl,
};

/* notifier for symbol resolver */
static struct notifier_block nvme_strom_nb = {
	.notifier_call	= strom_update_extra_symbols
};

int	__init nvme_strom_init(void)
{
	int		rc;

	/* solve the mandatory symbols */
	rc = strom_solve_extra_symbols();
	if (rc)
		return rc;

	/* make "/proc/nvme-strom" entry */
	nvme_strom_proc = proc_create("nvme-strom",
								  0444,
								  NULL,
								  &nvme_strom_fops);
	if (!nvme_strom_proc)
		return -ENOMEM;

	rc = register_module_notifier(&nvme_strom_nb);
	if (rc)
		goto out_1;
	printk(KERN_INFO "/proc/nvme-strom registered\n");

	return 0;

out_1:
	proc_remove(nvme_strom_proc);
	return rc;
}
module_init(nvme_strom_init);

void __exit nvme_strom_exit(void)
{
	module_put(mod_nvidia_p2p_get_pages);
	module_put(mod_nvidia_p2p_put_pages);
	module_put(mod_ext4_get_block);
	module_put(mod_xfs_get_blocks);

	unregister_module_notifier(&nvme_strom_nb);
	proc_remove(nvme_strom_proc);
	printk(KERN_INFO "/proc/nvme-strom unregistered\n");
}
module_exit(nvme_strom_exit);

MODULE_AUTHOR("KaiGai Kohei <kaigai@kaigai.gr.jp>");
MODULE_DESCRIPTION("SSD-to-GPU Direct Stream Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
