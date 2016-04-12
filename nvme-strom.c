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
#include <linux/nvme.h>
#include <linux/notifier.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/version.h>
#include "nv-p2p.h"
#include "nvme-strom.h"

/* prefix of printk */
#define NVME_STROM_PREFIX "nvme-strom: "

/* check the target kernel to build */
#if defined(RHEL_MAJOR) && (RHEL_MAJOR == 7)
#define STROM_TARGET_KERNEL_RHEL7		1
#else
#error not supported kernel
#endif

/* routines for extra symbols */
#include "extra-ksyms.c"

/*
 * for boundary alignment requirement
 */
#define GPU_BOUND_SHIFT		16
#define GPU_BOUND_SIZE		((u64)1 << GPU_BOUND_SHIFT)
#define GPU_BOUND_OFFSET	(GPU_BOUND_SIZE-1)
#define GPU_BOUND_MASK		(~GPU_BOUND_OFFSET)

/* procfs entry of "/proc/nvme-strom" */
static struct proc_dir_entry  *nvme_strom_proc = NULL;








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
 * strom_ioctl_pin_gpu_memory - ioctl(2) handler to pin device memory
 * strom_ioctl_unpin_gpu_memory - ioctl(2) handler to unpin device memory
 *
 * ================================================================
 */
#define PINNED_GPU_MEMORY_NSLOTS		100
static struct mutex		strom_pgmem_mutex[PINNED_GPU_MEMORY_NSLOTS];
static struct list_head	strom_pgmem_slots[PINNED_GPU_MEMORY_NSLOTS];

static inline int
strom_pgmem_index(unsigned long handle)
{
	u32		hash = arch_fast_hash(&handle, sizeof(unsigned long),
								  PINNED_GPU_MEMORY_NSLOTS);
	return hash % PINNED_GPU_MEMORY_NSLOTS;
}

typedef struct pinned_gpu_memory
{
	struct list_head	chain;			/* chain to the strom_pgmem_slots */
	int					usecnt;			/* number of concurrent tasks */
	pid_t				owner;			/* PID of the task who pinned */
	unsigned long		handle;			/* identifier of this entry */
	uint64_t			base_address;	/* aligned device virtual address */
	uint64_t			base_offset;	/* offset to user given address */
	uint64_t			base_length;	/* length from the base_address */
	struct task_struct *wait_task;		/* task waiting for DMA completion */
	nvidia_p2p_page_table_t *page_table;
	/*
	 * NOTE: Exclusion control. Once a pinned_gpu_memory is registered,
	 * it can be released by random and concurrent timing on ioclt(2),
	 * cuFreeMem() and others.
	 * If usecnt > 0, it means someone's DMA is in progress, so cleanup
	 * routine has to wait for completion, but detach pinned_gpu_memory
	 * entry from the slot not to be released twice or more.
	 */
} pinned_gpu_memory;


static pinned_gpu_memory *
strom_get_pinned_memory(unsigned long handle)
{
	int					index = strom_pgmem_index(handle);
	struct mutex	   *mutex = &strom_pgmem_mutex[index];
	struct list_head   *slot = &strom_pgmem_slots[index];
	pinned_gpu_memory  *pgmem;

	mutex_lock(mutex);
	list_for_each_entry(pgmem, slot, chain)
	{
		if (pgmem->handle != handle)
			continue;
		/* sanity checks */
		BUG_ON((unsigned long)pgmem != handle);
		BUG_ON(!pgmem->page_table);

		pgmem->usecnt++;

		mutex_unlock(mutex);
		return pgmem;
	}
	mutex_unlock(mutex);

	return NULL;	/* not found */
}

static void
strom_put_pinned_memory(pinned_gpu_memory *pgmem)
{
	int			index = strom_pgmem_index(pgmem->handle);

	mutex_lock(&strom_pgmem_mutex[index]);
	BUG_ON(pgmem->usecnt == 0);
	pgmem->usecnt--;
	if (pgmem->usecnt == 0 && pgmem->wait_task != NULL)
		wake_up_process(pgmem->wait_task);
	mutex_unlock(&strom_pgmem_mutex[index]);
}

/*
 * strom_clenup_gpu_memory - remove P2P page tables
 */
static void
strom_clenup_gpu_memory(void *private)
{
	unsigned long		handle = (unsigned long) private;
	int					index = strom_pgmem_index(handle);
	struct mutex	   *mutex = &strom_pgmem_mutex[index];
	struct list_head   *slot = &strom_pgmem_slots[index];
	pinned_gpu_memory  *pgmem;
	int					rc;

	mutex_lock(mutex);
	list_for_each_entry(pgmem, slot, chain)
	{
		if (pgmem->handle != handle)
			continue;

		/* sanity check */
		BUG_ON((unsigned long)pgmem != handle);
		BUG_ON(!pgmem->page_table);

		/*
		 * detach entry; no concurrent task can never touch this
		 * entry any more.
		 */
		list_del(&pgmem->chain);

		/*
		 * needs to wait for completion of concurrent DMA completion,
		 * if any task are running on.
		 */
		while (pgmem->usecnt > 0)
		{
			BUG_ON(pgmem->wait_task != NULL);
			pgmem->wait_task = current;
			set_current_state(TASK_UNINTERRUPTIBLE);
			mutex_unlock(mutex);

			schedule();

			mutex_lock(mutex);
		}
		mutex_unlock(mutex);

		/*
		 * OK, at this point, no concurrent task does not use this
		 * P2P GPU Memory.
		 */
		rc = __nvidia_p2p_free_page_table(pgmem->page_table);
		if (rc)
			printk(KERN_ERR NVME_STROM_PREFIX
				   "nvidia_p2p_free_page_table (handle=%lu, rc=%d)\n",
				   handle, rc);

		kfree(pgmem);

		printk(KERN_ERR NVME_STROM_PREFIX
			   "P2P GPU Memory (handle=%lu) was released\n", handle);
		return;
	}
	mutex_unlock(mutex);
	printk(KERN_ERR NVME_STROM_PREFIX
		   "P2P GPU Memory (handle=%lu) already released\n", handle);
}




/*
 * source_file_is_supported - checks whether the supplied 'filp' is
 * available to read contents using P2P DMA on NVMe SSD.
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

/*
 * strom_ioctl_check_supported
 *
 * ioctl(2) handler for STROM_IOCTL_CHECK_SUPPORTED
 */
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
	pinned_gpu_memory *gmem;
	int			index;
	int			rc;

	if (copy_from_user(&karg, uarg, sizeof(karg)))
		return -EFAULT;

	gmem = kmalloc(sizeof(pinned_gpu_memory), GFP_KERNEL);
	if (!gmem)
		return -ENOMEM;

	INIT_LIST_HEAD(&gmem->chain);
	gmem->usecnt = 0;
	gmem->owner = current->tgid;
	gmem->handle = (unsigned long) gmem;	/* pointer as unique identifier */
	gmem->base_address = karg.address & GPU_BOUND_MASK;
	gmem->base_offset = karg.address - gmem->base_address;
	gmem->base_length = gmem->base_offset + karg.length;
	gmem->wait_task = NULL;

	rc = __nvidia_p2p_get_pages(0,	/* p2p_token; deprecated */
								0,	/* va_space_token; deprecated */
								gmem->base_address,
								gmem->base_length,
								&gmem->page_table,
								strom_clenup_gpu_memory,
								gmem);
	if (rc)
	{
		printk(KERN_ERR NVME_STROM_PREFIX
			   "failed on nvidia_p2p_get_pages(addr=%p, length=%zu), rc=%d\n",
			   (void *)gmem->base_address, (size_t)gmem->base_length, rc);
		goto error_1;
	}

	/*
	 * return handle of pinned_gpu_memory
	 */
	rc = put_user(gmem->handle, &uarg->handle);
	if (rc)
		goto error_2;

	/* debug output */
	{
		nvidia_p2p_page_table_t *page_table = gmem->page_table;

		printk(KERN_INFO NVME_STROM_PREFIX
			   "P2P GPU Memory (handle=%lu) was mapped\n"
			   "  version=%u, page_size=%u, entries=%u\n",
			   gmem->handle,
			   page_table->version,
			   page_table->page_size,
			   page_table->entries);
		for (index=0; index < page_table->entries; index++)
		{
			printk(KERN_INFO NVME_STROM_PREFIX
				   "  H:%p <--> D:%p\n",
				   (void *)(gmem->base_address +
							index * page_table->page_size),
				   (void *)(page_table->pages[index]->physical_address));
		}
	}

	/*
	 * attach this pinned_gpu_memory
	 */
	index = strom_pgmem_index(gmem->handle);
	mutex_lock(&strom_pgmem_mutex[index]);
	list_add(&strom_pgmem_slots[index], &gmem->chain);
	mutex_unlock(&strom_pgmem_mutex[index]);

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
	struct mutex	   *mutex;
	struct list_head   *slot;
	pinned_gpu_memory  *pgmem;
	int					rc;

	if (copy_from_user(&karg, uarg, sizeof(karg)))
		return -EFAULT;

	index = strom_pgmem_index(karg.handle);
	mutex = &strom_pgmem_mutex[index];
	slot = &strom_pgmem_slots[index];

	mutex_lock(mutex);
	list_for_each_entry(pgmem, slot, chain)
	{
		if (pgmem->handle != karg.handle)
			continue;

		/* sanity checks */
		BUG_ON((unsigned long)pgmem != karg.handle);
		BUG_ON(!pgmem->page_table);

		/*
		 * detach entry; no concurrent task can never touch this
		 * entry any more.
		 */
		list_del(&pgmem->chain);

		/*
		 * needs to wait for completion of concurrent DMA completion,
		 * if any task are running on.
		 */
		while (pgmem->usecnt > 0)
		{
			BUG_ON(pgmem->wait_task != NULL);
			pgmem->wait_task = current;
			set_current_state(TASK_UNINTERRUPTIBLE);
			mutex_unlock(mutex);

			schedule();

			mutex_lock(mutex);
		}
		mutex_unlock(mutex);

		rc = __nvidia_p2p_put_pages(0,	/* p2p_token */
									0,	/* va_space_token */
									pgmem->base_address,
									pgmem->page_table);
		if (rc)
		{
			/* hmm... we have to attach pgmem again... */
			pgmem->wait_task = NULL;
			mutex_lock(mutex);
			list_add(slot, &pgmem->chain);
			mutex_unlock(mutex);

			printk(KERN_ERR NVME_STROM_PREFIX
				   "nvidia_p2p_put_pages (handle=%lu, addr=%p, rc=%d)\n",
				   karg.handle, (void *)pgmem->base_address, rc);
			return rc;
		}

		rc = __nvidia_p2p_free_page_table(pgmem->page_table);
		if (rc)
			printk(KERN_ERR NVME_STROM_PREFIX
				   "nvidia_p2p_free_page_table (handle=%lu, rc=%d)\n",
				   karg.handle, rc);

		printk(KERN_INFO NVME_STROM_PREFIX
			   "P2P GPU Memory (handle=%lu) was unmapped\n",
			   pgmem->handle);

		kfree(pgmem);

		return 0;
	}
	mutex_unlock(mutex);

	return -ENOENT;
}

/* ================================================================
 *
 * Main part of SSD-to-GPU P2P DMA
 *
 * ================================================================
 */




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
static void *
strom_proc_seq_start(struct seq_file *m, loff_t *pos)
{
	unsigned long		handle = (unsigned long) m->private;
	struct mutex	   *mutex;
	struct list_head   *slot;
	pinned_gpu_memory  *pgmem;
	int					index;

	if (handle == 0)
		index = 0;		/* walk on the slot from the head */
	else
	{
		bool			pickup_next = false;

		index = strom_pgmem_index(handle);
		mutex = &strom_pgmem_mutex[index];
		slot  = &strom_pgmem_slots[index];

		mutex_lock(mutex);
		list_for_each_entry(pgmem, slot, chain)
		{
			if (pickup_next)
			{
				m->private = (void *) pgmem->handle;
				return pgmem;
			}
			if (pgmem->handle == handle)
				pickup_next = true;
		}
		mutex_unlock(mutex);

		index++;
	}

	while (index < PINNED_GPU_MEMORY_NSLOTS)
	{
		mutex	= &strom_pgmem_mutex[index];
		slot	= &strom_pgmem_slots[index];

		mutex_lock(mutex);
		list_for_each_entry(pgmem, slot, chain)
		{
			m->private = (void *) pgmem->handle;
			return pgmem;
		}
		mutex_unlock(mutex);

		index++;
	}
	return NULL;	/* no entry was registered */
}

static void *
strom_proc_seq_next(struct seq_file *m, void *p, loff_t *pos)
{
	pinned_gpu_memory  *pgmem = (pinned_gpu_memory *) p;
	int					index = strom_pgmem_index(pgmem->handle);
	struct mutex	   *mutex = &strom_pgmem_mutex[index];
	struct list_head   *slot = &strom_pgmem_slots[index];

	/* pick up next entry in the same slot (still in lock) */
	list_for_each_entry_continue(pgmem, slot, chain)
		return pgmem;
	mutex_unlock(mutex);

	/* no entry any more, so pick up the next entry from the next slot */
	while (++index < PINNED_GPU_MEMORY_NSLOTS)
	{
		mutex = &strom_pgmem_mutex[index];
		slot = &strom_pgmem_slots[index];

		mutex_lock(mutex);
		list_for_each_entry(pgmem, slot, chain);
			return pgmem;
		mutex_unlock(mutex);
	}
	/* No pinned GPU memory any more */
	return NULL;
}

static void
strom_proc_seq_stop(struct seq_file *m, void *p)
{
	pinned_gpu_memory  *pgmem = (pinned_gpu_memory *) p;

	if (!pgmem)
		m->private = (void *) 0UL;	/* clear it */
	else
	{
		int		index = strom_pgmem_index(pgmem->handle);

		m->private = (void *) pgmem->handle;
		mutex_unlock(&strom_pgmem_mutex[index]);
	}
}

static int
strom_proc_seq_show(struct seq_file *m, void *p)
{
	pinned_gpu_memory *pgmem = (pinned_gpu_memory *) p;
	nvidia_p2p_page_table_t *page_table = pgmem->page_table;
	int			i;

	seq_printf(m, "P2P DMA GPU Mapping (handle=%lu, pid=%u, vaddress=%p-%p)\n",
			   pgmem->handle,
			   pgmem->owner,
			   (void *)(pgmem->base_address + pgmem->base_offset),
			   (void *)(pgmem->base_address + pgmem->base_length));
	seq_printf(m, "    GPU Page Table (ver=%u, page_size=%u, entries=%u)\n",
			   page_table->version,
			   page_table->page_size,
			   page_table->entries);
	for (i=0; i < page_table->entries; i++)
	{
		seq_printf(m, "    H:%p <--> D:%p\n",
				   (void *)(pgmem->base_address + page_table->page_size * i),
				   (void *)(page_table->pages[i]->physical_address));
	}

	return 0;
}

static const struct seq_operations strom_proc_seq_ops = {
	.start		= strom_proc_seq_start,
	.next		= strom_proc_seq_next,
	.stop		= strom_proc_seq_stop,
	.show		= strom_proc_seq_show,
};

static int
strom_proc_open(struct inode *inode, struct file *filp)
{
	return seq_open(filp, &strom_proc_seq_ops);
}

static long
strom_proc_ioctl(struct file *filp,
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

/* device file operations */
static const struct file_operations nvme_strom_fops = {
	.owner			= THIS_MODULE,
	.open			= strom_proc_open,
	.read			= seq_read,
	.llseek			= seq_lseek,
	.release		= seq_release,
	.unlocked_ioctl	= strom_proc_ioctl,
	.compat_ioctl	= strom_proc_ioctl,
};

int	__init nvme_strom_init(void)
{
	int		i, rc;

	/* init strom_pgmem_mutex/slots */
	for (i=0; i < PINNED_GPU_MEMORY_NSLOTS; i++)
	{
		mutex_init(&strom_pgmem_mutex[i]);
		INIT_LIST_HEAD(&strom_pgmem_slots[i]);
	}

	/* make "/proc/nvme-strom" entry */
	nvme_strom_proc = proc_create("nvme-strom",
								  0444,
								  NULL,
								  &nvme_strom_fops);
	if (!nvme_strom_proc)
		return -ENOMEM;

	/* solve mandatory symbols */
	rc = strom_init_extra_symbols();
	if (rc)
	{
		proc_remove(nvme_strom_proc);
		return rc;
	}
	printk(KERN_INFO NVME_STROM_PREFIX
		   "/proc/nvme-strom entry was registered\n");
	return 0;
}
module_init(nvme_strom_init);

void __exit nvme_strom_exit(void)
{
	strom_exit_extra_symbols();
	proc_remove(nvme_strom_proc);
	printk(KERN_INFO NVME_STROM_PREFIX
		   "/proc/nvme-strom entry was unregistered\n");
}
module_exit(nvme_strom_exit);

MODULE_AUTHOR("KaiGai Kohei <kaigai@kaigai.gr.jp>");
MODULE_DESCRIPTION("SSD-to-GPU Direct Stream Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
