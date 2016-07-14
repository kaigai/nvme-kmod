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
#error Linux kernel not supported
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








/*
 * ================================================================
 *
 * Routines to map/unmap GPU device memory segment
 *
 * ================================================================
 */
struct mapped_gpu_memory
{
	struct list_head	chain;		/* chain to the strom_mgmem_slots[] */
	int					refcnt;		/* number of the concurrent tasks */
	pid_t				owner;		/* PID who mapped this device memory */
	unsigned long		handle;		/* identifier of this entry */
	unsigned long		map_address;/* virtual address of the device memory
									 * (note: just for message output) */
	unsigned long		map_offset;	/* offset from the H/W page boundary */
	unsigned long		map_length;	/* length of the mapped area */
	struct task_struct *wait_task;	/* task waiting for DMA completion */
	nvidia_p2p_page_table_t *page_table;

	/*
	 * NOTE: User supplied virtual address of device memory may not be
	 * aligned to the hardware page boundary of GPUs. So, we may need to
	 * map the least device memory that wraps the region (vaddress ...
	 * vaddress + length) entirely.
	 * The 'map_offset' is offset of the 'vaddress' from the head of H/W
	 * page boundary. So, if application wants to kick DMA to the location
	 * where handle=1234 and offset=2000 and map_offset=500, the driver
	 * will set up DMA towards the offset=2500 from the head of mapped
	 * physical pages.
	 */

	/*
	 * NOTE: Once a mapped_gpu_memory is registered, it can be released
	 * on random timing, by cuFreeMem(), process termination and etc...
	 * If refcnt > 0, it means someone's P2P DMA is in-progress, so
	 * cleanup routine (that shall be called by nvidia driver) has to
	 * wait for completion of these operations. However, mapped_gpu_memory
	 * shall be released immediately not to use this region any more.
	 */
};
typedef struct mapped_gpu_memory	mapped_gpu_memory;

#define MAPPED_GPU_MEMORY_NSLOTS	48
static struct mutex		strom_mgmem_mutex[MAPPED_GPU_MEMORY_NSLOTS];
static struct list_head	strom_mgmem_slots[MAPPED_GPU_MEMORY_NSLOTS];

/*
 * strom_mapped_gpu_memory_index - index of strom_mgmem_mutex/slots
 */
static inline int
strom_mapped_gpu_memory_index(unsigned long handle)
{
	u32		hash = arch_fast_hash(&handle, sizeof(unsigned long),
								  0x20140702);
	return hash % MAPPED_GPU_MEMORY_NSLOTS;
}

/*
 * strom_get_mapped_gpu_memory
 */
static mapped_gpu_memory *
strom_get_mapped_gpu_memory(unsigned long handle)
{
	int					index = strom_mapped_gpu_memory_index(handle);
	struct mutex	   *mutex = &strom_mgmem_mutex[index];
	struct list_head   *slot  = &strom_mgmem_slots[index];
	mapped_gpu_memory  *mgmem;

	mutex_lock(mutex);
	list_for_each_entry(mgmem, slot, chain)
	{
		if (mgmem->handle != handle)
			continue;

		/* sanity checks */
		BUG_ON((unsigned long)mgmem != handle);
		BUG_ON(!mgmem->page_table);

		mgmem->refcnt++;
		mutex_unlock(mutex);
		return mgmem;
	}
	mutex_unlock(mutex);

	return NULL;	/* not found */
}

/*
 * strom_put_mapped_gpu_memory
 */
static inline void
__strom_put_mapped_gpu_memory(mapped_gpu_memory *mgmem)
{
	BUG_ON(mgmem->refcnt < 1);
	mgmem->refcnt--;
	if (mgmem->refcnt == 0 && mgmem->wait_task != NULL)
	{
		wake_up_process(mgmem->wait_task);
		mgmem->wait_task = NULL;
	}
}

static void
strom_put_mapped_gpu_memory(mapped_gpu_memory *mgmem)
{
	int				index = strom_mapped_gpu_memory_index(mgmem->handle);
	struct mutex   *mutex = &strom_mgmem_mutex[index];

	mutex_lock(mutex);
	__strom_put_mapped_gpu_memory(mgmem);
	mutex_unlock(mutex);
}

/*
 * strom_clenup_mapped_gpu_memory - remove P2P page tables
 */
static int
__strom_clenup_mapped_gpu_memory(unsigned long handle)
{
	int					index = strom_mapped_gpu_memory_index(handle);
	struct mutex	   *mutex = &strom_mgmem_mutex[index];
	struct list_head   *slot = &strom_mgmem_slots[index];
	struct task_struct *wait_task_saved;
	mapped_gpu_memory  *mgmem;
	int					rc;

	mutex_lock(mutex);
	list_for_each_entry(mgmem, slot, chain)
	{
		if (mgmem->handle != handle)
			continue;

		/* sanity check */
		BUG_ON((unsigned long)mgmem != handle);
		BUG_ON(!mgmem->page_table);

		/*
		 * detach entry; no concurrent task can never touch this
		 * entry any more.
		 */
		list_del(&mgmem->chain);

		/*
		 * needs to wait for completion of concurrent DMA completion,
		 * if any task are running on.
		 */
		if (mgmem->refcnt > 0)
		{
			wait_task_saved = mgmem->wait_task;
			mgmem->wait_task = current;

			/* sleep until refcnt == 0 */
			set_current_state(TASK_UNINTERRUPTIBLE);
            mutex_unlock(mutex);
			schedule();

			if (wait_task_saved)
				wake_up_process(wait_task_saved);

			mutex_lock(mutex);
			BUG_ON(mgmem->refcnt == 0);
		}
		mutex_unlock(mutex);

		/*
		 * OK, no concurrent task does not use this mapped GPU memory
		 * at this point. So, we have no problem to release page_table.
		 */
		rc = __nvidia_p2p_free_page_table(mgmem->page_table);
		if (rc)
			printk(KERN_ERR NVME_STROM_PREFIX
				   "nvidia_p2p_free_page_table (handle=%lu, rc=%d)\n",
				   handle, rc);
		kfree(mgmem);

		printk(KERN_ERR NVME_STROM_PREFIX
			   "P2P GPU Memory (handle=%lu) was released\n", handle);
		return 0;
	}
	mutex_unlock(mutex);
	printk(KERN_ERR NVME_STROM_PREFIX
		   "P2P GPU Memory (handle=%lu) already released\n", handle);
	return -ENOENT;
}

static void
strom_cleanup_mapped_gpu_memory(void *private)
{
	(void)__strom_clenup_mapped_gpu_memory((unsigned long) private);
}

/*
 * strom_ioctl_map_gpu_memory
 *
 * ioctl(2) handler for STROM_IOCTL__MAP_GPU_MEMORY
 */
static int
strom_ioctl_map_gpu_memory(StromCmd__MapGpuMemory __user *uarg)
{
	StromCmd__MapGpuMemory karg;
	mapped_gpu_memory  *mgmem;
	unsigned long	map_address;
	unsigned long	map_offset;
	int				index;
	int				rc;

	if (copy_from_user(&karg, uarg, sizeof(karg)))
		return -EFAULT;

	mgmem = kmalloc(sizeof(mapped_gpu_memory), GFP_KERNEL);
	if (!mgmem)
		return -ENOMEM;

	map_address = karg.vaddress & GPU_BOUND_MASK;
	map_offset  = karg.vaddress & GPU_BOUND_OFFSET;

	INIT_LIST_HEAD(&mgmem->chain);
	mgmem->refcnt		= 0;
	mgmem->owner		= current->tgid;
	mgmem->handle		= (unsigned long) mgmem;
	mgmem->map_address  = map_address;
	mgmem->map_offset	= map_offset;
	mgmem->map_length	= map_offset + karg.length;
	mgmem->wait_task	= NULL;

	rc = __nvidia_p2p_get_pages(0,	/* p2p_token; deprecated */
								0,	/* va_space_token; deprecated */
								mgmem->map_address,
								mgmem->map_length,
								&mgmem->page_table,
								strom_cleanup_mapped_gpu_memory,
								mgmem);		/* as handle */
	if (rc)
	{
		printk(KERN_ERR NVME_STROM_PREFIX
			   "failed on nvidia_p2p_get_pages(addr=%p, length=%zu), rc=%d\n",
			   (void *)map_address, (size_t)map_offset + karg.length, rc);
		goto error_1;
	}

	/* return the handle of mapped_gpu_memory */
	rc = put_user(mgmem->handle, &uarg->handle);
	if (rc)
		goto error_2;

	/* debug output */
	{
		nvidia_p2p_page_table_t *page_table = mgmem->page_table;

		printk(KERN_INFO NVME_STROM_PREFIX
			   "P2P GPU Memory (handle=%lu) was mapped\n"
			   "  version=%u, page_size=%u, entries=%u\n",
			   mgmem->handle,
			   page_table->version,
			   page_table->page_size,
			   page_table->entries);
		for (index=0; index < page_table->entries; index++)
		{
			printk(KERN_INFO NVME_STROM_PREFIX
				   "  V:%p <--> P:%p\n",
				   (void *)(map_address + index * page_table->page_size),
				   (void *)(page_table->pages[index]->physical_address));
		}
	}

	/* attach this mapped_gpu_memory */
	index = strom_mapped_gpu_memory_index(mgmem->handle);
	mutex_lock(&strom_mgmem_mutex[index]);
	list_add(&strom_mgmem_slots[index], &mgmem->chain);
	mutex_unlock(&strom_mgmem_mutex[index]);

	return 0;

error_2:
	__nvidia_p2p_put_pages(0, 0, mgmem->map_address, mgmem->page_table);
error_1:
	kfree(mgmem);

	return rc;
}

/*
 * strom_ioctl_unmap_gpu_memory
 *
 * ioctl(2) handler for STROM_IOCTL__UNMAP_GPU_MEMORY
 */
static int
strom_ioctl_unmap_gpu_memory(StromCmd__UnmapGpuMemory __user *uarg)
{
	StromCmd__UnmapGpuMemory karg;
	int			rc;

	if (copy_from_user(&karg, uarg, sizeof(karg)))
		return -EFAULT;

	rc = __strom_clenup_mapped_gpu_memory(karg.handle);

	return rc;
}

/*
 * strom_ioctl_info_gpu_memory
 *
 * ioctl(2) handler for STROM_IOCTL__INFO_GPU_MEMORY
 */
static int
strom_ioctl_info_gpu_memory(StromCmd__InfoGpuMemory __user *uarg)
{
	StromCmd__InfoGpuMemory karg;
	mapped_gpu_memory *mgmem;
	nvidia_p2p_page_table_t *page_table;
	size_t		length;
	int			i, rc = 0;

	length = offsetof(StromCmd__InfoGpuMemory, physical_address);
	if (copy_from_user(&karg, uarg, length))
		return -EFAULT;

	mgmem = strom_get_mapped_gpu_memory(karg.handle);
	if (!mgmem)
		return -ENOENT;

	page_table = mgmem->page_table;
	karg.version = page_table->version;
	karg.page_size = page_table->page_size;
	karg.entries = page_table->entries;
	if (copy_to_user((void __user *)uarg, &karg, length))
		rc = -EFAULT;
	for (i=0; i < page_table->entries; i++)
	{
		if (i >= karg.nrooms)
			break;
		if (put_user(page_table->pages[i]->physical_address,
					 &uarg->physical_address[i]))
		{
			rc = -EFAULT;
			break;
		}
	}

	strom_put_mapped_gpu_memory(mgmem);

	return rc;
}

/*
 * strom_ioctl_check_file - checks whether the supplied file descriptor is
 * capable to perform P2P DMA from NVMe SSD.
 * Here are various requirement on filesystem / devices.
 *
 * - application has permission to read the file.
 * - filesystem has to be Ext4 or XFS, because Linux has no portable way
 *   to identify device blocks underlying a particular range of the file.
 * - block device of the file has to be NVMe-SSD, managed by the inbox
 *   driver of Linux. RAID configuration is not available to use.
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
 * strom_ioctl_check_file
 *
 * ioctl(2) handler for STROM_IOCTL__CHECK_FILE
 */
static int
strom_ioctl_check_file(StromCmd__CheckFile __user *uarg)
{
	StromCmd__CheckFile karg;
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

/* ================================================================
 *
 * Main part for SSD-to-GPU P2P DMA
 *
 *
 *
 *
 *
 *
 *
 *
 *
 * ================================================================
 */
struct dma_ssd2gpu
{
	struct list_head	chain;
	unsigned long		dma_id;	/* ID of this DMA task */
	mapped_gpu_memory  *mgmem;	/* destination GPU memory segment */



};



static int
strom_ioctl_dma_ssd2gpu(StromCmd__DmaSsd2Gpu __user *uarg)
{
	//async + wait;
	return 0;
}

static int
strom_ioctl_dma_ssd2gpu_async(StromCmd__DmaSsd2Gpu __user *uarg)
{
	return 0;
}

static int
strom_ioctl_dma_ssd2gpu_wait(StromCmd__DmaSsd2GpuWait __user *uarg)
{
	return 0;
}

#if 0
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
#endif

/* ================================================================
 *
 * For debug
 *
 * ================================================================
 */
#include <linux/genhd.h>

static int
strom_ioctl_debug(StromCmd__Debug __user *uarg)
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
	mapped_gpu_memory  *mgmem;
	struct mutex	   *mutex;
	struct list_head   *slot;
	int					index;

	if (*pos == 0)
		seq_puts(m, "NVMe-Strom mapped GPU device memory regions");

	/* pick up first mapping, if any */
	for (index=0; index < MAPPED_GPU_MEMORY_NSLOTS; index++)
	{
		mutex = &strom_mgmem_mutex[index];
		slot  = &strom_mgmem_slots[index];

		mutex_lock(mutex);
		list_for_each_entry(mgmem, slot, chain)
		{
			return mgmem;	/* keep mutex hold */
		}
		mutex_unlock(mutex);
	}
	return NULL;
}

static void *
strom_proc_seq_next(struct seq_file *m, void *p, loff_t *pos)
{
	mapped_gpu_memory  *mgmem = (mapped_gpu_memory *) p;
	int					index = strom_mapped_gpu_memory_index(mgmem->handle);
	struct mutex	   *mutex = &strom_mgmem_mutex[index];
	struct list_head   *slot = &strom_mgmem_slots[index];

	/* pick up next entry on the same slot (still under the mutex) */
	list_for_each_entry_continue(mgmem, slot, chain)
		return mgmem;
	mutex_unlock(mutex);

	while (++index < MAPPED_GPU_MEMORY_NSLOTS)
	{
		mutex = &strom_mgmem_mutex[index];
		slot = &strom_mgmem_slots[index];

		mutex_lock(mutex);
		list_for_each_entry(mgmem, slot, chain);
			return mgmem;
		mutex_unlock(mutex);
	}
	/* No mapped GPU memory any more */
	return NULL;
}

static void
strom_proc_seq_stop(struct seq_file *m, void *p)
{
	BUG_ON(p != NULL);
}

static int
strom_proc_seq_show(struct seq_file *m, void *p)
{
	mapped_gpu_memory *mgmem = (mapped_gpu_memory *) p;
	nvidia_p2p_page_table_t *page_table = mgmem->page_table;
	int			i;

	seq_printf(m,
			   "GPU Memory Map (handle: %lu, owner: %u, refcnt: %d)\n"
			   "  Page Table (version=%u, page_size=%u, entries=%u)\n",
			   mgmem->handle,
			   mgmem->owner,
			   mgmem->refcnt,
			   page_table->version,
               page_table->page_size,
               page_table->entries);
	for (i=0; i < page_table->entries; i++)
	{
		seq_printf(m, "    V:%p <--> P:%p\n",
				   (void *)(mgmem->map_address + page_table->page_size * i),
				   (void *)(page_table->pages[i]->physical_address));
	}
	seq_putc(m, '\n');

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
		case STROM_IOCTL__CHECK_FILE:
			rc = strom_ioctl_check_file((void __user *) arg);
			break;

		case STROM_IOCTL__MAP_GPU_MEMORY:
			rc = strom_ioctl_map_gpu_memory((void __user *) arg);
			break;

		case STROM_IOCTL__UNMAP_GPU_MEMORY:
			rc = strom_ioctl_unmap_gpu_memory((void __user *) arg);
			break;

		case STROM_IOCTL__INFO_GPU_MEMORY:
			rc = strom_ioctl_info_gpu_memory((void __user *) arg);
			break;

		case STROM_IOCTL__DMA_SSD2GPU:
			rc = strom_ioctl_dma_ssd2gpu((void __user *) arg);
			break;

		case STROM_IOCTL__DMA_SSD2GPU_ASYNC:
			rc = strom_ioctl_dma_ssd2gpu_async((void __user *) arg);
			break;

		case STROM_IOCTL__DMA_SSD2GPU_WAIT:
			rc = strom_ioctl_dma_ssd2gpu_wait((void __user *) arg);
			break;

		case STROM_IOCTL__DEBUG:
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

	/* init strom_mgmem_mutex/slots */
	for (i=0; i < MAPPED_GPU_MEMORY_NSLOTS; i++)
	{
		mutex_init(&strom_mgmem_mutex[i]);
		INIT_LIST_HEAD(&strom_mgmem_slots[i]);
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
