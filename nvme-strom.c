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
#include <linux/buffer_head.h>
#include <linux/dmaengine.h>
#include <linux/crc32c.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/magic.h>
#include <linux/major.h>
#include <linux/moduleparam.h>
#include <linux/nvme.h>
#include <linux/notifier.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/version.h>
#include "nv-p2p.h"
#include "nvme-strom.h"

/* check the target kernel to build */
#if defined(RHEL_MAJOR) && (RHEL_MAJOR == 7)
#define STROM_TARGET_KERNEL_RHEL7		1
#else
#error Linux kernel not supported
#endif

/* utility macros */
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

static int	verbose = 1;
module_param(verbose, int, 1);

#define prDebug(fmt, ...)												\
	do {																\
		printk(KERN_ALERT "nvme-strom(%s:%d): " fmt "\n",				\
			   __FUNCTION__, __LINE__, ##__VA_ARGS__);					\
	} while(0)

#define prInfo(fmt, ...)												\
	do {																\
		if (verbose)													\
			printk(KERN_INFO "nvme-strom: " fmt "\n", ##__VA_ARGS__);	\
	} while(0)

#define prNotice(fmt, ...)												\
	do {																\
		if (verbose)													\
			printk(KERN_NOTICE "nvme-strom: " fmt "\n", ##__VA_ARGS__);	\
	} while(0)

#define prWarn(fmt, ...)						\
	do {																\
		printk(KERN_WARNING "nvme-strom: " fmt "\n", ##__VA_ARGS__);	\
	} while(0)

#define prError(fmt, ...)												\
	do {																\
		printk(KERN_ERR "nvme-strom: " fmt "\n", ##__VA_ARGS__);		\
	} while(0)

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
	size_t				gpu_page_sz;/* page size in bytes; note that
									 * 'page_size' of nvidia_p2p_page_table_t
									 * is one of NVIDIA_P2P_PAGE_SIZE_* */
	size_t				gpu_page_shift;	/* log2 of gpu_page_sz */
	nvidia_p2p_page_table_t *page_table;
	void			  **iomap_vaddrs;

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

	prError("P2P GPU Memory (handle=0x%lx) not found", handle);

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
	unsigned int		entries;
	int					i, rc;

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
		entries = mgmem->page_table->entries;
		for (i=0; i < entries; i++)
			iounmap(mgmem->iomap_vaddrs[i]);
		kfree(mgmem->iomap_vaddrs);

		rc = __nvidia_p2p_free_page_table(mgmem->page_table);
		if (rc)
			prError("nvidia_p2p_free_page_table (handle=0x%lx, rc=%d)",
					handle, rc);
		kfree(mgmem);

		prInfo("P2P GPU Memory (handle=%p) was released", (void *)handle);
		return 0;
	}
	mutex_unlock(mutex);
	prError("P2P GPU Memory (handle=%p) already released", (void *)handle);
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
	nvidia_p2p_page_t **p2p_pages;
	unsigned long	map_address;
	unsigned long	map_offset;
	uint32_t		entries;
	int				i, rc;

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
		prError("failed on nvidia_p2p_get_pages(addr=%p, len=%zu), rc=%d",
				(void *)map_address, (size_t)map_offset + karg.length, rc);
		goto error_1;
	}

	/* page size in bytes */
	switch (mgmem->page_table->page_size)
	{
		case NVIDIA_P2P_PAGE_SIZE_4KB:
			mgmem->gpu_page_sz = 4 * 1024;
			mgmem->gpu_page_shift = 12;
			break;
		case NVIDIA_P2P_PAGE_SIZE_64KB:
			mgmem->gpu_page_sz = 64 * 1024;
			mgmem->gpu_page_shift = 16;
			break;
		case NVIDIA_P2P_PAGE_SIZE_128KB:
			mgmem->gpu_page_sz = 128 * 1024;
			mgmem->gpu_page_shift = 17;
			break;
		default:
			rc = -EINVAL;
			goto error_2;
	}

	/* address for ioremap virtual addresses */
	entries = mgmem->page_table->entries;
	mgmem->iomap_vaddrs = kzalloc(sizeof(void *) * entries, GFP_KERNEL);
	if (!mgmem->iomap_vaddrs)
	{
		rc = -ENOMEM;
		goto error_2;
	}

	p2p_pages = mgmem->page_table->pages;
	for (i=0; i < entries; i++)
	{
		void	   *vaddr = ioremap(p2p_pages[i]->physical_address,
									mgmem->gpu_page_sz);
		if (!vaddr)
		{
			while (--i >= 0)
				iounmap(mgmem->iomap_vaddrs[i]);
			rc = -ENOMEM;
			goto error_3;
		}
		mgmem->iomap_vaddrs[i] = vaddr;
	}

	/* return the handle of mapped_gpu_memory */
	if (put_user(mgmem->handle, &uarg->handle) ||
		put_user(mgmem->gpu_page_sz, &uarg->gpu_page_sz) ||
		put_user(entries, &uarg->gpu_npages))
	{
		rc = -EFAULT;
		goto error_4;
	}

	/* debug output */
	{
		nvidia_p2p_page_table_t *page_table = mgmem->page_table;

		prNotice("P2P GPU Memory (handle=%p) mapped\n"
				 "  version=%u, page_size=%zu, entries=%u\n",
				 (void *)mgmem->handle,
				 page_table->version,
				 mgmem->gpu_page_sz,
				 page_table->entries);
		for (i=0; i < page_table->entries; i++)
		{
			prNotice("  V:%p <--> P:%p\n",
					 (void *)(mgmem->iomap_vaddrs[i]),
					 (void *)(page_table->pages[i]->physical_address));
		}
	}

	/*
	 * Warning message if mapped device memory is not aligned well
	 */
	if ((mgmem->map_offset & (PAGE_SIZE - 1)) != 0 ||
		(mgmem->map_length & (PAGE_SIZE - 1)) != 0)
	{
		prWarn("Gpu memory mapping (handle=%lx) is not aligned well "
			   "(map_offset=%lx map_length=%lx)."
			   "It may be inconvenient to submit DMA requests",
			   mgmem->handle,
			   mgmem->map_offset,
			   mgmem->map_length);
	}

	/* attach this mapped_gpu_memory */
	i = strom_mapped_gpu_memory_index(mgmem->handle);
	mutex_lock(&strom_mgmem_mutex[i]);
	list_add(&mgmem->chain, &strom_mgmem_slots[i]);
	mutex_unlock(&strom_mgmem_mutex[i]);

	return 0;

error_4:
	entries = mgmem->page_table->entries;
	for (i=0; i < entries; i++)
	{
		if (mgmem->iomap_vaddrs[i])
			iounmap(mgmem->iomap_vaddrs[i]);
	}
error_3:
	kfree(mgmem->iomap_vaddrs);
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

	length = offsetof(StromCmd__InfoGpuMemory, pages);
	if (copy_from_user(&karg, uarg, length))
		return -EFAULT;

	mgmem = strom_get_mapped_gpu_memory(karg.handle);
	if (!mgmem)
		return -ENOENT;

	page_table = mgmem->page_table;
	karg.version = page_table->version;
	karg.gpu_page_sz = mgmem->gpu_page_sz;
	karg.nitems = page_table->entries;
	if (copy_to_user((void __user *)uarg, &karg, length))
		rc = -EFAULT;
	for (i=0; i < page_table->entries; i++)
	{
		if (i >= karg.nrooms)
			break;
		if (put_user((void *)mgmem->iomap_vaddrs[i],
					 &uarg->pages[i].vaddr) ||
			put_user(page_table->pages[i]->physical_address,
					 &uarg->pages[i].paddr))
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
 * - file has to be larger than or equal to PAGE_SIZE, because Ext4/XFS
 *   are capable to have file contents inline, for very small files.
 */
#define XFS_SB_MAGIC			0x58465342

static int
source_file_is_supported(struct file *filp, struct nvme_ns **p_nvme_ns)
{
	struct inode		   *f_inode = filp->f_inode;
	struct super_block	   *i_sb = f_inode->i_sb;
	struct file_system_type *s_type = i_sb->s_type;
	struct block_device	   *s_bdev = i_sb->s_bdev;
	struct gendisk		   *bd_disk = s_bdev->bd_disk;
	const char			   *dname;
	int						rc;

	/*
	 * must have READ permission of the source file
	 */
	if ((filp->f_mode & FMODE_READ) == 0)
	{
		prError("process (pid=%u) has no permission to read file",
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
	if (!((i_sb->s_magic == EXT4_SUPER_MAGIC &&
		   strcmp(s_type->name, "ext4") == 0 &&
		   s_type->owner == mod_ext4_get_block) ||
		  (i_sb->s_magic == XFS_SB_MAGIC &&
		   strcmp(s_type->name, "xfs") == 0 &&
		   s_type->owner == mod_xfs_get_blocks)))
	{
		prError("file_system_type name=%s, not supported", s_type->name);
		return -ENOTSUPP;
	}

	/*
	 * check whether the file size is, at least, more than PAGE_SIZE
	 *
	 * MEMO: It is a rough alternative to prevent inline files on Ext4/XFS.
	 * Contents of these files are stored with inode, instead of separate
	 * data blocks. It usually makes no sense on SSD-to-GPU Direct fature.
	 */
	spin_lock(&f_inode->i_lock);
	if (f_inode->i_size < PAGE_SIZE)
	{
		unsigned long		i_size = f_inode->i_size;
		spin_unlock(&f_inode->i_lock);
		prError("file size too small (%lu bytes), not suitable", i_size);
		return -ENOTSUPP;
	}
	spin_unlock(&f_inode->i_lock);

	/*
	 * check whether the block size is equivalent to PAGE_SIZE, or not.
	 *
	 * MEMO: This limitation may be removed in the future version.
	 * For simple implementation, we require to have block_size == PAGE_SIZE.
	 */
	if (i_sb->s_blocksize != PAGE_SIZE)
	{
		prError("block size does not match with PAGE_SIZE (%lu)",
				i_sb->s_blocksize);
		return -ENOTSUPP;
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
		prError("block device major number = %d, not 'blkext'",
				bd_disk->major);
		return -ENOTSUPP;
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
		prError("block device '%s' is not supported", dname);
		return -ENOTSUPP;
	}

	/* try to call ioctl */
	if (!bd_disk->fops->ioctl)
	{
		prError("block device '%s' does not provide ioctl",
				bd_disk->disk_name);
		return -ENOTSUPP;
	}

	rc = bd_disk->fops->ioctl(s_bdev, 0, NVME_IOCTL_ID, 0UL);
	if (rc < 0)
	{
		prError("ioctl(NVME_IOCTL_ID) on '%s' returned an error: %d",
				bd_disk->disk_name, rc);
		return -ENOTSUPP;
	}

	if (p_nvme_ns)
		*p_nvme_ns = (struct nvme_ns *)bd_disk->private_data;

	/* OK, we assume the underlying device is supported NVMe-SSD */
	return 0;
}

/*
 * strom_get_block - a generic version of get_block_t for the supported
 * filesystems. It assumes the target filesystem is already checked by
 * source_file_is_supported, so we have minimum checks here.
 */
static inline int
strom_get_block(struct inode *inode, sector_t iblock,
				struct buffer_head *bh, int create)
{
	struct super_block	   *i_sb = inode->i_sb;

	if (i_sb->s_magic == EXT4_SUPER_MAGIC)
		return __ext4_get_block(inode, iblock, bh, create);
	else if (i_sb->s_magic == XFS_SB_MAGIC)
		return __xfs_get_blocks(inode, iblock, bh, create);
	else
		return -ENOTSUPP;
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
	struct nvme_ns *nvme_ns;
	int				rc;

	if (copy_from_user(&karg, uarg, sizeof(karg)))
		return -EFAULT;

	filp = fget(karg.fdesc);
	if (!filp)
		return -EBADF;

	rc = source_file_is_supported(filp, &nvme_ns);
	if (rc == 0)
	{
		if (put_user((size_t)(1UL << nvme_ns->lba_shift), &uarg->falign))
			rc = -EFAULT;
	}
	fput(filp);

	return (rc < 0 ? rc : 0);
}

/* ================================================================
 *
 * Main part for SSD-to-GPU P2P DMA
 *
 *
 *
 *
 *
 * ================================================================
 */
#define STROM_DMA_TASK_MAX_PAGES		32

struct strom_dma_task
{
	struct list_head	chain;
	unsigned long		dma_task_id;/* ID of this DMA task */
	int					hindex;		/* index of hash slot */
	int					refcnt;		/* reference counter */
	mapped_gpu_memory  *mgmem;		/* destination GPU memory segment */
	struct nvme_ns	   *nvme_ns;	/* NVMe namespace (=SCSI LUN) */
	struct file		   *filp;		/* source file, if any */
	size_t				falign;		/* alignment of source/destination */
	/* contiguous SSD blocks */
	sector_t			src_block;	/* head of the source blocks */
	unsigned int		nr_blocks;	/* # of the contigunous source blocks */
	/* contiguous file cache pages */
	struct page		   *src_pages[STROM_DMA_TASK_MAX_PAGES];
									/* array of file-cache pages */
	unsigned int		nr_pages;	/* # of the contigunous source pages */

	size_t				src_offset;	/* offset from the chunk */
	size_t				dma_length;	/* length of the pending DMA request */
	size_t				dest_offset;/* current destination offset from the
									 * mgmem segment head */
	/* result of the asynchronous task */
	struct task_struct *wait_task;	/* task which waits for completion */
	int					dma_status;
	u32					dma_result;

	/* definition of the chunks */
	unsigned int		nchunks;
	strom_dma_chunk		chunks[1];
};
typedef struct strom_dma_task	strom_dma_task;

#define STROM_DMA_TASK_NSLOTS	100
static spinlock_t		strom_dma_task_locks[STROM_DMA_TASK_NSLOTS];
static struct list_head	strom_dma_task_slots[STROM_DMA_TASK_NSLOTS];

/*
 * strom_dma_task_index
 */
static inline int
strom_dma_task_index(unsigned long dma_task_id)
{
	u32		hash = arch_fast_hash(&dma_task_id, sizeof(unsigned long),
								  0x20120106);
	return hash % STROM_DMA_TASK_NSLOTS;
}

/*
 * strom_get_dma_task
 */
static strom_dma_task *
strom_get_dma_task(strom_dma_task *dtask)
{
	int				index = strom_dma_task_index(dtask->dma_task_id);
	spinlock_t	   *lock = &strom_dma_task_locks[index];
	unsigned long	flags;

	spin_lock_irqsave(lock, flags);
	Assert(dtask->refcnt > 0);
	dtask->refcnt++;
	spin_unlock_irqrestore(lock, flags);

	return dtask;
}

/*
 * strom_put_dma_task
 */
static void
strom_put_dma_task(strom_dma_task *dtask)
{
	int				index = strom_dma_task_index(dtask->dma_task_id);
	spinlock_t	   *lock = &strom_dma_task_locks[index];
	unsigned long	flags;

	spin_lock_irqsave(lock, flags);
	Assert(dtask->refcnt > 0);
	if (--dtask->refcnt == 0)
	{
		list_del(&dtask->chain);
		spin_unlock_irqrestore(lock, flags);

		/* release the relevant resources */
		strom_put_mapped_gpu_memory(dtask->mgmem);
		if (dtask->filp)
			fput(dtask->filp);
		if (dtask->wait_task)
			wake_up_process(dtask->wait_task);
		kfree(dtask);

		prInfo("DMA task (id=%p) was completed", dtask);
		return;
	}
	spin_unlock_irqrestore(lock, flags);
}

/*
 * lookup_dma_dest_addr - lookup a DMA address by a pair of mapped GPU memory
 * and its offset. Here is no guarantee all the destination GPU pages are
 * located continuously.
 */
static inline dma_addr_t
lookup_dma_dest_addr(mapped_gpu_memory *mgmem, size_t dma_dest_offset)
{
	size_t			gpu_page_sz = mgmem->gpu_page_sz;
	unsigned int	i = (mgmem->map_offset + dma_dest_offset) / gpu_page_sz;

	Assert(mgmem->map_offset + dma_dest_offset <= mgmem->map_length);
	Assert(i < mgmem->page_table->entries);
	return (mgmem->page_table->pages[i]->physical_address +
			dma_dest_offset % gpu_page_sz);
}

/*
 * DMA transaction for RAM->GPU asynchronous copy
 */
static int
submit_ram2gpu_memcpy(strom_dma_task *dtask)
{
	mapped_gpu_memory *mgmem = dtask->mgmem;
	char	   *src_buffer;
	char	   *dest_buffer;
	size_t		src_offset  = dtask->src_offset;
	size_t		dest_offset = dtask->dest_offset;
	size_t		dma_length = dtask->dma_length;
	size_t		dest_length;
	int			i, j;

	Assert(src_offset < PAGE_CACHE_SIZE);
	Assert((src_offset + dma_length) <= PAGE_SIZE * dtask->nr_pages);

	while (dma_length > 0)
	{
		dest_length = ((dest_offset + mgmem->gpu_page_sz)
					   & ~(mgmem->gpu_page_sz - 1)) - dest_offset;
		dest_length = Min(dest_length, dma_length);
		Assert(dest_length > 0);

		i = dest_offset >> mgmem->gpu_page_shift;
		Assert(i == (dest_offset + dest_length - 1) >> mgmem->gpu_page_shift);
		dest_buffer = ((char *)mgmem->iomap_vaddrs[i] +
					   (dest_offset & (mgmem->gpu_page_sz - 1)));
		while (dest_length  > 0)
		{
			size_t	page_ofs = src_offset & (PAGE_CACHE_SIZE - 1);
			size_t	page_len;

			if (page_ofs + dest_length >= PAGE_CACHE_SIZE)
				page_len = PAGE_CACHE_SIZE - page_ofs;
			else
				page_len = dest_length - page_ofs;

			j = src_offset >> PAGE_CACHE_SHIFT;
			src_buffer = kmap_atomic(dtask->src_pages[j]);
			memcpy(dest_buffer, src_buffer + page_ofs, page_len);
			kunmap_atomic(src_buffer);

			src_offset += page_len;
			dest_buffer += page_len;
			dest_length -= page_len;
		}
	}

	/* release source file-cached pages and revert the source state */
	for (i=0; i < dtask->nr_pages; i++)
		put_page(dtask->src_pages[i]);
	dtask->nr_pages = 0;
	dtask->src_offset = 0;
	/* make the destination offset advanced */
	dtask->dest_offset += dtask->dma_length;
	dtask->dma_length = 0;

	return 0;
}

/*
 * DMA transaction for SSD->GPU asynchronous copy
 */
#ifdef STROM_TARGET_KERNEL_RHEL7
#include "nvme-strom.rhel7.c"
#else
#error "no platform specific NVMe-SSD routines"
#endif

static int
submit_ssd2gpu_memcpy(strom_dma_task *dtask)
{
	struct nvme_ns	   *nvme_ns = dtask->nvme_ns;
	mapped_gpu_memory  *mgmem = dtask->mgmem;
	size_t		src_offset  = dtask->src_offset;
	size_t		dest_offset = dtask->dest_offset;
	size_t		dma_length = dtask->dma_length;
	size_t		dest_length;
	u64			slba;	/* starting logical block address */
	u16			nlb;	/* number of logical blocks to read */
	u64			dma_addr;
	int			i, retval = 0;

	Assert(((src_offset + dma_length + PAGE_CACHE_SIZE - 1)
			& PAGE_CACHE_MASK) == PAGE_CACHE_SIZE * dtask->nr_blocks);
	Assert(((dtask->src_block * PAGE_CACHE_SIZE +
			 dtask->src_offset) & (dtask->falign - 1)) == 0);

	while (dma_length > 0)
	{
		dest_length = ((dest_offset + mgmem->gpu_page_sz)
					   & ~(mgmem->gpu_page_sz - 1)) - dest_offset;
		dest_length = Min(dest_length, dma_length);
		Assert(dest_length > 0);
		Assert((dest_length & (dtask->falign - 1)) == 0);

		slba = (dtask->src_block * PAGE_CACHE_SIZE +
				src_offset) >> nvme_ns->lba_shift;
		nlb = (dest_length) >> nvme_ns->lba_shift;

		i = dest_offset >> mgmem->gpu_page_shift;
		Assert(i < mgmem->page_table->entries);
		dma_addr = (mgmem->page_table->pages[i]->physical_address +
					(dest_offset & (mgmem->gpu_page_sz - 1)));

		retval = nvme_submit_async_read_cmd(dtask, dma_addr, slba, nlb);
		if (retval)
			break;

		/* make the */
		dest_offset += dest_length;
		src_offset += dest_length;
		dma_length -= dest_length;
	}

	dtask->src_block = ~0UL;
	dtask->nr_blocks = 0;
	dtask->dest_offset += dtask->dma_length;
	dtask->dma_length = 0;

	return retval;
}

/*
 * strom_memcpy_ssd2gpu_wait - synchronization of a dma_task
 */
static int
strom_memcpy_ssd2gpu_wait(unsigned long dma_task_id)
{
	spinlock_t		   *lock;
	struct list_head   *slot;
	struct task_struct *wait_task_saved;
	strom_dma_task	   *dtask;
	int					index;
	unsigned long		flags;

	index = strom_dma_task_index(dma_task_id);
	lock = &strom_dma_task_locks[index];
	slot = &strom_dma_task_slots[index];

	prInfo("begin strom_memcpy_ssd2gpu_wait");

	spin_lock_irqsave(lock, flags);
	list_for_each_entry(dtask, slot, chain)
	{
		if (dtask->dma_task_id != dma_task_id)
			continue;

		wait_task_saved = dtask->wait_task;
		dtask->wait_task = current;

		/* sleep until DMA completion */
		set_current_state(TASK_UNINTERRUPTIBLE);
		spin_unlock_irqrestore(lock, flags);
		schedule();

		if (wait_task_saved)
			wake_up_process(wait_task_saved);
#if 1
		/* for debug, ensure dma_task has already gone */
		spin_lock_irqsave(lock, flags);
		list_for_each_entry(dtask, slot, chain)
		{
			BUG_ON(dtask->dma_task_id == dma_task_id);
		}
		spin_unlock_irqrestore(lock, flags);
#endif
		return 0;
	}
	spin_unlock_irqrestore(lock, flags);

	/*
	 * DMA task was not found. Likely, asynchronous DMA task gets already
	 * completed.
	 */
	return -ENOENT;
}


/*
 * strom_memcpy_ssd2gpu_async
 */
static int
strom_memcpy_ssd2gpu_async(StromCmd__MemCpySsdToGpu __user *uarg,
						   unsigned long *p_dma_task_id)
{
	StromCmd__MemCpySsdToGpu karg;
	mapped_gpu_memory  *mgmem;
	strom_dma_task	   *dtask;
	struct file		   *filp;
	struct page		   *fpage;
	struct nvme_ns	   *nvme_ns;
	loff_t				i_size;
	unsigned long		dma_task_id;
	unsigned long		flags;
	int					i, rc = 0;

	prInfo("begin strom_memcpy_ssd2gpu_async");
	if (copy_from_user(&karg, uarg,
					   offsetof(StromCmd__MemCpySsdToGpu, chunks)))
		return -EFAULT;

	/* ensure the file is supported */
	filp = fget(karg.fdesc);
	if (!filp)
	{
		prError("file descriptor %d of process %u is not available",
				karg.fdesc, current->tgid);
		return -EBADF;
	}
	rc = source_file_is_supported(filp, &nvme_ns);
	if (rc < 0)
		goto error_1;

	/* get destination GPU memory */
	mgmem = strom_get_mapped_gpu_memory(karg.handle);
	if (!mgmem)
	{
		rc = -ENOENT;
		goto error_1;
	}

	/* make strom_dma_task object */
	dtask = kmalloc(offsetof(strom_dma_task,
							 chunks[karg.nchunks]), GFP_KERNEL);
	if (!dtask)
	{
		rc = -ENOMEM;
		goto error_2;
	}
	*p_dma_task_id = dma_task_id = (unsigned long) dtask;
	dtask->dma_task_id = dma_task_id;
	dtask->hindex = strom_dma_task_index(dma_task_id);
	dtask->refcnt = 1;
	dtask->mgmem = mgmem;
	dtask->nvme_ns = nvme_ns;
	dtask->filp = filp;
	dtask->falign = (1UL << nvme_ns->lba_shift);
	dtask->src_block = ~0UL;
	dtask->nr_blocks = 0;
	dtask->nr_pages = 0;
	dtask->dma_length = 0;
	dtask->src_offset = 0;
	dtask->dest_offset = mgmem->map_offset + karg.offset;
	dtask->wait_task = NULL;
	dtask->dma_status = 0;
	dtask->dma_result = 0;
	dtask->nchunks = karg.nchunks;
	if (copy_from_user(dtask->chunks, uarg->chunks,
					   sizeof(strom_dma_chunk) * karg.nchunks))
	{
		rc = -EFAULT;
		goto error_3;
	}

	spin_lock_irqsave(&strom_dma_task_locks[dtask->hindex], flags);
	list_add(&dtask->chain, &strom_dma_task_slots[dtask->hindex]);
	spin_unlock_irqrestore(&strom_dma_task_locks[dtask->hindex], flags);

	prInfo("run a new DMA task ID=%lx", dma_task_id);

	/*
	 * Kick asynchronous DMA operation
	 */
	i_size = i_size_read(filp->f_inode);
	for (i=0; i < karg.nchunks; i++)
	{
		strom_dma_chunk *dchunk = &dtask->chunks[i];
		loff_t		pos;
		loff_t		end;

		if (dchunk->length == 0)
			continue;

		pos = dchunk->fpos;
		if (pos >= i_size)
		{
			rc = -ERANGE;
			goto bailout;
		}
		end = Min(pos + dchunk->length, i_size);

		/* check alignment */
		if ((dtask->dest_offset & (dtask->falign - 1)) != 0 ||
			(pos & (dtask->falign - 1)) != 0 ||
			(end & (dtask->falign - 1)) != 0)
		{
			prError("alignment violation src=%zu dest=%zu len=%zu i_size=%zu",
					(size_t)pos, (size_t)dtask->dest_offset, (size_t)end,
					(size_t)i_size);
			rc = -EINVAL;
			goto bailout;
		}

		while (pos < end)
		{
			size_t		offset = (pos & (PAGE_SIZE - 1));
			size_t		unitsz;

			if (end - pos <= PAGE_SIZE)
				unitsz = end - pos;
			else
				unitsz = PAGE_SIZE - offset;

			fpage = find_get_page(filp->f_mapping, pos >> PAGE_SHIFT);
			if (fpage)
			{
				/* Submit SSD2GPU DMA, if any pending request */
				if (dtask->nr_blocks > 0)
				{
					rc = submit_ssd2gpu_memcpy(dtask);
					if (rc)
					{
						prDebug("submit_ssd2gpu_memcpy() = %d", rc);
						goto bailout;
					}
					Assert(dtask->nr_pages == 0 && dtask->nr_blocks == 0);
				}

				if (offset == 0 &&
					((dtask->src_offset +
					  dtask->dma_length) & (PAGE_CACHE_SIZE - 1)) == 0 &&
					dtask->nr_pages > 0 &&
					dtask->nr_pages < STROM_DMA_TASK_MAX_PAGES)
				{
					dtask->src_pages[dtask->nr_pages] = fpage;
					dtask->nr_pages++;
					dtask->dma_length += unitsz;
				}
				else
				{
					/*
					 * Submit RAM2GPU DMA of non-contiguous pages, or if dtask
					 * cannot keep file cache pages any more
					 */
					if (dtask->nr_pages > 0)
					{
						rc = submit_ram2gpu_memcpy(dtask);
						if (rc)
						{
							prDebug("submit_ram2gpu_memcpy() = %d", rc);
							goto bailout;
						}
						Assert(dtask->nr_pages == 0 && dtask->nr_blocks == 0);
					}
					/* This fpage becomes the new head of source pages */
					dtask->src_pages[0] = fpage;
					dtask->nr_pages = 1;
					dtask->src_offset = offset;
					dtask->dma_length = unitsz;
				}
			}
			else
			{
				struct buffer_head		bh;

				/* Submit RAM2GPU DMA, if any pending request */
				if (dtask->nr_pages > 0)
				{
					rc = submit_ram2gpu_memcpy(dtask);
					if (rc)
					{
						prDebug("submit_ram2gpu_memcpy() = %d", rc);
						goto bailout;
					}
					Assert(dtask->nr_pages == 0 && dtask->nr_blocks);
				}

				/* Lookup underlying block number */
				memset(&bh, 0, sizeof(bh));
				bh.b_size = PAGE_SIZE;	// needs to pull from device?

				rc = strom_get_block(filp->f_inode,
									 pos >> PAGE_CACHE_SHIFT,
									 &bh, 0);
				if (rc)
				{
					prDebug("strom_get_block rc=%d", rc);
					goto bailout;
				}

				/* Merge with the pending blocks, if any */
				if (offset == 0 &&
					((dtask->src_offset +
					  dtask->dma_length) & (PAGE_CACHE_SIZE - 1)) == 0 &&
					dtask->nr_blocks > 0 &&
					dtask->src_block + dtask->nr_blocks == bh.b_blocknr)
				{
					dtask->nr_blocks++;
					dtask->dma_length += unitsz;
				}
				else
				{
					/* Submit the last pending blocks, if any */
					if (dtask->nr_blocks > 0)
					{
						rc = submit_ssd2gpu_memcpy(dtask);
						if (rc)
						{
							prDebug("submit_ssd2gpu_memcpy() = %d", rc);
							goto bailout;
						}
						Assert(dtask->nr_blocks == 0 && dtask->nr_pages == 0);
					}
					dtask->src_block = bh.b_blocknr;
					dtask->nr_blocks = 1;
					dtask->src_offset = offset;
					dtask->dma_length = unitsz;
				}
			}
			pos += unitsz;
		}
	}
	/* Submit the pending RAM2GPU or SSD2GPU requests */
	if (dtask->nr_pages > 0)
	{
		Assert(dtask->nr_blocks == 0);	/* no SSD2GPU DMA should exist */
		rc = submit_ram2gpu_memcpy(dtask);
		if (rc)
			prDebug("submit_ram2gpu_memcpy() = %d", rc);
	}
	else if (dtask->nr_blocks > 0)
	{
		Assert(dtask->nr_pages == 0);	/* no RAM2GPU DMA should exist */
		rc = submit_ssd2gpu_memcpy(dtask);
		if (rc)
			prDebug("submit_ssd2gpu_memcpy() = %d", rc);
	}

bailout:
	if (rc)
	{
		/* release file cache pages if pending RAM2GPU request */
		for (i=0; i < dtask->nr_pages; i++)
			put_page(dtask->src_pages[i]);

		prDebug("wait for DMA Task %lx due to an error (%d)",
				dma_task_id, rc);
		(void)strom_memcpy_ssd2gpu_wait(dma_task_id);
	}
	return rc;


error_3:
	kfree(dtask);
error_2:
	strom_put_mapped_gpu_memory(mgmem);
error_1:
	fput(filp);
	return rc;
}

/*
 * ioctl(2) handler for STROM_IOCTL__MEMCPY_SSD2GPU
 */
static int
strom_ioctl_memcpy_ssd2gpu(StromCmd__MemCpySsdToGpu __user *uarg)
{
	unsigned long	dma_task_id;
	int				rc;

	rc = strom_memcpy_ssd2gpu_async(uarg, &dma_task_id);
	if (rc == 0)
	{
		if (put_user(dma_task_id, &uarg->dma_task_id))
			rc = -EFAULT;
	}
	(void) strom_memcpy_ssd2gpu_wait(dma_task_id);

	return rc;
}

/*
 * ioctl(2) handler for STROM_IOCTL__MEMCPY_SSD2GPU_ASYNC
 */
static int
strom_ioctl_memcpy_ssd2gpu_async(StromCmd__MemCpySsdToGpu __user *uarg)
{
	unsigned long	dma_task_id;
	int				rc;

	rc = strom_memcpy_ssd2gpu_async(uarg, &dma_task_id);
	if (rc == 0)
	{
		if (put_user(dma_task_id, &uarg->dma_task_id))
		{
			rc = -EFAULT;
			(void) strom_memcpy_ssd2gpu_wait(dma_task_id);
		}
	}
	else
	{
		(void) strom_memcpy_ssd2gpu_wait(dma_task_id);
	}
	return rc;
}

/*
 * ioctl(2) handler for STROM_IOCTL__MEMCPY_SSD2GPU_WAIT
 */
static int
strom_ioctl_memcpy_ssd2gpu_wait(StromCmd__MemCpySsdToGpuWait __user *uarg)
{
	StromCmd__MemCpySsdToGpuWait karg;

	if (copy_from_user(&karg, uarg, sizeof(karg)))
		return -EFAULT;

	return strom_memcpy_ssd2gpu_wait(karg.dma_task_id);
}

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
	StromCmd__Debug	karg;
	struct file	   *filp;
	struct inode   *inode;
	struct page	   *page;
	int				rc;
	int				fs_type;
	unsigned long	pos;
	unsigned long	ofs;
	unsigned long	end;

	if (copy_from_user(&karg, uarg, sizeof(StromCmd__Debug)))
		return -EFAULT;

	filp = fget(karg.fdesc);
	printk(KERN_INFO "filp = %p\n", filp);
	if (!filp)
		return 0;
	inode = filp->f_inode;

	fs_type = source_file_is_supported(filp, NULL);
	if (fs_type < 0)
	{
		fput(filp);
		return fs_type;
	}
	pos = karg.offset >> PAGE_CACHE_SHIFT;
	ofs = karg.offset &  PAGE_MASK;
	end = (karg.offset + karg.length) >> PAGE_CACHE_SHIFT;

	while (pos < end)
	{
		page = find_get_page(filp->f_mapping, pos);
		if (page)
		{
			printk(KERN_INFO "file index=%lu page %p\n", pos, page);
			put_page(page);
		}
		else
		{
			struct buffer_head	bh;

			memset(&bh, 0, sizeof(bh));
			bh.b_size = PAGE_SIZE;

			rc = strom_get_block(filp->f_inode, pos, &bh, 0);
			if (rc < 0)
				printk(KERN_INFO "failed on strom_get_block: %d\n", rc);
			else
			{
				printk(KERN_INFO "file index=%lu blocknr=%lu\n",
					   pos, bh.b_blocknr);
			}
		}
		pos++;
	}
	fput(filp);

	return 0;
}

/* ================================================================
 *
 * file_operations of '/proc/nvme-strom' entry
 *
 * ================================================================
 */
typedef struct
{
	/* contents of read(2) */
	size_t		length;
	size_t		usage;
	char		data[1];
} strom_proc_entry;

static strom_proc_entry *
strom_proc_printf(strom_proc_entry *spent, const char *fmt, ...)
{
	va_list	args;
	int		count;
	char	linebuf[200];

	if (!spent)
		return NULL;

	va_start(args, fmt);
	count = vsnprintf(linebuf, sizeof(linebuf), fmt, args);
	va_end(args);

	while (spent->usage + count > spent->length)
	{
		strom_proc_entry *spent_new;
		size_t		length_new = 2 * spent->length;		

		spent_new = __krealloc(spent, length_new, GFP_KERNEL);
		kfree(spent);
		spent = spent_new;
		if (!spent)
			return NULL;
		spent->length = length_new;
	}
	strcpy(spent->data + spent->usage, linebuf);
	spent->usage += count;

	return spent;
}

static int
strom_proc_open(struct inode *inode, struct file *filp)
{
	strom_proc_entry   *spent;
	mapped_gpu_memory  *mgmem;
	struct mutex	   *mutex;
	struct list_head   *slot;
	nvidia_p2p_page_table_t *page_table;
	int					i, j;

	spent = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!spent)
		return -ENOMEM;
	spent->length = PAGE_SIZE - offsetof(strom_proc_entry, data);
	spent->usage  = 0;

	/* headline */
	spent = strom_proc_printf(spent, "# NVM-Strom Mapped GPU Memory\n");

	/* for each mapping */
	for (i=0; i < MAPPED_GPU_MEMORY_NSLOTS; i++)
	{
		mutex = &strom_mgmem_mutex[i];
		slot  = &strom_mgmem_slots[i];

		mutex_lock(mutex);
		list_for_each_entry(mgmem, slot, chain)
		{
			page_table = mgmem->page_table;

			spent = strom_proc_printf(
				spent,
				"slot: %d\n"
				"handle: %p\n"
				"owner: %u\n"
				"refcnt: %d\n"
				"version: %u\n"
				"page_size: %zu\n"
				"entries: %u\n",
				i,
				(void *)mgmem->handle,
				mgmem->owner,
				mgmem->refcnt,
				page_table->version,
				mgmem->gpu_page_sz,
				page_table->entries);

			for (j=0; j < page_table->entries; j++)
			{
				spent = strom_proc_printf(
					spent,
					"PTE: V:%p <--> P:%p\n",
					(void *)(mgmem->iomap_vaddrs[j]),
					(void *)(page_table->pages[j]->physical_address));
			}
			spent = strom_proc_printf(spent, "\n");
		}
		mutex_unlock(mutex);
	}

	if (!spent)
		return -ENOMEM;

	filp->private_data = spent;

	return 0;
}

static ssize_t
strom_proc_read(struct file *filp, char __user *buf, size_t len, loff_t *pos)
{
	strom_proc_entry   *spent = filp->private_data;

	if (!spent)
		return -EINVAL;

	if (*pos >= spent->usage)
		return 0;
	if (*pos + len >= spent->usage)
		len = spent->usage - *pos;

	if (copy_to_user(buf, spent->data + *pos, len))
		return -EFAULT;

	*pos += len;

	return len;
}

static int
strom_proc_release(struct inode *inode, struct file *filp)
{
	strom_proc_entry   *spent = filp->private_data;

	if (spent)
		kfree(spent);
	return 0;
}

static long
strom_proc_ioctl(struct file *filp,
				 unsigned int cmd,
				 unsigned long arg)
{
	int			rc;

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

		case STROM_IOCTL__MEMCPY_SSD2GPU:
			rc = strom_ioctl_memcpy_ssd2gpu((void __user *) arg);
			break;

		case STROM_IOCTL__MEMCPY_SSD2GPU_ASYNC:
			rc = strom_ioctl_memcpy_ssd2gpu_async((void __user *) arg);
			break;

		case STROM_IOCTL__MEMCPY_SSD2GPU_WAIT:
			rc = strom_ioctl_memcpy_ssd2gpu_wait((void __user *) arg);
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
	.read			= strom_proc_read,
	.release		= strom_proc_release,
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

	/* init strom_dma_task_locks/slots */
	for (i=0; i < STROM_DMA_TASK_NSLOTS; i++)
	{
		spin_lock_init(&strom_dma_task_locks[i]);
		INIT_LIST_HEAD(&strom_dma_task_slots[i]);
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
	prInfo("/proc/nvme-strom entry was registered");
	return 0;
}
module_init(nvme_strom_init);

void __exit nvme_strom_exit(void)
{
	strom_exit_extra_symbols();
	proc_remove(nvme_strom_proc);
	prInfo("/proc/nvme-strom entry was unregistered");
}
module_exit(nvme_strom_exit);

MODULE_AUTHOR("KaiGai Kohei <kaigai@kaigai.gr.jp>");
MODULE_DESCRIPTION("SSD-to-GPU Direct Stream Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
