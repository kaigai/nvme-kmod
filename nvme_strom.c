/*
 * NVMe-Strom
 *
 * A Linux kernel driver to support SSD-to-GPU direct stream.
 *
 *
 *
 *
 */
#include <asm/cpufeature.h>
#include <asm/uaccess.h>
#ifdef CONFIG_X86_64
#include <asm/i387.h>
#endif
#include <linux/buffer_head.h>
#include <linux/crc32c.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/magic.h>
#include <linux/major.h>
#include <linux/moduleparam.h>
#include <linux/nvme.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <generated/utsrelease.h>
#include "nv-p2p.h"
#include "nvme_strom.h"

/* turn on/off debug message */
static int	nvme_strom_debug = 1;
module_param(nvme_strom_debug, int, 0644);
MODULE_PARM_DESC(nvme_strom_debug, "");

/* check the target kernel to build */
#if defined(RHEL_MAJOR) && (RHEL_MAJOR == 7)
#define STROM_TARGET_KERNEL_RHEL7		1
#else
#error Not a supported Linux kernel
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

/* message verbosity control */
static int	verbose = 0;
module_param(verbose, int, 1);
MODULE_PARM_DESC(verbose, "turn on/off debug message");

#define prDebug(fmt, ...)												\
	do {																\
		if (verbose > 1)												\
			printk(KERN_ALERT "nvme-strom(%s:%d): " fmt "\n",			\
				   __FUNCTION__, __LINE__, ##__VA_ARGS__);				\
		else if (verbose)												\
			printk(KERN_ALERT "nvme-strom: " fmt "\n", ##__VA_ARGS__);	\
	} while(0)

#define prInfo(fmt, ...)												\
	do {																\
		if (verbose)													\
			printk(KERN_INFO "nvme-strom: " fmt "\n", ##__VA_ARGS__);	\
	} while(0)

#define prNotice(fmt, ...)												\
	do {																\
		printk(KERN_NOTICE "nvme-strom: " fmt "\n", ##__VA_ARGS__);		\
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
#include "extra_ksyms.c"

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
	int					hindex;		/* index of the hash slot */
	int					refcnt;		/* number of the concurrent tasks */
	kuid_t				owner;		/* effective user-id who mapped this
									 * device memory */
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
static spinlock_t		strom_mgmem_locks[MAPPED_GPU_MEMORY_NSLOTS];
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
	spinlock_t		   *lock = &strom_mgmem_locks[index];
	struct list_head   *slot = &strom_mgmem_slots[index];
	unsigned long		flags;
	mapped_gpu_memory  *mgmem;

	spin_lock_irqsave(lock, flags);
	list_for_each_entry(mgmem, slot, chain)
	{
		if (mgmem->handle == handle &&
			uid_eq(mgmem->owner, current_euid()))
		{
			/* sanity checks */
			Assert((unsigned long)mgmem == handle);
			Assert(mgmem->hindex == index);

			mgmem->refcnt++;
			spin_unlock_irqrestore(lock, flags);

			return mgmem;
		}
	}
	spin_unlock_irqrestore(lock, flags);

	prError("P2P GPU Memory (handle=%lx) not found", handle);

	return NULL;	/* not found */
}

/*
 * strom_put_mapped_gpu_memory
 */
static void
strom_put_mapped_gpu_memory(mapped_gpu_memory *mgmem)
{
	int				index = mgmem->hindex;
	spinlock_t	   *lock = &strom_mgmem_locks[index];
	unsigned long	flags;

	spin_lock_irqsave(lock, flags);
	Assert(mgmem->refcnt > 0);
	if (--mgmem->refcnt == 0)
	{
		if (mgmem->wait_task != NULL)
		{
			wake_up_process(mgmem->wait_task);
			mgmem->wait_task = NULL;
		}
	}
	spin_unlock_irqrestore(lock, flags);
}

/*
 * callback_release_mapped_gpu_memory
 */
static void
callback_release_mapped_gpu_memory(void *private)
{
	mapped_gpu_memory  *mgmem = private;
	spinlock_t		   *lock = &strom_mgmem_locks[mgmem->hindex];
	unsigned long		handle = mgmem->handle;
	unsigned long		flags;
	int					rc;

	/* sanity check */
	Assert((unsigned long)mgmem == handle);

	spin_lock_irqsave(lock, flags);
	/*
	 * Detach this mapped GPU memory from the global list first, if
	 * application didn't unmap explicitly.
	 */
	if (mgmem->chain.next || mgmem->chain.prev)
	{
		list_del(&mgmem->chain);
		memset(&mgmem->chain, 0, sizeof(struct list_head));
	}

	/*
	 * wait for completion of the concurrent DMA tasks, if any tasks
	 * are running.
	 */
	if (mgmem->refcnt > 0)
	{
		struct task_struct *wait_task_saved = mgmem->wait_task;

		mgmem->wait_task = current;
		/* sleep until refcnt == 0 */
		set_current_state(TASK_UNINTERRUPTIBLE);
		spin_unlock_irqrestore(lock, flags);

		schedule();

		if (wait_task_saved)
			wake_up_process(wait_task_saved);

		spin_lock_irqsave(lock, flags);
		Assert(mgmem->refcnt == 0);
	}
	spin_unlock_irqrestore(lock, flags);

	/*
	 * OK, no concurrent task does not use this mapped GPU memory region
	 * at this point. So, we can release the page table and relevant safely.
	 */
	rc = __nvidia_p2p_free_page_table(mgmem->page_table);
	if (rc)
		prError("nvidia_p2p_free_page_table (handle=0x%lx, rc=%d)",
				handle, rc);
	kfree(mgmem);

	prNotice("P2P GPU Memory (handle=%p) was released", (void *)handle);

	module_put(THIS_MODULE);
}

/*
 * ioctl_map_gpu_memory
 *
 * ioctl(2) handler for STROM_IOCTL__MAP_GPU_MEMORY
 */
static int
ioctl_map_gpu_memory(StromCmd__MapGpuMemory __user *uarg)
{
	StromCmd__MapGpuMemory karg;
	mapped_gpu_memory  *mgmem;
	unsigned long		map_address;
	unsigned long		map_offset;
	unsigned long		handle;
	unsigned long		flags;
	uint32_t			entries;
	int					rc;

	if (copy_from_user(&karg, uarg, sizeof(karg)))
		return -EFAULT;

	mgmem = kmalloc(sizeof(mapped_gpu_memory), GFP_KERNEL);
	if (!mgmem)
		return -ENOMEM;

	map_address = karg.vaddress & GPU_BOUND_MASK;
	map_offset  = karg.vaddress & GPU_BOUND_OFFSET;
	handle = (unsigned long) mgmem;

	INIT_LIST_HEAD(&mgmem->chain);
	mgmem->hindex		= strom_mapped_gpu_memory_index(handle);
	mgmem->refcnt		= 0;
	mgmem->owner		= current_euid();
	mgmem->handle		= handle;
	mgmem->map_address  = map_address;
	mgmem->map_offset	= map_offset;
	mgmem->map_length	= map_offset + karg.length;
	mgmem->wait_task	= NULL;

	rc = __nvidia_p2p_get_pages(0,	/* p2p_token; deprecated */
								0,	/* va_space_token; deprecated */
								mgmem->map_address,
								mgmem->map_length,
								&mgmem->page_table,
								callback_release_mapped_gpu_memory,
								mgmem);
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

	/* return the handle of mapped_gpu_memory */
	entries = mgmem->page_table->entries;
	if (put_user(mgmem->handle, &uarg->handle) ||
		put_user(mgmem->gpu_page_sz, &uarg->gpu_page_sz) ||
		put_user(entries, &uarg->gpu_npages))
	{
		rc = -EFAULT;
		goto error_2;
	}

	prNotice("P2P GPU Memory (handle=%p) mapped "
			 "(version=%u, page_size=%zu, entries=%u)",
			 (void *)mgmem->handle,
			 mgmem->page_table->version,
			 mgmem->gpu_page_sz,
			 mgmem->page_table->entries);

	/*
	 * Warning message if mapped device memory is not aligned well
	 */
	if ((mgmem->map_offset & (PAGE_SIZE - 1)) != 0 ||
		(mgmem->map_length & (PAGE_SIZE - 1)) != 0)
	{
		prWarn("Gpu memory mapping (handle=%lx) is not aligned well "
			   "(map_offset=%lx map_length=%lx). "
			   "It may be inconvenient to submit DMA requests",
			   mgmem->handle,
			   mgmem->map_offset,
			   mgmem->map_length);
	}
	__module_get(THIS_MODULE);

	/* attach this mapped_gpu_memory */
	spin_lock_irqsave(&strom_mgmem_locks[mgmem->hindex], flags);
	list_add(&mgmem->chain, &strom_mgmem_slots[mgmem->hindex]);
	spin_unlock_irqrestore(&strom_mgmem_locks[mgmem->hindex], flags);

	return 0;

error_2:
	__nvidia_p2p_put_pages(0, 0, mgmem->map_address, mgmem->page_table);
error_1:
	kfree(mgmem);

	return rc;
}

/*
 * ioctl_unmap_gpu_memory
 *
 * ioctl(2) handler for STROM_IOCTL__UNMAP_GPU_MEMORY
 */
static int
ioctl_unmap_gpu_memory(StromCmd__UnmapGpuMemory __user *uarg)
{
	StromCmd__UnmapGpuMemory karg;
	mapped_gpu_memory  *mgmem;
	spinlock_t		   *lock;
	struct list_head   *slot;
	unsigned long		flags;
	int					i, rc;

	if (copy_from_user(&karg, uarg, sizeof(karg)))
		return -EFAULT;

	i = strom_mapped_gpu_memory_index(karg.handle);
	lock = &strom_mgmem_locks[i];
	slot = &strom_mgmem_slots[i];

	spin_lock_irqsave(lock, flags);
	list_for_each_entry(mgmem, slot, chain)
	{
		/*
		 * NOTE: I'm not 100% certain whether PID is the right check to
		 * determine availability of the virtual address of GPU device.
		 * So, this behavior may be changed in the later version.
		 */
		if (mgmem->handle == karg.handle &&
			uid_eq(mgmem->owner, current_euid()))
		{
			list_del(&mgmem->chain);
			memset(&mgmem->chain, 0, sizeof(struct list_head));
			spin_unlock_irqrestore(lock, flags);

			rc = __nvidia_p2p_put_pages(0, 0,
										mgmem->map_address,
										mgmem->page_table);
			if (rc)
				prError("failed on nvidia_p2p_put_pages: %d", rc);
			return rc;
		}
	}
	spin_unlock_irqrestore(lock, flags);

	prError("no mapped GPU memory found (handle: %lx)", karg.handle);
	return -ENOENT;
}

/*
 * ioctl_list_gpu_memory
 *
 * ioctl(2) handler for STROM_IOCTL__LIST_GPU_MEMORY
 */
static int
ioctl_list_gpu_memory(StromCmd__ListGpuMemory __user *uarg)
{
	StromCmd__ListGpuMemory karg;
	spinlock_t		   *lock;
	struct list_head   *slot;
	unsigned long		flags;
	mapped_gpu_memory  *mgmem;
	int					i, j;
	int					retval = 0;

	if (copy_from_user(&karg, uarg,
					   offsetof(StromCmd__ListGpuMemory, handles)))
		return -EFAULT;

	karg.nitems = 0;
	for (i=0; i < MAPPED_GPU_MEMORY_NSLOTS; i++)
	{
		lock = &strom_mgmem_locks[i];
		slot = &strom_mgmem_slots[i];

		spin_lock_irqsave(lock, flags);
		list_for_each_entry(mgmem, slot, chain)
		{
			j = karg.nitems++;
			if (j < karg.nrooms)
			{
				if (put_user(mgmem->handle, &uarg->handles[j]))
					retval = -EFAULT;
			}
			else
				retval = -ENOBUFS;
		}
		spin_unlock_irqrestore(lock, flags);
	}
	/* write back */
	if (copy_to_user(uarg, &karg,
					 offsetof(StromCmd__ListGpuMemory, handles)))
		retval = -EFAULT;

	return retval;
}

/*
 * ioctl_info_gpu_memory
 *
 * ioctl(2) handler for STROM_IOCTL__INFO_GPU_MEMORY
 */
static int
ioctl_info_gpu_memory(StromCmd__InfoGpuMemory __user *uarg)
{
	StromCmd__InfoGpuMemory karg;
	mapped_gpu_memory *mgmem;
	nvidia_p2p_page_table_t *page_table;
	size_t		length;
	int			i, rc = 0;

	length = offsetof(StromCmd__InfoGpuMemory, paddrs);
	if (copy_from_user(&karg, uarg, length))
		return -EFAULT;

	mgmem = strom_get_mapped_gpu_memory(karg.handle);
	if (!mgmem)
		return -ENOENT;

	page_table       = mgmem->page_table;
	karg.nitems      = page_table->entries;
	karg.version     = page_table->version;
	karg.gpu_page_sz = mgmem->gpu_page_sz;
	karg.owner       = __kuid_val(mgmem->owner);
	karg.map_offset  = mgmem->map_offset;
	karg.map_length  = mgmem->map_length;
	if (copy_to_user((void __user *)uarg, &karg, length))
		rc = -EFAULT;
	else
	{
		for (i=0; i < page_table->entries; i++)
		{
			if (i >= karg.nrooms)
			{
				rc = -ENOBUFS;
				break;
			}
			if (put_user(page_table->pages[i]->physical_address,
						 &uarg->paddrs[i]))
			{
				rc = -EFAULT;
				break;
			}
		}
	}
	strom_put_mapped_gpu_memory(mgmem);

	return rc;
}

/*
 * ioctl_check_file - checks whether the supplied file descriptor is
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
	struct nvme_ns		   *nvme_ns = (struct nvme_ns *)bd_disk->private_data;
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

	/*
	 * check block size of the device.
	 */
	if (i_sb->s_blocksize > PAGE_CACHE_SIZE)
	{
		prError("block size of '%s' is %zu; larger than PAGE_CACHE_SIZE",
				bd_disk->disk_name, (size_t)i_sb->s_blocksize);
		return -ENOTSUPP;
	}

	if (p_nvme_ns)
		*p_nvme_ns = nvme_ns;

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
 * ioctl_check_file
 *
 * ioctl(2) handler for STROM_IOCTL__CHECK_FILE
 */
static int
ioctl_check_file(StromCmd__CheckFile __user *uarg)
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

/*
 * NOTE: It looks to us Intel 750 SSD does not accept DMA request larger
 * than 128KB. However, we are not certain whether it is restriction for
 * all the NVMe-SSD devices. Right now, 128KB is a default of the max unit
 * length of DMA request.
 */
#define STROM_DMA_SSD2GPU_MAXLEN		(128 * 1024)

struct strom_dma_task
{
	struct list_head	chain;
	unsigned long		dma_task_id;/* ID of this DMA task */
	int					hindex;		/* index of hash slot */
	int					refcnt;		/* reference counter */
	struct file		   *filp;		/* source file */
	mapped_gpu_memory  *mgmem;		/* destination GPU memory segment */

	wait_queue_head_t	wait_tasks;	/* waitq for the tasks that are waiting */

	/*
	 * status of asynchronous tasks
	 *
	 * MEMO: Pay attention to error status of the asynchronous tasks.
	 * Asynchronous task may cause errors on random timing, and kernel
	 * space wants to inform this status on the next call. On the other
	 * hands, application may invoke ioctl(2) to reference DMA results,
	 * but may not. So, we have to keep an error status somewhere, but
	 * also needs to be released on appropriate timing; to avoid kernel
	 * memory leak by rude applications.
	 * If any errors, we attach strom_dma_task structure on file handler
	 * used for ioctl(2). The error status shall be reclaimed on the
	 * next time when application wait for a particular DMA task, or
	 * this file handler is closed.
	 */
	long				dma_status;
	struct file		   *ioctl_filp;
};
typedef struct strom_dma_task	strom_dma_task;

struct strom_dma_state
{
	strom_dma_task	   *dtask;
	struct nvme_ns	   *nvme_ns;	/* NVMe namespace (=SCSI LUN) */
	size_t				blocksz;	/* blocksize of this partition */
	int					blocksz_shift;	/* log2 of 'blocksz' */
	sector_t			start_sect;	/* first sector of the source partition */
	sector_t			nr_sects;	/* number of sectors of the partition */
	/* Contiguous SSD blocks */
	sector_t			src_block;	/* head of the source blocks */
	unsigned int		nr_blocks;	/* # of the contigunous source blocks */
	unsigned int		max_nblocks;/* upper limit of @nr_blocks */
	size_t				dest_offset;/* destination offset of the pending req */
	/* Current position of the destination GPU page */
	char			   *dest_iomap;	/* current mapped destination page */
	int					dest_index;	/* current index of the destination page */
	/* Buffer to keep pages in a chunk */
	struct page		   *file_pages[STROM_DMA_SSD2GPU_MAXLEN / PAGE_SIZE + 1];
};
typedef struct strom_dma_state	strom_dma_state;

#define STROM_DMA_TASK_NSLOTS		100
static spinlock_t		strom_dma_task_locks[STROM_DMA_TASK_NSLOTS];
static struct list_head	strom_dma_task_slots[STROM_DMA_TASK_NSLOTS];
static struct list_head	failed_dma_task_slots[STROM_DMA_TASK_NSLOTS];

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
 * strom_create_dma_task
 */
static long
strom_create_dma_task(struct strom_dma_state *dstate,
					  unsigned long handle,
					  int fdesc,
					  struct file *ioctl_filp)
{
	mapped_gpu_memory	   *mgmem;
	strom_dma_task		   *dtask;
	struct file			   *filp;
	struct super_block	   *i_sb;
	struct block_device	   *s_bdev;
	struct nvme_ns		   *nvme_ns;
	long					retval;
	unsigned long			flags;

	/* ensure the source file is supported */
	filp = fget(fdesc);
	if (!filp)
	{
		prError("file descriptor %d of process %u is not available",
				fdesc, current->tgid);
		return -EBADF;
	}
	retval = source_file_is_supported(filp, &nvme_ns);
	if (retval < 0)
		goto error_1;
	i_sb = filp->f_inode->i_sb;
	s_bdev = i_sb->s_bdev;

	/* get destination GPU memory */
	mgmem = strom_get_mapped_gpu_memory(handle);
	if (!mgmem)
	{
		retval = -ENOENT;
		goto error_1;
	}

	/* allocate strom_dma_task object */
	dtask = kzalloc(sizeof(strom_dma_task), GFP_KERNEL);
	if (!dtask)
	{
		retval = -ENOMEM;
		goto error_2;
	}
	dtask->dma_task_id	= (unsigned long) dtask;
	dtask->hindex		= strom_dma_task_index(dtask->dma_task_id);
    dtask->refcnt		= 1;
    dtask->filp			= filp;
    dtask->mgmem		= mgmem;
    init_waitqueue_head(&dtask->wait_tasks);
    dtask->dma_status	= 0;
    dtask->ioctl_filp	= get_file(ioctl_filp);
    /* OK, this strom_dma_task is now tracked */
	spin_lock_irqsave(&strom_dma_task_locks[dtask->hindex], flags);
	list_add(&dtask->chain, &strom_dma_task_slots[dtask->hindex]);
    spin_unlock_irqrestore(&strom_dma_task_locks[dtask->hindex], flags);

	/* Then, setup dma_task_state */
	dstate->dtask		= dtask;
	dstate->nvme_ns		= nvme_ns;
	dstate->blocksz		= i_sb->s_blocksize;
	dstate->blocksz_shift = i_sb->s_blocksize_bits;
	Assert(dstate->blocksz == (1UL << dstate->blocksz_shift));
	dstate->start_sect	= s_bdev->bd_part->start_sect;
	dstate->nr_sects	= s_bdev->bd_part->nr_sects;
	dstate->src_block	= 0;
	dstate->nr_blocks	= 0;
	dstate->max_nblocks	= STROM_DMA_SSD2GPU_MAXLEN >> dstate->blocksz_shift;
	dstate->dest_iomap	= NULL; /* map on demand */
	dstate->dest_index	= -1;

	return 0;

error_2:
	strom_put_mapped_gpu_memory(mgmem);
error_1:
	fput(filp);
	return retval;
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
strom_put_dma_task(strom_dma_task *dtask, long dma_status)
{
	int					index = strom_dma_task_index(dtask->dma_task_id);
	spinlock_t		   *lock = &strom_dma_task_locks[index];
	struct list_head   *slot;
	unsigned long		flags;

	spin_lock_irqsave(lock, flags);
	Assert(dtask->refcnt > 0);

	if (dma_status && !dtask->dma_status)
	{
		Assert(dma_status < 0);
		dtask->dma_status = dma_status;
	}

	if (--dtask->refcnt == 0)
	{
		struct file	   *ioctl_filp = dtask->ioctl_filp;
		long			status = dtask->dma_status;

		/* detach from the global hash table */
		list_del(&dtask->chain);
		/* if any error status, move to the ioctl_filp without kfree() */
		if (status)
		{
			slot = &failed_dma_task_slots[index];
			list_add_tail(slot, &dtask->chain);
		}
		/* wake up all the waiting tasks, if any */
		wake_up_all(&dtask->wait_tasks);
		/* release relevant resources */
		strom_put_mapped_gpu_memory(dtask->mgmem);
		fput(dtask->filp);
		if (!status)
			kfree(dtask);
		spin_unlock_irqrestore(lock, flags);

		fput(ioctl_filp);

		prInfo("DMA task (id=%p) was completed", dtask);

		return;
	}
	spin_unlock_irqrestore(lock, flags);
}

/*
 * Slow RAM->GPU synchronous copy
 */
static void
memcpy_simd(volatile void __iomem *__dst, const void *__src, size_t nbytes)
{
	volatile char __iomem *dst = __dst;
	const char *src = __src;
	size_t		unitsz;

#ifdef CONFIG_X86_64
	kernel_fpu_begin();
	/*
	 * Use of %ymm register needs 256-bits alignment
	 */
	if (cpu_has_avx &&
		((uintptr_t)dst & 0x1f) == 0 && ((uintptr_t)src & 0x1f) == 0)
	{
		unitsz = 8 * 0x20;	/* 8x 256bits register */

		while (nbytes >= unitsz)
		{
			/* read */
			asm volatile("vmovdqa %0,%%ymm0" : : "m" (src[0x00]));
			asm volatile("vmovdqa %0,%%ymm1" : : "m" (src[0x20]));
			asm volatile("vmovdqa %0,%%ymm2" : : "m" (src[0x40]));
			asm volatile("vmovdqa %0,%%ymm3" : : "m" (src[0x60]));
			asm volatile("vmovdqa %0,%%ymm4" : : "m" (src[0x80]));
			asm volatile("vmovdqa %0,%%ymm5" : : "m" (src[0xa0]));
			asm volatile("vmovdqa %0,%%ymm6" : : "m" (src[0xc0]));
			asm volatile("vmovdqa %0,%%ymm7" : : "m" (src[0xe0]));

			/* write */
			asm volatile("vmovdqa %%ymm0,%0" : : "m" (dst[0x00]));
			asm volatile("vmovdqa %%ymm1,%0" : : "m" (dst[0x20]));
			asm volatile("vmovdqa %%ymm2,%0" : : "m" (dst[0x40]));
			asm volatile("vmovdqa %%ymm3,%0" : : "m" (dst[0x60]));
			asm volatile("vmovdqa %%ymm4,%0" : : "m" (dst[0x80]));
			asm volatile("vmovdqa %%ymm5,%0" : : "m" (dst[0xa0]));
			asm volatile("vmovdqa %%ymm6,%0" : : "m" (dst[0xc0]));
			asm volatile("vmovdqa %%ymm7,%0" : : "m" (dst[0xe0]));

			dst += unitsz;
			src += unitsz;
			nbytes -= unitsz;
		}
	}

	/*
	 * Use of %xmm register needs 128bits alignment
	 */
	if (cpu_has_xmm &&
		((uintptr_t)dst & 0x0f) == 0 && ((uintptr_t)src & 0x0f) == 0)
	{
		unitsz = 8 * 0x10;	/* 8x 128bits register */

		while (nbytes >= unitsz)
		{
			/* read */
			asm volatile("movdqa %0,%%xmm0" : : "m" (src[0x00]));
			asm volatile("movdqa %0,%%xmm1" : : "m" (src[0x10]));
			asm volatile("movdqa %0,%%xmm2" : : "m" (src[0x20]));
			asm volatile("movdqa %0,%%xmm3" : : "m" (src[0x30]));
			asm volatile("movdqa %0,%%xmm4" : : "m" (src[0x40]));
			asm volatile("movdqa %0,%%xmm5" : : "m" (src[0x50]));
			asm volatile("movdqa %0,%%xmm6" : : "m" (src[0x60]));
			asm volatile("movdqa %0,%%xmm7" : : "m" (src[0x70]));

			/* write */
			asm volatile("movdqa %%xmm0,%0" : : "m" (dst[0x00]));
			asm volatile("movdqa %%xmm1,%0" : : "m" (dst[0x10]));
			asm volatile("movdqa %%xmm2,%0" : : "m" (dst[0x20]));
			asm volatile("movdqa %%xmm3,%0" : : "m" (dst[0x30]));
			asm volatile("movdqa %%xmm4,%0" : : "m" (dst[0x40]));
			asm volatile("movdqa %%xmm5,%0" : : "m" (dst[0x50]));
			asm volatile("movdqa %%xmm6,%0" : : "m" (dst[0x60]));
			asm volatile("movdqa %%xmm7,%0" : : "m" (dst[0x70]));

			dst += unitsz;
			src += unitsz;
			nbytes -= unitsz;
		}
	}
	kernel_fpu_end();
#endif
	memcpy_toio(dst, src, nbytes);
}

static int
slow_ram2gpu_memcpy(strom_dma_state *dstate, size_t dest_offset,
					struct page *fpage, size_t page_ofs, size_t page_len)
{
	strom_dma_task	   *dtask = dstate->dtask;
	mapped_gpu_memory  *mgmem = dtask->mgmem;
	nvidia_p2p_page_table_t *page_table = mgmem->page_table;
	uint64_t			phy_addr;
	char			   *src_buffer;
	char			   *dst_buffer;
	size_t				copy_len;
	int					i;

	do {
		i = dest_offset >> mgmem->gpu_page_shift;
		copy_len = Min(page_len, (mgmem->gpu_page_sz -
								  (dest_offset & (mgmem->gpu_page_sz - 1))));

		/* map destination GPU page, if needed */
		if (!dstate->dest_iomap || i != dstate->dest_index)
		{
			if (dstate->dest_iomap)
				iounmap(dstate->dest_iomap);
			Assert(i < mgmem->page_table->entries);
			phy_addr = page_table->pages[i]->physical_address;
			dstate->dest_iomap = ioremap(phy_addr, mgmem->gpu_page_sz);
			if (!dstate->dest_iomap)
				return -ENOMEM;
			dstate->dest_index = i;
		}

		/* map source RAM page, and memcpy by CPU */
		src_buffer = kmap_atomic(fpage);
		dst_buffer = (dstate->dest_iomap +
					  (dest_offset & (mgmem->gpu_page_sz - 1)));
		memcpy_simd(dst_buffer, src_buffer + page_ofs, copy_len);
		__kunmap_atomic(src_buffer);

		page_len -= copy_len;
		page_ofs += copy_len;
		dest_offset += copy_len;
	} while (page_len > 0);

	return 0;
}

/*
 * DMA transaction for SSD->GPU asynchronous copy
 */
#ifdef STROM_TARGET_KERNEL_RHEL7
#include "nvme_strom.rhel7.c"
#else
#error "no platform specific NVMe-SSD routines"
#endif

/* alternative of the core nvme_alloc_iod */
static struct nvme_iod *
nvme_alloc_iod(size_t nbytes,
			   mapped_gpu_memory *mgmem,
			   struct nvme_dev *dev, gfp_t gfp)
{
	struct nvme_iod *iod;
	unsigned int	nsegs;
	unsigned int	nprps;
	unsigned int	npages;

	/*
	 * Will slightly overestimate the number of pages needed.  This is OK
	 * as it only leads to a small amount of wasted memory for the lifetime of
	 * the I/O.
	 */
	nsegs = DIV_ROUND_UP(nbytes + mgmem->gpu_page_sz, mgmem->gpu_page_sz);
	nprps = DIV_ROUND_UP(nbytes + dev->page_size, dev->page_size);
	npages = DIV_ROUND_UP(8 * nprps, dev->page_size - 8);

	iod = kmalloc(offsetof(struct nvme_iod, sg[nsegs]) +
				  sizeof(__le64) * npages, gfp);
	if (iod)
	{
		iod->private = 0;
		iod->npages = -1;
		iod->offset = offsetof(struct nvme_iod, sg[nsegs]);
		iod->length = nbytes;
		iod->nents = 0;
		iod->first_dma = 0ULL;
	}
	sg_init_table(iod->sg, nsegs);

	return iod;
}

static int
submit_ssd2gpu_memcpy(strom_dma_state *dstate)
{
	strom_dma_task	   *dtask = dstate->dtask;
	mapped_gpu_memory  *mgmem = dtask->mgmem;
	nvidia_p2p_page_table_t *page_table = mgmem->page_table;
	struct nvme_ns	   *nvme_ns = dstate->nvme_ns;
	struct nvme_dev	   *nvme_dev = nvme_ns->dev;
	struct nvme_iod	   *iod;
	size_t				offset;
	size_t				total_nbytes;
	dma_addr_t			base_addr;
	int					length;
	int					i, base;
	int					retval;

	total_nbytes = (dstate->nr_blocks << dstate->blocksz_shift);
	if (!total_nbytes || total_nbytes > STROM_DMA_SSD2GPU_MAXLEN)
		return -EINVAL;
	if (dstate->dest_offset < mgmem->map_offset ||
		dstate->dest_offset + total_nbytes > (mgmem->map_offset +
											  mgmem->map_length))
		return -ERANGE;

	iod = nvme_alloc_iod(total_nbytes,
						 mgmem,
						 nvme_dev,
						 GFP_KERNEL);
	if (!iod)
		return -ENOMEM;

	base = (dstate->dest_offset >> mgmem->gpu_page_shift);
	offset = (dstate->dest_offset & (mgmem->gpu_page_sz - 1));
	prDebug("base=%d offset=%zu dest_offset=%zu total_nbytes=%zu",
			base, offset, dstate->dest_offset, total_nbytes);

	for (i=0; i < page_table->entries; i++)
	{
		if (!total_nbytes)
			break;

		base_addr = page_table->pages[base + i]->physical_address;
		length = Min(total_nbytes, mgmem->gpu_page_sz - offset);
		iod->sg[i].page_link = 0;
		iod->sg[i].dma_address = base_addr + offset;
		iod->sg[i].length = length;
		iod->sg[i].dma_length = length;
		iod->sg[i].offset = 0;

		offset = 0;
		total_nbytes -= length;
	}

	if (total_nbytes)
	{
		__nvme_free_iod(nvme_dev, iod);
		return -EINVAL;
	}
	sg_mark_end(&iod->sg[i]);
	iod->nents = i;

	retval = nvme_submit_async_read_cmd(dstate, iod);
	if (retval)
		__nvme_free_iod(nvme_dev, iod);

	/* clear the state */
	dstate->nr_blocks = 0;
	dstate->src_block = 0;
	dstate->dest_offset = ~0UL;

	return retval;
}

/*
 * strom_memcpy_ssd2gpu_wait - synchronization of a dma_task
 */
static int
strom_memcpy_ssd2gpu_wait(unsigned int ntasks,
						  unsigned int nwaits,
						  unsigned long *dma_task_id_array,
						  unsigned long *p_failed_dma_task_id,
						  long *p_failed_dma_status)
{
	strom_dma_task	   *dtask;
	wait_queue_t		__task_waitq[20];
	wait_queue_t	   *task_waitq;
	wait_queue_t	   *__task_waitq_array[20];
	wait_queue_t	  **task_waitq_array;
	unsigned long		dma_task_id;
	unsigned long		flags;
	spinlock_t		   *lock;
	struct list_head   *slot;
	bool				first_try = true;
	int					wq_index = 0;
	int					w_index = 0;
	int					r_index;
	int					hindex;
	int					retval = 0;

	/* temporary buffer for wait queue */
	if (ntasks <= lengthof(__task_waitq))
	{
		/* skip kmalloc for small ntasks */
		task_waitq = __task_waitq;
		task_waitq_array = __task_waitq_array;
	}
	else
	{
		task_waitq = kmalloc(sizeof(wait_queue_t) * ntasks,
							 GFP_KERNEL);
		task_waitq_array = kmalloc(sizeof(wait_queue_t *) * ntasks,
								   GFP_KERNEL);
		if (!task_waitq || !task_waitq_array)
		{
			kfree(task_waitq);
			kfree(task_waitq_array);
			return -ENOMEM;
		}
	}
	memset(task_waitq, 0, sizeof(wait_queue_t) * ntasks);
	memset(task_waitq_array, 0, sizeof(wait_queue_t *) * ntasks);

	prDebug("Begin strom_memcpy_ssd2gpu_wait(ntasks=%u, nwaits=%u)",
			ntasks, nwaits);
	for (;;)
	{
		set_current_state(TASK_INTERRUPTIBLE);

		for (r_index = w_index; r_index < ntasks; r_index++)
		{
			dma_task_id = dma_task_id_array[r_index];
			hindex = strom_dma_task_index(dma_task_id);

			lock = &strom_dma_task_locks[hindex];
			spin_lock_irqsave(lock, flags);

			/*
			 * Look up failed DMA tasks first to pick up its error status
			 * and return it immediately, if any.
			 */
			slot = &failed_dma_task_slots[hindex];
			list_for_each_entry(dtask, slot, chain)
			{
				if (dtask->dma_task_id == dma_task_id)
				{
					if (p_failed_dma_task_id)
						*p_failed_dma_task_id = dma_task_id;
					if (p_failed_dma_status)
						*p_failed_dma_status = dtask->dma_status;
					list_del(&dtask->chain);
					kfree(dtask);
					spin_unlock_irqrestore(lock, flags);

					retval = -EIO;

					goto bailout;
				}
			}

			/*
			 * OK, this DMA task either still running or successfully done.
			 */
			slot = &strom_dma_task_slots[hindex];
			list_for_each_entry(dtask, slot, chain)
			{
				/* Hmm, this task is still in-progress */
				if (dtask->dma_task_id == dma_task_id)
				{
					if (first_try)
					{
						init_waitqueue_entry(&task_waitq[wq_index], current);
						add_wait_queue(&dtask->wait_tasks,
									   &task_waitq[wq_index]);
						task_waitq_array[r_index] = &task_waitq[wq_index];
						wq_index++;
					}
					goto found;
				}
			}
			/* move the completed tasks to the earlier half */
			dma_task_id_array[r_index] = dma_task_id_array[w_index];
			dma_task_id_array[w_index] = dma_task_id;
			task_waitq_array[r_index] = task_waitq_array[w_index];
			task_waitq_array[w_index] = NULL;	/* already not valid */
			w_index++;
		found:
			spin_unlock_irqrestore(lock, flags);
		}

		if (w_index >= nwaits)
			break;

		if (signal_pending(current))
		{
			retval = -EINTR;
			break;
		}
		/* sleep until somebody kicks me */
		schedule();
	}
bailout:
	/* revert current task status */
	set_current_state(TASK_RUNNING);

	/*
	 * Remove the current context from wait-queue of the DMA task which
	 * is still running.
	 */
	for (r_index = w_index; r_index < ntasks; r_index++)
	{
		dma_task_id = dma_task_id_array[r_index];
		hindex = strom_dma_task_index(dma_task_id);

		lock = &strom_dma_task_locks[hindex];
		slot = &strom_dma_task_slots[hindex];

		spin_lock_irqsave(lock, flags);
		list_for_each_entry(dtask, slot, chain)
		{
			if (dtask->dma_task_id == dma_task_id)
			{
				remove_wait_queue(&dtask->wait_tasks,
								  task_waitq_array[r_index]);
				break;
			}
		}
		spin_unlock_irqrestore(lock, flags);
	}

	/* cleanup */
	if (task_waitq != __task_waitq)
		kfree(task_waitq);
	if (task_waitq_array != __task_waitq_array)
		kfree(task_waitq_array);

	return (retval < 0 ? retval : w_index);
}

/*
 * do_ssd2gpu_async_memcpy - kicker of asyncronous DMA requests
 */
static long
do_ssd2gpu_async_memcpy(strom_dma_state *dstate,
						int nchunks, strom_dma_chunk *dchunks)
{
	strom_dma_task	   *dtask = dstate->dtask;
	mapped_gpu_memory  *mgmem = dtask->mgmem;
	struct file		   *filp = dtask->filp;
	struct page		   *fpage;
	long				retval;
	size_t				i_size;
	size_t				dest_offset = ~0UL;
	unsigned int		i;

	i_size = i_size_read(filp->f_inode);
	for (i=0; i < nchunks; i++)
	{
		strom_dma_chunk *dchunk = &dchunks[i];
		loff_t		pos;
		loff_t		end;
		size_t		curr_offset;

		if (dchunk->length == 0)
			continue;

		pos = dchunk->fpos;
		end = pos + dchunk->length;
		curr_offset = dchunk->offset + mgmem->map_offset;

		/* range checks */
		if (pos > i_size ||
			end > i_size ||
			curr_offset + dchunk->length > mgmem->map_length)
			return -ERANGE;

		/*
		 * Submit if pending SSD2GPU DMA request is not merginable with
		 * the next chunk.
		 */
		if (dstate->nr_blocks > 0 &&
			curr_offset != (dstate->dest_offset +
							dstate->nr_blocks * dstate->blocksz))
		{
			retval = submit_ssd2gpu_memcpy(dstate);
			if (retval)
			{
				prDebug("submit_ssd2gpu_memcpy() = %ld", retval);
				return retval;
			}
			Assert(dstate->nr_blocks == 0);
		}

		/*
		 * alignment checks
		 */
		if ((curr_offset & (sizeof(int) - 1)) != 0 ||
			(pos & (dstate->blocksz - 1)) != 0 ||
			(end & (dstate->blocksz - 1)) != 0)
		{
			prError("alignment violation pos=%zu end=%zu --> dest=%zu",
					(size_t)pos, (size_t)end, (size_t)dest_offset);
			return -EINVAL;
		}

		while (pos < end)
		{
			size_t		page_ofs = (pos & (PAGE_CACHE_SIZE - 1));
			size_t		page_len;

			if (end - pos <= PAGE_CACHE_SIZE)
				page_len = end - pos;
			else
				page_len = PAGE_CACHE_SIZE - page_ofs;

			Assert((page_ofs & (dstate->blocksz - 1)) == 0 &&
				   (page_len & (dstate->blocksz - 1)) == 0);

			/*
			 * NOTE: Theoretical performance of RAM-to-GPU transfer should
			 * be faster than SSD-to-GPU, however, we cannot use DMA engine
			 * of GPU device, thus, we have to map PCI BAR region with
			 * ioremap() then copy values by CPU.
			 * It tends to use unreasonably small packet even if SSE/AVX
			 * registers are used.
			 * So, as a workaround, RAM-to-GPU transfer shall be applied
			 * only when the cached page is dirty.
			 */
			fpage = find_lock_page(filp->f_mapping, pos >> PAGE_CACHE_SHIFT);
			if (fpage && PageDirty(fpage))
			{
				/* Submit SSD2GPU DMA, if any pending request */
				if (dstate->nr_blocks > 0)
				{
					retval = submit_ssd2gpu_memcpy(dstate);
					if (retval)
					{
						unlock_page(fpage);
						page_cache_release(fpage);

						prDebug("submit_ssd2gpu_memcpy() = %ld", retval);
						return retval;
					}
					Assert(dstate->nr_blocks == 0);
				}

				/* Slow RAM2GPU Copy */
				retval = slow_ram2gpu_memcpy(dstate, curr_offset,
											 fpage, page_ofs, page_len);

				unlock_page(fpage);
				page_cache_release(fpage);

				if (retval)
				{
					prDebug("slow_ram2gpu_memcpy() = %ld", retval);
					return retval;
				}
				curr_offset += page_len;
			}
			else
			{
				struct buffer_head	bh;
				sector_t			lba_curr;
				unsigned int		nr_blocks;

				/* Cache shall not be referenced */
				if (fpage)
				{
					unlock_page(fpage);
					page_cache_release(fpage);
				}

				/* Lookup underlying block number */
				memset(&bh, 0, sizeof(bh));
				bh.b_size = dstate->blocksz;

				retval = strom_get_block(filp->f_inode,
										 pos >> dstate->blocksz_shift,
										 &bh, 0);
				if (retval)
				{
					prDebug("strom_get_block() = %ld", retval);
					return retval;
				}
				lba_curr = bh.b_blocknr + (page_ofs >> dstate->blocksz_shift);
				nr_blocks = (page_len >> dstate->blocksz_shift);
				/* Is it merginable with the pending request? */
				if (dstate->nr_blocks > 0 &&
					dstate->nr_blocks + nr_blocks <= dstate->max_nblocks &&
					dstate->src_block + dstate->nr_blocks == lba_curr)
				{
					dstate->nr_blocks += nr_blocks;
				}
				else
				{
					/* Submit the latest pending blocks but not merginable */
					if (dstate->nr_blocks > 0)
					{
						retval = submit_ssd2gpu_memcpy(dstate);
						if (retval)
						{
							prDebug("submit_ssd2gpu_memcpy() = %ld", retval);
							return retval;
						}
						Assert(dstate->nr_blocks == 0);
					}
					/* This block becomes new head of the pending request */
					dstate->dest_offset = curr_offset;
					dstate->src_block = lba_curr;
					dstate->nr_blocks = nr_blocks;
				}
			}
			pos += page_len;
		}
	}
	/* Submit pending SSD2GPU request, if any */
	if (dstate->nr_blocks > 0)
	{
		retval = submit_ssd2gpu_memcpy(dstate);
		if (retval)
			prDebug("submit_ssd2gpu_memcpy() = %ld", retval);
	}
	return retval;
}

/*
 * ioctl(2) handler for STROM_IOCTL__MEMCPY_SSD2GPU(_ASYNC)
 */
static long
ioctl_memcpy_ssd2gpu_async(StromCmd__MemCpySsdToGpu __user *uarg,
						   struct file *ioctl_filp,
						   bool do_sync)
{
	StromCmd__MemCpySsdToGpu karg;
	strom_dma_chunk	   *dchunks;
	strom_dma_state		dstate;
	unsigned long		dma_task_id;
	long				retval;

	/* copy ioctl(2) arguments from the userspace */
	if (copy_from_user(&karg, uarg,
					   offsetof(StromCmd__MemCpySsdToGpu, chunks)))
		return -EFAULT;
	dchunks = kmalloc(sizeof(strom_dma_chunk) * karg.nchunks, GFP_KERNEL);
	if (!dchunks)
		return -ENOMEM;
	if (copy_from_user(dchunks, uarg->chunks,
					   sizeof(strom_dma_chunk) * karg.nchunks))
	{
		kfree(dchunks);
		return -EFAULT;
	}

	/* construct dma_tast and dma_state */
	retval = strom_create_dma_task(&dstate,
								   karg.handle,
								   karg.fdesc,
								   ioctl_filp);
	if (retval < 0)
	{
		kfree(dchunks);
		return retval;
	}
	dma_task_id = dstate.dtask->dma_task_id;

	/* then, submit asynchronous DMA requests */
	retval = do_ssd2gpu_async_memcpy(&dstate, karg.nchunks, dchunks);

	/* release resources no longer referenced */
	strom_put_dma_task(dstate.dtask, retval);
	if (dstate.dest_iomap)
		iounmap(dstate.dest_iomap);

	/* inform the dma_task_id to userspace */
	if (retval == 0 && put_user(dma_task_id, &uarg->dma_task_id))
		retval = -EFAULT;
	/* synchronization if necessary */
	if (retval || do_sync)
	{
		while (strom_memcpy_ssd2gpu_wait(1, 1, &dma_task_id,
										 NULL, NULL) == -EINTR)
		{
			prNotice("dma_task_id=%p was interrupted by a signel",
					 (void *)dma_task_id);
		}
	}
	kfree(dchunks);

	return retval;
}

/*
 * ioctl_memcpy_ssd2gpu_reorder
 */
static long
do_writeback_to_user_buffer(strom_dma_state *dstate,
							unsigned int nr_pages,
							loff_t fpos, size_t length,
							char __user *uaddr)
{
	struct file	   *filp = dstate->dtask->filp;
	struct page	   *fpage;
	long			retval;
	int				index;

	for (index=0; index < nr_pages; index++)
	{
		size_t		page_ofs = (fpos & (PAGE_CACHE_SIZE - 1));
		size_t		page_len = Min(length, PAGE_CACHE_SIZE) - page_ofs;
		char	   *kaddr;
		ulong		left;

		/* synchronous read if page is not uncached */
		fpage = dstate->file_pages[index];
		if (!fpage)
		{
			fpage = read_mapping_page(filp->f_mapping,
									  fpos >> PAGE_CACHE_SHIFT,
									  filp);
			if (IS_ERR(fpage))
			{
				retval = PTR_ERR(fpage);
				goto error;
			}
			lock_page(fpage);
		}
		Assert(fpage != NULL);

		/* write-back the pages to userspace, like file_read_actor() */
		if (!fault_in_pages_writeable(uaddr, page_len))
		{
			kaddr = kmap_atomic(fpage);
			left = __copy_to_user_inatomic(uaddr,
										   kaddr + page_ofs,
										   page_len);
			kunmap_atomic(kaddr);
			if (left == 0)
				goto success;
		}
		/* do it the slow way */
		kaddr = kmap(fpage);
		left = __copy_to_user(uaddr, kaddr + page_ofs, page_len);
		kunmap(fpage);
	success:
		unlock_page(fpage);
		page_cache_release(fpage);
		if (unlikely(left))
		{
			retval = -EFAULT;
			goto error;
		}
		Assert(page_len <= length);
		length -= page_len;
		uaddr += page_len;
		fpos  += page_len;
	}
	return 0;

error:
	while (index < nr_pages)
	{
		fpage = dstate->file_pages[index++];
		if (fpage)
		{
			unlock_page(fpage);
			page_cache_release(fpage);
		}
	}
	return retval;
}

static long
exec_ssd2gpu_memcpy_async(strom_dma_state *dstate,
						  unsigned int nr_pages,
						  loff_t fpos, size_t length,
						  size_t dest_offset)
{
	struct file	   *filp = dstate->dtask->filp;
	struct page	   *fpage;
	long			retval = 0;
	int				index = 0;

	/*
	 * Submit if pending SSD2GPU DMA request is not merginable with
	 * the next chunk.
	 */
	if (dstate->nr_blocks > 0 &&
		dest_offset != (dstate->dest_offset +
						dstate->nr_blocks * dstate->blocksz))
	{
		retval = submit_ssd2gpu_memcpy(dstate);
		if (retval)
		{
			prDebug("submit_ssd2gpu_memcpy() = %ld", retval);
			goto error;
		}
		Assert(dstate->nr_blocks == 0);
	}

	for (index=0; index < nr_pages; index++)
	{
		size_t		page_ofs = (fpos & (PAGE_CACHE_SIZE - 1));
		size_t		page_len = Min(length, PAGE_CACHE_SIZE) - page_ofs;

		Assert((page_ofs & (dstate->blocksz - 1)) == 0 &&
			   (page_len & (dstate->blocksz - 1)) == 0);
		fpage = dstate->file_pages[index];
		if (fpage && PageDirty(fpage))
		{
			/* Submit SSD2GPU DMA, if any pending request */
			if (dstate->nr_blocks > 0)
			{
				retval = submit_ssd2gpu_memcpy(dstate);
				if (retval)
				{
					prDebug("submit_ssd2gpu_memcpy() = %ld", retval);
					goto error;
				}
				Assert(dstate->nr_blocks == 0);
			}
			/* Fallback to slow memcpy */
			retval = slow_ram2gpu_memcpy(dstate, dest_offset,
										 fpage, page_ofs, page_len);
			if (retval)
			{
				prDebug("slow_ram2gpu_memcpy() = %ld", retval);
				goto error;
			}
			unlock_page(fpage);
			page_cache_release(fpage);
		}
		else
		{
			struct buffer_head	bh;
			sector_t			lba_curr;
			unsigned int		nr_blocks;

			/* lookup underlying block number */
			memset(&bh, 0, sizeof(bh));
			bh.b_size = dstate->blocksz;

			retval = strom_get_block(filp->f_inode,
									 fpos >> dstate->blocksz_shift,
									 &bh, 0);
			if (retval)
			{
				prDebug("strom_get_block() = %ld", retval);
				goto error;
			}
			lba_curr = bh.b_blocknr + (page_ofs >> dstate->blocksz_shift);
			nr_blocks = (page_len >> dstate->blocksz_shift);

			/* Is it merginable with the pending request? */
			if (dstate->nr_blocks > 0 &&
				dstate->nr_blocks + nr_blocks <= dstate->max_nblocks &&
				dstate->src_block + dstate->nr_blocks == lba_curr)
			{
				dstate->nr_blocks += nr_blocks;
			}
			else
			{
				/* Submit the latest pending blocks but not merginable */
				if (dstate->nr_blocks > 0)
				{
					retval = submit_ssd2gpu_memcpy(dstate);
					if (retval)
					{
						prDebug("submit_ssd2gpu_memcpy() = %ld", retval);
						goto error;
					}
					Assert(dstate->nr_blocks == 0);
				}
				/* This block becomes new head of the pending request */
				dstate->dest_offset = dest_offset;
				dstate->src_block = lba_curr;
				dstate->nr_blocks = nr_blocks;
			}

			/* page cache is no longer referenced */
			if (fpage)
			{
				unlock_page(fpage);
				page_cache_release(fpage);
			}
		}
		Assert(page_len <= length);
		length -= page_len;
		fpos += page_len;
		dest_offset += page_len;
	}
	Assert(length == 0);
	return 0;

error:
	while (index < nr_pages)
	{
		fpage = dstate->file_pages[index++];
		if (fpage)
		{
			unlock_page(fpage);
			page_cache_release(fpage);
		}
	}
	return retval;
}

/*
 * ioctl(2) handler for STROM_IOCTL__MEMCPY_SSD2GPU_WRITEBACK
 */
static long
ioctl_memcpy_ssd2gpu_writeback(StromCmd__MemCpySsdToGpuWriteBack __user *uarg,
							   struct file *ioctl_filp)
{
	StromCmd__MemCpySsdToGpuWriteBack karg;
	mapped_gpu_memory  *mgmem;
	strom_dma_state		dstate;
	loff_t			   *dchunks;
	uint32_t		   *block_nums = NULL;
	unsigned long		dma_task_id;
	struct file		   *filp;
	struct page		   *fpage;
	size_t				i_size;
	size_t				dest_offset;
	long				retval;
	int					i;

	if (copy_from_user(&karg, uarg,
					   offsetof(StromCmd__MemCpySsdToGpuWriteBack, chunks)))
		return -EFAULT;
	dchunks = kmalloc(sizeof(loff_t) * karg.nchunks, GFP_KERNEL);
	if (!dchunks)
		return -ENOMEM;
	if (copy_from_user(dchunks, uarg->chunks,
					   sizeof(loff_t) * karg.nchunks))
	{
		kfree(dchunks);
		return -EFAULT;
	}

	/* Optional BlockNumber array if any */
	if (karg.block_nums)
	{
		block_nums = kmalloc(sizeof(uint32_t) * karg.nchunks, GFP_KERNEL);
		if (!block_nums)
		{
			kfree(dchunks);
			return -ENOMEM;
		}

		if (copy_from_user(block_nums, karg.block_nums,
						   sizeof(uint32_t) * karg.nchunks))
		{
			kfree(dchunks);
			kfree(block_nums);
			return -EFAULT;
		}
	}

	/* construct strom_dma_task and strom_dma_state */
	retval = strom_create_dma_task(&dstate,
								   karg.handle,
								   karg.fdesc,
								   ioctl_filp);
	if (retval < 0)
	{
		kfree(dchunks);
		return retval;
	}
	mgmem = dstate.dtask->mgmem;
	dma_task_id = dstate.dtask->dma_task_id;

	/* sanity checks */
	if (karg.unitsz > STROM_DMA_SSD2GPU_MAXLEN)
	{
		prError("chunk size (%zu) is too large (max: %zu)",
				karg.unitsz, (size_t)STROM_DMA_SSD2GPU_MAXLEN);
		retval = -EINVAL;
		goto out;
	}

	if ((karg.unitsz & (dstate.blocksz - 1)) != 0UL)
	{
		prError("chunk size (%zu) is not aligned to %zu",
				karg.unitsz, dstate.blocksz);
		retval = -EINVAL;
		goto out;
	}

	if (((mgmem->map_offset + karg.offset) & 15) != 0UL)
	{
		prError("destination address is not aligned to 128bit");
		retval = -EINVAL;
		goto out;
	}

	if (mgmem->map_offset + karg.offset +
		karg.unitsz * karg.nchunks > mgmem->map_length)
	{
		prError("destination address is out of range");
		retval = -ERANGE;
		goto out;
	}

	/* then, submit asynchronous DMA requests */
	filp = dstate.dtask->filp;
	i_size = i_size_read(filp->f_inode);
	karg.dma_task_id = dma_task_id;
	karg.nr_ram2gpu = 0;
	karg.nr_ssd2gpu = 0;
	dest_offset = mgmem->map_offset + karg.offset;
	for (i=0; i < karg.nchunks; i++)
	{
		loff_t		fpos = dchunks[i];
		loff_t		fend = fpos + karg.unitsz;
		uint32_t	block_nr = (block_nums ? block_nums[i] : 0x7e7e7e7e);
		uint		nr_cached = 0;
		uint		nr_pages = 0;
		bool		has_dirty_pages = false;

		/* sanity check - alignment of fpos */
		if ((fpos & (dstate.blocksz - 1)) != 0UL)
		{
			prError("Head of chunk[%d] (%zu) is not aligned to %zu",
					i, (size_t)fpos, dstate.blocksz);
			retval = -EINVAL;
			goto out;
		}
		/* sanity check - range must be file range */
		if (fpos + karg.unitsz > i_size)
		{
			prError("source address is out of range");
			retval = -ERANGE;
			goto out;
		}

		while (fpos < fend)
		{
			size_t	page_ofs = (fpos & (PAGE_CACHE_SIZE - 1));
			size_t	page_len;

			if (fend - fpos <= PAGE_CACHE_SIZE)
				page_len = fend - fpos;
			else
				page_len = PAGE_CACHE_SIZE - page_ofs;

			fpage = find_lock_page(filp->f_mapping, fpos >> PAGE_CACHE_SHIFT);
			dstate.file_pages[nr_pages++] = fpage;
			if (fpage)
			{
				/*
				 * NOTE: We cannot use SSD-to-GPU Direct DMA for dirty pages.
				 * So, we have to choose either memcpy_toio() or write-back to
				 * user buffer then RAM-to-GPU DMA by CUDA. Heuristically, the
				 * later is better approach, so we bias to the write-back if
				 * page is dirty.
				 */
				if (!PageDirty(fpage))
					nr_cached++;
				else
				{
					has_dirty_pages = true;
					nr_cached += 3;
				}
			}
			fpos += page_len;
			Assert(fpos <= fend);
		}

		/*
		 * If cached pages are majority in this chunk, we write back the pages
		 * to user buffers for the later RAM-to-GPU DMA by CUDA API.
		 * Elsewhere, we submit SSD-to-GPU Direct DMA by itself.
		 */
		if (nr_cached > nr_pages / 2)
		{
			char __user *uaddr = (char __user *)karg.block_data +
				(karg.nchunks - karg.nr_ram2gpu - 1) * karg.unitsz;
			retval = do_writeback_to_user_buffer(&dstate,
												 nr_pages,
												 dchunks[i],
												 karg.unitsz,
												 uaddr);
			if (retval)
				goto out;

			karg.nr_ram2gpu++;
			if (block_nums)
				block_nums[karg.nchunks - karg.nr_ram2gpu] = block_nr;
		}
		else
		{
			retval = exec_ssd2gpu_memcpy_async(&dstate,
											   nr_pages,
											   dchunks[i],
											   karg.unitsz,
											   dest_offset);
			if (retval)
				goto out;

			if (block_nums)
				block_nums[karg.nr_ssd2gpu] = block_nr;
			karg.nr_ssd2gpu++;
			dest_offset += karg.unitsz;
		}
	}
	Assert(karg.nr_ram2gpu + karg.nr_ssd2gpu == karg.nchunks);

out:
	/* release resources no longer referenced */
	strom_put_dma_task(dstate.dtask, 0);
	Assert(!dstate.dest_iomap);

	if (retval == 0 &&
		copy_to_user(uarg, &karg,
					 offsetof(StromCmd__MemCpySsdToGpuWriteBack, handle)))
		retval = -EFAULT;
	if (retval)
	{
		/* synchronization, if any error */
		while (strom_memcpy_ssd2gpu_wait(1, 1, &dma_task_id,
										 NULL, NULL) == -EINTR);
	}
	kfree(block_nums);
	kfree(dchunks);
	return retval;
}

/*
 * ioctl(2) handler for STROM_IOCTL__MEMCPY_SSD2GPU_WAIT
 */
static int
ioctl_memcpy_ssd2gpu_wait(StromCmd__MemCpySsdToGpuWait __user *uarg,
						  struct file *ioctl_filp)
{
	StromCmd__MemCpySsdToGpuWait	__karg;
	StromCmd__MemCpySsdToGpuWait   *karg;
	unsigned long	failed_dma_task_id = 0;
	long			failed_dma_status;
	long			retval;

	if (copy_from_user(&__karg, uarg,
					   offsetof(StromCmd__MemCpySsdToGpuWait, dma_task_id)))
		return -EFAULT;

	if (__karg.ntasks == 0 || __karg.ntasks < __karg.nwaits)
		return -EINVAL;
	else if (__karg.ntasks == 1)
	{
		if (get_user(__karg.dma_task_id[0], &uarg->dma_task_id[0]))
			return -EFAULT;
		karg = &__karg;
	}
	else
	{
		karg = kmalloc(offsetof(StromCmd__MemCpySsdToGpuWait,
								dma_task_id[__karg.ntasks]),
					   GFP_KERNEL);
		if (!karg)
			return -ENOMEM;
		karg->ntasks = __karg.ntasks;
		karg->nwaits = __karg.nwaits;
		if (copy_from_user(karg->dma_task_id,
						   uarg->dma_task_id,
						   sizeof(unsigned long) * __karg.ntasks))
		{
			kfree(karg);
			return -EFAULT;
		}
	}

	retval = strom_memcpy_ssd2gpu_wait(karg->ntasks,
									   karg->nwaits,
									   karg->dma_task_id,
									   &failed_dma_task_id,
									   &failed_dma_status);
	if (retval >= 0)
	{
		karg->nwaits = retval;
		karg->status = 0;
		if (retval > 0 &&
			copy_to_user(uarg, karg,
						 offsetof(StromCmd__MemCpySsdToGpuWait,
								  dma_task_id[karg->nwaits])))
			retval = -EFAULT;
		retval = 0;
	}
	else
	{
		if (!failed_dma_task_id)
		{
			karg->nwaits = 0;
			karg->status = 0;
		}
		else
		{
			karg->nwaits = 1;
			karg->status = failed_dma_status;
			karg->dma_task_id[0] = failed_dma_task_id;
		}
		if (copy_to_user(uarg, karg,
						 offsetof(StromCmd__MemCpySsdToGpuWait,
                                  dma_task_id[karg->nwaits])))
			retval = -EFAULT;
	}

	if (karg != &__karg)
		kfree(karg);
	return retval;
}

/* ================================================================
 *
 * file_operations of '/proc/nvme-strom' entry
 *
 * ================================================================
 */
static const char  *strom_proc_signature =		\
	"nvme_strom version " NVME_STROM_VERSION	\
	" built for linux kernel " UTS_RELEASE;

static int
strom_proc_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static ssize_t
strom_proc_read(struct file *filp, char __user *buf, size_t len, loff_t *pos)
{
	size_t		sig_len = strlen(strom_proc_signature);

	if (*pos >= sig_len)
		return 0;
	if (*pos + len >= sig_len)
		len = sig_len - *pos;
	if (copy_to_user(buf, strom_proc_signature + *pos, len))
		return -EFAULT;
	*pos += len;

	return len;
}

static int
strom_proc_release(struct inode *inode, struct file *filp)
{
	int			i;

	for (i=0; i < STROM_DMA_TASK_NSLOTS; i++)
	{
		spinlock_t		   *lock = &strom_dma_task_locks[i];
		struct list_head   *slot = &failed_dma_task_slots[i];
		unsigned long		flags;
		strom_dma_task	   *dtask;
		strom_dma_task	   *dnext;

		spin_lock_irqsave(lock, flags);
		list_for_each_entry_safe(dtask, dnext, slot, chain)
		{
			if (dtask->ioctl_filp == filp)
			{
				prNotice("Unreferenced asynchronous SSD2GPU DMA error "
						 "(dma_task_id: %lu, status=%ld)",
						 dtask->dma_task_id, dtask->dma_status);
				list_del(&dtask->chain);
				kfree(dtask);
			}
		}
		spin_unlock_irqrestore(lock, flags);
	}
	return 0;
}

static long
strom_proc_ioctl(struct file *ioctl_filp,
				 unsigned int cmd,
				 unsigned long arg)
{
	long		retval;

	switch (cmd)
	{
		case STROM_IOCTL__CHECK_FILE:
			retval = ioctl_check_file((void __user *) arg);
			break;

		case STROM_IOCTL__MAP_GPU_MEMORY:
			retval = ioctl_map_gpu_memory((void __user *) arg);
			break;

		case STROM_IOCTL__UNMAP_GPU_MEMORY:
			retval = ioctl_unmap_gpu_memory((void __user *) arg);
			break;

		case STROM_IOCTL__LIST_GPU_MEMORY:
			retval = ioctl_list_gpu_memory((void __user *) arg);
			break;

		case STROM_IOCTL__INFO_GPU_MEMORY:
			retval = ioctl_info_gpu_memory((void __user *) arg);
			break;

		case STROM_IOCTL__MEMCPY_SSD2GPU:
			retval = ioctl_memcpy_ssd2gpu_async((void __user *) arg,
												ioctl_filp,
												true);
			break;

		case STROM_IOCTL__MEMCPY_SSD2GPU_ASYNC:
			retval = ioctl_memcpy_ssd2gpu_async((void __user *) arg,
												ioctl_filp,
												false);
			break;

		case STROM_IOCTL__MEMCPY_SSD2GPU_WAIT:
			retval = ioctl_memcpy_ssd2gpu_wait((void __user *) arg,
											   ioctl_filp);
			break;

		case STROM_IOCTL__MEMCPY_SSD2GPU_WRITEBACK:
			retval = ioctl_memcpy_ssd2gpu_writeback((void __user *) arg,
													ioctl_filp);
			break;

		default:
			retval = -EINVAL;
			break;
	}
	return retval;
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
	int			i, rc;

	/* init strom_mgmem_mutex/slots */
	for (i=0; i < MAPPED_GPU_MEMORY_NSLOTS; i++)
	{
		spin_lock_init(&strom_mgmem_locks[i]);
		INIT_LIST_HEAD(&strom_mgmem_slots[i]);
	}

	/* init strom_dma_task_locks/slots */
	for (i=0; i < STROM_DMA_TASK_NSLOTS; i++)
	{
		spin_lock_init(&strom_dma_task_locks[i]);
		INIT_LIST_HEAD(&strom_dma_task_slots[i]);
		INIT_LIST_HEAD(&failed_dma_task_slots[i]);
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
