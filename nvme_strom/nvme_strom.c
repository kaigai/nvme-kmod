/*
 * NVMe-Strom
 *
 * A Linux kernel driver to support SSD-to-GPU P2P DMA.
 *
 * Copyright (C) 2016 KaiGai Kohei <kaigai@kaigai.gr.jp>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
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

/* determine the target kernel to build */
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
module_param(verbose, int, 0644);
MODULE_PARM_DESC(verbose, "turn on/off debug message");

#define prDebug(fmt, ...)												\
	do {																\
		if (verbose > 1)												\
			printk(KERN_ALERT "nvme-strom(%s:%d): " fmt "\n",			\
				   __FUNCTION__, __LINE__, ##__VA_ARGS__);				\
		else if (verbose)												\
			printk(KERN_ALERT "nvme-strom: " fmt "\n", ##__VA_ARGS__);	\
	} while(0)
#define prInfo(fmt, ...)						\
	printk(KERN_INFO "nvme-strom: " fmt "\n", ##__VA_ARGS__)
#define prNotice(fmt, ...)						\
	printk(KERN_NOTICE "nvme-strom: " fmt "\n", ##__VA_ARGS__)
#define prWarn(fmt, ...)						\
	printk(KERN_WARNING "nvme-strom: " fmt "\n", ##__VA_ARGS__)
#define prError(fmt, ...)						\
	printk(KERN_ERR "nvme-strom: " fmt "\n", ##__VA_ARGS__)

/* routines for extra symbols */
#define EXTRA_KSYMS_NEEDS_NVIDIA	1
#include "../common/extra_ksyms.c"
#include "../common/nvme_misc.c"

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
		if (mgmem->wait_task)
			wake_up_process(mgmem->wait_task);
		mgmem->wait_task = NULL;
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
		 * NOTE: I'm not 100% certain whether UID is the right check to
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
 * strom_get_block - a generic version of get_block_t for the supported
 * filesystems. It assumes the target filesystem is already checked by
 * file_is_supported_nvme, so we have minimum checks here.
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
	int				rc;

	if (copy_from_user(&karg, uarg, sizeof(karg)))
		return -EFAULT;

	filp = fget(karg.fdesc);
	if (!filp)
		return -EBADF;

	rc = file_is_supported_nvme(filp, false, NULL);

	fput(filp);

	return (rc < 0 ? rc : 0);
}

/* ================================================================
 *
 * Main part for SSD-to-GPU P2P DMA
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

/*
 * Number of pages to be enqueued to a workqueue for asynchronous RAM2GPU
 * memcpy. Too small request will increase the task switch overhead.
 */
#define STROM_RAM2GPU_MAXPAGES		(2048 * 1024 / PAGE_SIZE)	/* 2MB */

struct strom_dma_task
{
	struct list_head	chain;
	unsigned long		dma_task_id;/* ID of this DMA task */
	int					hindex;		/* index of hash slot */
	int					refcnt;		/* reference counter */
	mapped_gpu_memory  *mgmem;		/* destination GPU memory segment */
	/* reference to the backing file */
	struct file		   *filp;		/* source file */
	struct nvme_ns	   *nvme_ns;	/* NVMe namespace (=SCSI LUN) */
	size_t				blocksz;	/* blocksize of this partition */
	int					blocksz_shift;	/* log2 of 'blocksz' */
	sector_t			start_sect;	/* first sector of the source partition */
	sector_t			nr_sects;	/* number of sectors of the partition */

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

	/* current destination offset of GPU memory */
	size_t				dest_offset;	// deprecated?

	char			   *dest_iomap;	/* current ioremap_wc() window */
	unsigned int		dest_index;	/* index of the GPU memory page */

	/* contiguous SSD blocks */
	sector_t			src_block;	/* head of the source blocks */
	unsigned int		nr_blocks;	/* # of the contigunous source blocks */
	unsigned int		max_nblocks;/* upper limit of @nr_blocks */
	/* contiguous Page caches */
	size_t				page_ofs;	/* offset from the first page */
	size_t				copy_len;	/* "total" length to copy */
	unsigned int		nr_fpages;	/* number of the pending pages */
	struct page		   *file_pages[STROM_RAM2GPU_MAXPAGES];
};
typedef struct strom_dma_task	strom_dma_task;

/*
 * strom_memcpy_task - request of RAM2GPU asynchronous memcpy
 */
struct strom_memcpy_task
{
	struct work_struct work;
	strom_dma_task *dtask;
	size_t			offset;		/* destination offset of the request */
	size_t			copy_len;	/* total length to copy */
	size_t			page_ofs;	/* offset of the first page */
	unsigned int	nr_fpages;	/* number of pending pages */
	struct page	   *file_pages[1];	/* variable length */
};
typedef struct strom_memcpy_task	strom_memcpy_task;

#define STROM_DMA_TASK_NSLOTS		240
static spinlock_t		strom_dma_task_locks[STROM_DMA_TASK_NSLOTS];
static struct list_head	strom_dma_task_slots[STROM_DMA_TASK_NSLOTS];
static struct list_head	failed_dma_task_slots[STROM_DMA_TASK_NSLOTS];
static wait_queue_head_t strom_dma_task_waitq[STROM_DMA_TASK_NSLOTS];

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
static strom_dma_task *
strom_create_dma_task(unsigned long handle,
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
		retval = -EBADF;
		goto error_0;
	}
	retval = file_is_supported_nvme(filp, false, &nvme_ns);
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
    dtask->mgmem		= mgmem;
    dtask->filp			= filp;
	dtask->nvme_ns		= nvme_ns;
	dtask->blocksz		= i_sb->s_blocksize;
	dtask->blocksz_shift = i_sb->s_blocksize_bits;
	Assert(dtask->blocksz == (1UL << dtask->blocksz_shift));
	dtask->start_sect	= s_bdev->bd_part->start_sect;
	dtask->nr_sects		= s_bdev->bd_part->nr_sects;
    dtask->dma_status	= 0;
    dtask->ioctl_filp	= get_file(ioctl_filp);

	dtask->dest_offset	= 0;
	dtask->src_block	= 0;
	dtask->nr_blocks	= 0;
	dtask->max_nblocks = STROM_DMA_SSD2GPU_MAXLEN >> dtask->blocksz_shift;
	dtask->page_ofs		= 0;
	dtask->copy_len		= 0;
	dtask->nr_fpages	= 0;

    /* OK, this strom_dma_task is now tracked */
	spin_lock_irqsave(&strom_dma_task_locks[dtask->hindex], flags);
	list_add_rcu(&dtask->chain, &strom_dma_task_slots[dtask->hindex]);
    spin_unlock_irqrestore(&strom_dma_task_locks[dtask->hindex], flags);

	return dtask;

error_2:
	strom_put_mapped_gpu_memory(mgmem);
error_1:
	fput(filp);
error_0:
	return ERR_PTR(retval);
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
		mapped_gpu_memory *mgmem = dtask->mgmem;
		struct file	   *ioctl_filp = dtask->ioctl_filp;
		struct file	   *data_filp = dtask->filp;
		long			status = dtask->dma_status;

		/* detach from the global hash table */
		list_del_rcu(&dtask->chain);
		/* if any error status, move to the ioctl_filp without kfree() */
		if (status)
		{
			slot = &failed_dma_task_slots[index];
			list_add_tail(slot, &dtask->chain);
		}
		/* wake up all the waiting tasks, if any */
		wake_up_all(&strom_dma_task_waitq[index]);
		spin_unlock_irqrestore(lock, flags);
		/* release relevant resources */
		if (!status)
			kfree(dtask);
		strom_put_mapped_gpu_memory(mgmem);
		fput(data_filp);
		fput(ioctl_filp);

		prDebug("DMA task (id=%p) was completed", dtask);

		return;
	}
	spin_unlock_irqrestore(lock, flags);
}

/*
 * submit_ram2gpu_memcpy - asynchronous RAM2GPU copy by CPU workqueue
 */
static void
callback_ram2gpu_memcpy(struct work_struct *work)
{
	strom_memcpy_task  *mc_task = (strom_memcpy_task *) work;
	strom_dma_task	   *dtask = mc_task->dtask;
	mapped_gpu_memory  *mgmem = dtask->mgmem;
	nvidia_p2p_page_table_t *page_table = mgmem->page_table;
	size_t		dest_offset = mc_task->offset;
	char	   *dest_iomap = NULL;
	int			dest_index = -1;
	size_t		cur = mc_task->page_ofs;
	size_t		end = mc_task->page_ofs + mc_task->copy_len;
	int			i, j;
	long		status = 0;

	Assert((mc_task->page_ofs +
			mc_task->copy_len +
			PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT == mc_task->nr_fpages);

	while (cur < end)
	{
		struct page	   *fpage = mc_task->file_pages[cur >> PAGE_CACHE_SHIFT];
		size_t			page_ofs = (cur & (PAGE_CACHE_SIZE - 1));
		size_t			page_len;
		uint64_t		phy_addr;
		char		   *saddr;
		char		   *daddr;

		/* length to copy from this page */
		page_len = Min(PAGE_CACHE_SIZE, end - (cur & PAGE_MASK)) - page_ofs;

		/* map destination GPU page using write-combined mode */
		j = dest_offset >> mgmem->gpu_page_shift;
		if (!dest_iomap || j != dest_index)
		{
			if (dest_iomap)
				iounmap(dest_iomap);
			phy_addr = page_table->pages[j]->physical_address;
			dest_iomap = ioremap_wc(phy_addr, mgmem->gpu_page_sz);
			if (!dest_iomap)
			{
				status = -ENOMEM;
				break;
			}
			dest_index = j;
		}
		/* choose shorter page_len if it comes across GPU page boundary */
		if (j != ((dest_offset + page_len) >> mgmem->gpu_page_shift))
		{
			page_len = (mgmem->gpu_page_sz -
						(dest_offset & (mgmem->gpu_page_sz - 1)));
		}
		/* do copy by CPU */
		daddr = dest_iomap + (dest_offset & (mgmem->gpu_page_sz - 1));
		saddr = kmap_atomic(fpage);

		memcpy_toio(daddr, saddr + page_ofs, page_len);
		kunmap_atomic(saddr);

		cur += page_len;
		dest_offset += page_len;
	}
	Assert(cur == end || status != 0);
	/* release resources */
	for (i=0; i < mc_task->nr_fpages; i++)
	{
		unlock_page(mc_task->file_pages[i]);
		page_cache_release(mc_task->file_pages[i]);
	}
	if (dest_iomap)
		iounmap(dest_iomap);

	strom_put_dma_task(dtask, status);
	kfree(mc_task);
}

static int
submit_ram2gpu_memcpy(strom_dma_task *dtask)
{
	strom_memcpy_task  *mc_task;
	int		i;

	mc_task = kmalloc(offsetof(strom_memcpy_task,
							   file_pages[dtask->nr_fpages]),
					  GFP_KERNEL);
	if (!mc_task)
	{
		for (i=0; i < dtask->nr_fpages; i++)
		{
			struct page	   *fpage = dtask->file_pages[i];

			unlock_page(fpage);
			page_cache_release(fpage);
		}
		return -ENOMEM;
	}

	INIT_WORK(&mc_task->work, callback_ram2gpu_memcpy);
	mc_task->dtask		= strom_get_dma_task(dtask);
	mc_task->offset		= dtask->dest_offset;
	mc_task->copy_len	= dtask->copy_len;
	mc_task->page_ofs	= dtask->page_ofs;
	mc_task->nr_fpages	= dtask->nr_fpages;
	memcpy(mc_task->file_pages, dtask->file_pages,
		   sizeof(struct page *) * dtask->nr_fpages);
	schedule_work(&mc_task->work);

	dtask->nr_fpages	= 0;	/* reset */

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
submit_ssd2gpu_memcpy(strom_dma_task *dtask)
{
	mapped_gpu_memory  *mgmem = dtask->mgmem;
	nvidia_p2p_page_table_t *page_table = mgmem->page_table;
	struct nvme_ns	   *nvme_ns = dtask->nvme_ns;
	struct nvme_dev	   *nvme_dev = nvme_ns->dev;
	struct nvme_iod	   *iod;
	size_t				offset;
	size_t				total_nbytes;
	dma_addr_t			base_addr;
	int					length;
	int					i, base;
	int					retval;

	total_nbytes = (dtask->nr_blocks << dtask->blocksz_shift);
	if (!total_nbytes || total_nbytes > STROM_DMA_SSD2GPU_MAXLEN)
		return -EINVAL;
	if (dtask->dest_offset < mgmem->map_offset ||
		dtask->dest_offset + total_nbytes > (mgmem->map_offset +
											 mgmem->map_length))
		return -ERANGE;

	iod = nvme_alloc_iod(total_nbytes,
						 mgmem,
						 nvme_dev,
						 GFP_KERNEL);
	if (!iod)
		return -ENOMEM;

	base = (dtask->dest_offset >> mgmem->gpu_page_shift);
	offset = (dtask->dest_offset & (mgmem->gpu_page_sz - 1));
	prDebug("base=%d offset=%zu dest_offset=%zu total_nbytes=%zu",
			base, offset, dtask->dest_offset, total_nbytes);

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

	retval = nvme_submit_async_read_cmd(dtask, iod);
	if (retval)
		__nvme_free_iod(nvme_dev, iod);

	/* clear the state */
	dtask->nr_blocks = 0;
	dtask->src_block = 0;
	dtask->dest_offset = ~0UL;

	return retval;
}

/*
 * strom_memcpy_ssd2gpu_wait - synchronization of a dma_task
 */
static int
strom_memcpy_ssd2gpu_wait(unsigned long dma_task_id,
						  long *p_dma_task_status,
						  int task_state)
{
	int					hindex = strom_dma_task_index(dma_task_id);
	spinlock_t		   *lock = &strom_dma_task_locks[hindex];
	unsigned long		flags;
	strom_dma_task	   *dtask;
	struct list_head   *slot;
	wait_queue_head_t  *waitq = &strom_dma_task_waitq[hindex];
	int					retval = 0;

	DEFINE_WAIT(__wait);
	for (;;)
	{
		bool	has_spinlock = false;
		bool	task_is_running = false;

		prepare_to_wait(waitq, &__wait, task_state);

		rcu_read_lock();
	retry:
		/* check error status first */
		slot = &failed_dma_task_slots[hindex];
		list_for_each_entry_rcu(dtask, slot, chain)
		{
			if (dtask->dma_task_id == dma_task_id)
			{
				if (!has_spinlock)
				{
					rcu_read_unlock();
					has_spinlock = true;
					spin_lock_irqsave(lock, flags);
					goto retry;
				}
				if (p_dma_task_status)
					*p_dma_task_status = dtask->dma_status;
				list_del(&dtask->chain);
				kfree(dtask);

				goto out;
			}
		}

		/* check whether it is a running task or not */
		slot = &strom_dma_task_slots[hindex];
		list_for_each_entry_rcu(dtask, slot, chain)
		{
			if (dtask->dma_task_id == dma_task_id)
			{
				task_is_running = true;
				break;
			}
		}
		if (has_spinlock)
			spin_unlock_irqrestore(lock, flags);
		else
			rcu_read_unlock();

		if (!task_is_running)
			break;
		if (signal_pending(current))
		{
			retval = -EINTR;
			break;
		}
		schedule();
	}
out:
	finish_wait(waitq, &__wait);

	return retval;
}

/*
 * do_ssd2gpu_async_memcpy - kicker of asyncronous DMA requests
 */
static long
do_ssd2gpu_async_memcpy(strom_dma_task *dtask,
						int nchunks, strom_dma_chunk *dchunks)
{
	mapped_gpu_memory  *mgmem = dtask->mgmem;
	struct file		   *filp = dtask->filp;
	struct page		   *fpage;
	long				retval;
	size_t				i_size;
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
		if (dtask->nr_blocks > 0 &&
			curr_offset != (dtask->dest_offset +
							dtask->nr_blocks * dtask->blocksz))
		{
			retval = submit_ssd2gpu_memcpy(dtask);
			if (retval)
			{
				prDebug("submit_ssd2gpu_memcpy() = %ld", retval);
				return retval;
			}
			Assert(dtask->nr_blocks == 0);
		}

		/*
		 * alignment checks
		 */
		if ((curr_offset & (sizeof(int) - 1)) != 0 ||
			(pos & (dtask->blocksz - 1)) != 0 ||
			(end & (dtask->blocksz - 1)) != 0)
		{
			prError("alignment violation pos=%zu end=%zu --> dest=%zu",
					(size_t)pos, (size_t)end, (size_t)curr_offset);
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

			Assert((page_ofs & (dtask->blocksz - 1)) == 0 &&
				   (page_len & (dtask->blocksz - 1)) == 0);

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
			if (fpage)
			{
				/* Submit SSD2GPU DMA, if any pending request */
				if (dtask->nr_blocks > 0)
				{
					retval = submit_ssd2gpu_memcpy(dtask);
					if (retval)
					{
						prDebug("submit_ssd2gpu_memcpy() = %ld", retval);
						return retval;
					}
					Assert(dtask->nr_blocks == 0);
				}

				/* merge pending memcpy if possible */
				if (dtask->nr_fpages > 0 &&
					dtask->nr_fpages < STROM_RAM2GPU_MAXPAGES &&
					page_ofs == 0 &&
					((dtask->page_ofs +
					  dtask->copy_len) & (PAGE_CACHE_SIZE - 1)) == 0 &&
					dtask->dest_offset + dtask->copy_len == curr_offset)
				{
					dtask->file_pages[dtask->nr_fpages] = fpage;
					dtask->copy_len += page_len;
					dtask->nr_fpages++;
				}
				else
				{
					/* submit if any pending request */
					if (dtask->nr_fpages > 0)
					{
						retval = submit_ram2gpu_memcpy(dtask);
						if (retval)
						{
							prDebug("submit_ssd2gpu_memcpy() = %ld", retval);
							return retval;
						}
						Assert(dtask->nr_fpages == 0);
					}
					/* This page becomes the first pending page */
					dtask->page_ofs		= page_ofs;
					dtask->copy_len		= page_len;
					dtask->file_pages[0]	= fpage;
					dtask->nr_fpages		= 1;
					dtask->dest_offset		= curr_offset;
				}
			}
			else
			{
				struct buffer_head	bh;
				sector_t			lba_curr;
				unsigned int		nr_blocks;

				/* Submit RAM2GPU Async Memcpy if any */
				if (dtask->nr_fpages > 0)
				{
					retval = submit_ram2gpu_memcpy(dtask);
					if (retval)
					{
						prDebug("submit_ram2gpu_memcpy() = %ld", retval);
						return retval;
					}
					Assert(dtask->nr_fpages == 0);
				}

				/* Lookup underlying block number */
				memset(&bh, 0, sizeof(bh));
				bh.b_size = dtask->blocksz;

				retval = strom_get_block(filp->f_inode,
										 pos >> dtask->blocksz_shift,
										 &bh, 0);
				if (retval)
				{
					prDebug("strom_get_block() = %ld", retval);
					return retval;
				}
				lba_curr = bh.b_blocknr + (page_ofs >> dtask->blocksz_shift);
				nr_blocks = (page_len >> dtask->blocksz_shift);
				/* Is it merginable with the pending request? */
				if (dtask->nr_blocks > 0 &&
					dtask->nr_blocks + nr_blocks <= dtask->max_nblocks &&
					dtask->src_block + dtask->nr_blocks == lba_curr)
				{
					dtask->nr_blocks += nr_blocks;
				}
				else
				{
					/* Submit the latest pending blocks but not merginable */
					if (dtask->nr_blocks > 0)
					{
						retval = submit_ssd2gpu_memcpy(dtask);
						if (retval)
						{
							prDebug("submit_ssd2gpu_memcpy() = %ld", retval);
							return retval;
						}
						Assert(dtask->nr_blocks == 0);
					}
					/* This block becomes new head of the pending request */
					dtask->src_block = lba_curr;
					dtask->nr_blocks = nr_blocks;
					dtask->dest_offset = curr_offset;
				}
			}
			curr_offset += page_len;
			pos += page_len;
		}
	}
	/* Submit pending SSD2GPU request, if any */
	if (dtask->nr_blocks > 0)
	{
		Assert(dtask->nr_fpages == 0);
		retval = submit_ssd2gpu_memcpy(dtask);
		if (retval)
			prDebug("submit_ssd2gpu_memcpy() = %ld", retval);
	}
	else if (dtask->nr_fpages > 0)
	{
		Assert(dtask->nr_blocks == 0);
		retval = submit_ram2gpu_memcpy(dtask);
		if (retval)
			prDebug("submit_ram2gpu_memcpy() = %ld", retval);
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
	strom_dma_task	   *dtask;
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

	/* construct dma_task and dma_state */
	dtask = strom_create_dma_task(karg.handle,
								  karg.fdesc,
								  ioctl_filp);
	if (IS_ERR(dtask))
		return PTR_ERR(dtask);
	dma_task_id = dtask->dma_task_id;

	/* then, submit asynchronous DMA requests */
	retval = do_ssd2gpu_async_memcpy(dtask, karg.nchunks, dchunks);

	/* release resources no longer referenced */
	strom_put_dma_task(dtask, retval);

	/* inform the dma_task_id to userspace */
	if (retval == 0 && put_user(dma_task_id, &uarg->dma_task_id))
		retval = -EFAULT;
	/* synchronization if necessary */
	if (retval || do_sync)
		strom_memcpy_ssd2gpu_wait(dma_task_id, NULL, TASK_UNINTERRUPTIBLE);

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
	StromCmd__MemCpySsdToGpuWait karg;
	long		retval;

	if (copy_from_user(&karg, uarg, sizeof(StromCmd__MemCpySsdToGpuWait)))
		return -EFAULT;

	karg.status = 0;
	retval = strom_memcpy_ssd2gpu_wait(karg.dma_task_id,
									   &karg.status,
									   TASK_INTERRUPTIBLE);
	if (copy_to_user(uarg, &karg, sizeof(StromCmd__MemCpySsdToGpuWait)))
		return -EFAULT;

	return retval;
}

/*
 * write back a chunk to user buffer
 */
static int
__memcpy_ssd2gpu_writeback(strom_dma_task *dtask,
						   int nr_pages,
						   loff_t fpos,
						   char __user *dest_uaddr)
{
	struct page	   *fpage;
	char		   *kaddr;
	loff_t			left;
	int				i, retval = 0;

	for (i=0; i < n_pages; i++)
	{
		fpage = dtask->file_pages[i];

		/* Synchronous read, if not cached */
		if (!fpage)
		{
			fpage = read_mapping_page(filp->f_mapping,
									  (fpos >> PAGE_CACHE_SHIFT) + i,
									  NULL);
			if (IS_ERR(fpage))
			{
				retval = PTR_ERR(fpage);
				break;
			}
			lock_page(fpage);
		}
		Assert(fpage != NULL);

		/* write-back the pages to userspace, like file_read_actor() */
		if (unlikely(fault_in_pages_writeable(dest_uaddr, PAGE_CACHE_SIZE)))
			left = 1;	/* go to slow way */
		else
		{
			kaddr = kmap_atomic(fpage);
			left = __copy_to_user_inatomic(dest_uaddr, kaddr,
										   PAGE_CACHE_SIZE);
			kunmap_atomic(kaddr);
		}

		/* Do it by the slow way, if needed */
		if (left)
		{
			kaddr = kmap(fpage);
			left = __copy_to_user(user_addr, kaddr,
								  PAGE_CACHE_SIZE);
			kunmap(kaddr);
		}
		unlock_page(fpage);
		page_cache_release(fpage);

		/* Error? */
		if (left)
		{
			retval = -EFAULT;
			break;
		}
		dest_uaddr += PAGE_CACHE_SIZE;
	}

	/* Error? */
	while (unlikely(i < n_pages))
	{
		fpage = dtask->file_pages[i++];
		if (fpage)
		{
			unlock_page(fpage);
			page_cache_release(fpage);
		}
	}
	return retval;
}

/*
 * Submit a P2P DMA request
 */
static int
__memcpy_ssd2gpu_submit_dma(strom_dma_task *dtask,
							int nr_pages,
							loff_t fpos,
							loff_t dest_offset)
{
	mapped_gpu_memory  *mgmem = dtask->mgmem;
	struct page		   *fpage;
	struct buffer_head	bh;
	unsigned int		nr_blocks;
	uint64_t			phy_addr;
	int					i, j, retval = 0;

	Assert(dtask->nr_blocks == 0);
	for (i=0; i < n_pages; i++)
	{
		fpage = dtask->file_pages[i];
		if (fpage && PageDirty(fpage))
		{
			size_t		page_len = PAGE_CACHE_SIZE;
			size_t		page_ofs = 0;
			size_t		copy_len;
			char	   *saddr;
			char	   *daddr;

			/* submit SSD2GPU DMA */
			if (dtask->nr_blocks > 0)
				/* submit it */;

			/* dirty page must be copied by CPU, synchronously */
			while (page_len > 0)
			{
				j = dest_offset >> mgmem->gpu_page_shift;
				if (!dtask->dest_iomap || j != dtask->dest_index)
				{
					if (dtask->dest_iomap)
						iounmap(dtask->dest_iomap);
					phy_addr = page_table->pages[j]->physical_address;
					dtask->dest_iomap = ioremap_wc(phy_addr,
												   mgmem->gpu_page_sz);
					if (!dtask->dest_iomap)
					{
						retval = -ENOMEM;
						goto out;
					}
					dtask->dest_index = j;
				}
				copy_len = page_len;
				if (j != ((dest_offset + copy_len) >> mgmem->gpu_page_shift))
					copy_len = (mgmem->gpu_page_sz -
								(dest_offset & (mgmem->gpu_page_sz - 1)));
				Assert(copy_len <= page_len);
				/* Sync copy by CPU */
				daddr = (dtask->dest_iomap +
						 (dest_offset & (mgmem->gpu_page_sz - 1)));
				saddr = kmap_atomic(fpage);
				memcpy_toio(daddr, saddr + page_ofs, copy_len);
				kunmap_atomic(saddr);

				dest_offset += copy_len;
				page_ofs += copy_len;
				page_len -= copy_len;
			}
		}
		else
		{
			// SSD to GPU DMA
			memset(&bh, 0, sizeof(bh));
			bh.b_size = dtask->blocksz;

			retval = strom_get_block(filp->f_inode,
									 fpos >> dtask->blocksz_shift,
									 &bh, 0);
			if (retval)
			{
				prError("strom_get_block: %lu", retval);
				goto out;
			}
			nr_blocks = PAGE_CACHE_SIZE >> dtask->blocksz_shift;

			/* merge with pending request if possible */
			if (dtask->nr_blocks > 0 &&
				dtask->nr_blocks + nr_blocks <= dtask->max_nblocks &&
				dtask->src_block + dtask->nr_blocks == bh.b_blocknr)
			{
				dtask->nr_blocks += nr_blocks;
			}
			else
			{
				/* submit SSD2GPU DMA */
				if (dtask->nr_blocks > 0)
					/* submit it */;
				dtask->src_block = bh.b_blocknr;
				dtask->nr_blocks = nr_blocks;
			}
		}
	}
	/* submit pending request */
	if (dtask->nr_blocks > 0)
		/* submit it */;
	Assert(dtask->nr_blocks == 0);
out:
	/* Error? */
	while (unlikely(i < n_pages))
	{
		fpage = dtask->file_pages[i++];
		if (fpage)
		{
			unlock_page(fpage);
			page_cache_release(fpage);
		}
	}
	return retval;
}

/*
 * main logic of STROM_IOCTL__MEMCPY_SSD2GPU_WRITEBACK
 */
static int
memcpy_ssd2gpu_writeback(strom_dma_task *dtask,
						 size_t buffer_offset,
						 size_t chunk_size,
						 int nchunks,
						 loff_t *file_pos
						 uint32_t *block_nums,
						 char __user *block_data,
						 unsigned int *p_nr_ram2gpu,
						 unsigned int *p_nr_ssd2gpu)
{
	mapped_gpu_memory *mgmem = dtask->mgmem;
	struct file	   *filp = dtask->filp;
	char __user	   *dest_uaddr;
	size_t			dest_offset = mgmem->map_offset + buffer_offset;
	unsigned int	nr_ram2gpu = 0;
	unsigned int	nr_ssd2gpu = 0;
	unsigned int	n_pages = chunk_size >> PAGE_CACHE_SHIFT;
	int				threshold = n_pages / 2;
	size_t			i_size;
	int				retval = 0;
	int				i, j;

	/* sanity checks */
	if ((chunk_size & (PAGE_CACHE_SIZE - 1)) != 0 ||	/* alignment */
		chunk_size < PAGE_CACHE_SIZE ||					/* >= 4KB */
		chunk_size > STROM_DMA_SSD2GPU_MAXLEN)			/* <= 128KB */
		return -EINVAL;
	dest_offset = mgmem->map_offset + buffer_offset + nchunks * chunk_size;
	if (dest_offset > mgmem->map_length)
		return -ERANGE;

	i_size = i_size_read(filp->f_inode);
	for (i=0; i < nchunks; i++)
	{
		loff_t			fpos = file_pos[i];
		struct page	   *fpage;
		int				score = 0;

		/* sanity checks */
		if ((fpos & (PAGE_CACHE_SIZE - 1)) != 0)
			return -EINVAL;
		if ((fpos + chunks_size) > i_size)
			return -ERANGE;

		for (j=0; j < n_pages; j++, fpos += PAGE_CACHE_SIZE)
		{
			fpage = find_lock_page(filp->f_mapping,
								   fpos >> PAGE_CACHE_SHIFT);
			dtask->file_pages[j] = fpage;
			if (fpage)
				score += (PageDirty(fpage) ? 3 : 1);
		}

		if (score > threshold)
		{
			dest_uaddr = block_data + chunk_size * nr_ram2gpu;
			retval = __memcpy_ssd2gpu_writeback(dtask, n_pages,
												file_pos[i],
												dest_uaddr);
			nr_ram2gpu++;
		}
		else
		{
			dest_offset -= chunk_size;
			__memcpy_ssd2gpu_submit_dma(dtask, n_pages,
										file_pos[i],
										dest_offset);
			nr_ssd2gpu++;
		}
	}
	Assert(nr_ram2gpu + nr_ssd2gpu == nchunks);



	return 0;
}

/*
 * ioctl(2) handler for STROM_IOCTL__MEMCPY_SSD2GPU_WRITEBACK
 */
static int
ioctl_memcpy_ssd2gpu_writeback(StromCmd__MemCpySsdToGpuWriteBack __user *uarg,
							   struct file *ioctl_filp)
{
	StromCmd__MemCpySsdToGpuWriteBack karg;
	strom_dma_task *dtask;
	loff_t		   *file_pos;
	uint32_t	   *block_nums;
	int				retval;

	if (copy_from_user(&karg, uarg,
					   offsetof(StromCmd__MemCpySsdToGpuWriteBack, file_pos)))
		return -EFAULT;

	/* move the @file_pos array */
	file_pos = kmalloc(sizeof(loff_t) * karg.nchunks, GFP_KERNEL);
	if (!file_pos)
		return -ENOMEM;
	if (copy_from_user(file_pos, uarg->file_pos,
					   sizeof(loff_t) * karg.nchunks))
	{
		retval = -EFAULT;
		goto out;
	}

	/* move the @block_nums array, if any */
	if (!karg.block_nums)
		block_nums = NULL;
	else
	{
		block_nums = kmalloc(sizeof(uint32_t) * karg.nchunks, GFP_KERNEL);
		if (!block_nums)
		{
			retval = -ENOMEM;
			goto out;
		}
		if (copy_from_user(block_nums, karg.block_nums,
						   sizeof(uint32_t) * karg.nchunks))
		{
			retval = -EFAULT;
			goto out;
		}
	}

	dtask = strom_create_dma_task(karg.handle,
								  karg.file_desc,
								  ioctl_filp);
	if (IS_ERR(dtask))
	{
		retval = PTR_ERR(dtask);
		goto out;
	}
	karg.dma_task_id = dtask->dma_task_id;
	karg.nr_ram2gpu = 0;
	karg.nr_ssd2gpu = 0;
	
	retval = memcpy_ssd2gpu_writeback(dtask,
									  karg.offset,
									  karg.block_size,
									  karg.nchunks,
									  file_pos,
									  block_nums,	/* may be NULL */
									  karg.block_data,	/* __user */
									  &karg.nr_ram2gpu,
									  &karg.nr_ssd2gpu);
	strom_put_dma_task(dtask, 0);

	/* write back the results */
	if (!retval)
	{
		if (copy_to_user(uarg, &karg,
						 offsetof(StromCmd__MemCpySsdToGpuWriteBack, handle)))
			retval = -EFAULT;
		if (block_nums &&
			copy_to_user(karg.block_nums, block_nums,
						 sizeof(uint32_t) * karg.nchunks))
			retval = -EFAULT;
	}
	/* synchronization of completion if any error */
	if (retval)
		strom_memcpy_ssd2gpu_wait(dma_task_id, NULL, TASK_UNINTERRUPTIBLE);
out:
	kfree(block_nums);
	kfree(file_pos);
	return retval;
}

/* ================================================================
 *
 * file_operations of '/proc/nvme-strom' entry
 *
 * ================================================================
 */
static const char  *strom_proc_signature =		\
	"version: " NVME_STROM_VERSION "\n"			\
	"target: " UTS_RELEASE "\n"					\
	"build: " NVME_STROM_BUILD_TIMESTAMP "\n";

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
		init_waitqueue_head(&strom_dma_task_waitq[i]);
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
	prNotice("/proc/nvme-strom entry was registered");

	return 0;
}
module_init(nvme_strom_init);

void __exit nvme_strom_exit(void)
{
	strom_exit_extra_symbols();
	proc_remove(nvme_strom_proc);
	prNotice("/proc/nvme-strom entry was unregistered");
}
module_exit(nvme_strom_exit);

MODULE_AUTHOR("KaiGai Kohei <kaigai@kaigai.gr.jp>");
MODULE_DESCRIPTION("SSD-to-GPU Direct Stream Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
