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
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
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
static inline int
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
 * strom_pin_gpu_memory - ioctl(2) handler to pin device memory
 * strom_unpin_gpu_memory - ioctl(2) handler to unpin device memory
 *
 * ================================================================
 */
#define PINNED_GPU_MEMORY_NSLOTS		100
static spinlock_t		strom_pgmem_locks[PINNED_GPU_MEMORY_NSLOTS];
static struct list_head	strom_pgmem_slots[PINNED_GPU_MEMORY_NSLOTS];

struct pinned_gpu_memory
{
	int					refcnt;			/* reference counter */
	struct list_head	chain;			/* chain to the pgmem_slot */
	unsigned long		handle;			/* identifier of this entry */
	uint64_t			base_address;	/* aligned device virtual address */
	uint64_t			base_offset;	/* offset to user given address */
	struct nvidia_p2p_page_table *page_table;
};

static struct pinned_gpu_memory *
strom_get_pinned_memory(unsigned long handle)
{
	int					index = handle % PINNED_GPU_MEMORY_NSLOTS;
	spinlock_t		   *lock = &strom_pgmem_locks[index];
	struct list_head   *slot = &strom_pgmem_slots[index];
	unsigned long		flags;
	struct pinned_gpu_memory *pgmem;

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
strom_put_pinned_memory(struct pinned_gpu_memory *pgmem)
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
	struct pinned_gpu_memory *pgmem;
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
 *
 *
 *
 *
 *
 *
 *
 */
static int
strom_pin_gpu_memory(struct file *file,
					 struct strom_cmd_pin_gpu_memory_arg __user *uarg)
{
	struct strom_cmd_pin_gpu_memory_arg karg;
	struct pinned_gpu_memory   *gmem;
	size_t				pin_size;
	int					index;
	spinlock_t		   *lock;
	struct list_head   *slot;
	unsigned long		flags;
	int					rc;

	if (copy_from_user(&karg, uarg, sizeof(karg)))
		return -EFAULT;

	gmem = kmalloc(sizeof(struct pinned_gpu_memory), GFP_KERNEL);
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
 *
 *
 *
 *
 *
 *
 *
 */
static int
strom_unpin_gpu_memory(struct file *file,
					   struct strom_cmd_unpin_gpu_memory_arg __user *uarg)
{
	struct strom_cmd_unpin_gpu_memory_arg karg;
	int					index;
	spinlock_t		   *lock;
	struct list_head   *slot;
	unsigned long		flags;
	struct pinned_gpu_memory *pgmem;

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
 * file_operations of '/proc/nvme-strom' entry
 *
 * ================================================================
 */
static int
strom_proc_open(struct inode *inode, struct file *file)
{
	return -EINVAL;
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
		case STROM_IOCTL_PIN_GPU_MEMORY:
			rc = strom_pin_gpu_memory(file, (void __user *) arg);
			break;
		case STROM_IOCTL_UNPIN_GPU_MEMORY:
			rc = strom_unpin_gpu_memory(file, (void __user *) arg);
			break;
		default:
			rc = -EINVAL;
			break;
	}
	return rc;
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

	if (!p_nvidia_p2p_get_pages)
	{
		addr = kallsyms_lookup_name("nvidia_p2p_get_pages");
		if (addr)
		{
			mod_nvidia_p2p_get_pages = __module_text_address(addr);
			if (mod_nvidia_p2p_get_pages)
				__module_get(mod_nvidia_p2p_get_pages);
			p_nvidia_p2p_get_pages = (void *) addr;
			printk(KERN_INFO NVME_STROM_PREFIX
				   "found nvidia_p2p_get_pages = %p\n",
				   p_nvidia_p2p_get_pages);
		}
	}

	if (!p_nvidia_p2p_put_pages)
	{
		addr = kallsyms_lookup_name("nvidia_p2p_put_pages");
		if (addr)
		{
			mod_nvidia_p2p_put_pages = __module_text_address(addr);
			if (mod_nvidia_p2p_put_pages)
				__module_get(mod_nvidia_p2p_put_pages);
			p_nvidia_p2p_put_pages = (void *) addr;
			printk(KERN_INFO NVME_STROM_PREFIX
				   "found nvidia_p2p_put_pages = %p\n",
				   p_nvidia_p2p_put_pages);
		}
	}

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
