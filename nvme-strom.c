/*
 * NVMe-Strom
 *
 * A Linux kernel driver to support SSD-to-GPU direct stream.
 *
 *
 *
 *
 */
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/proc_fs.h>


/* procfs entry of "/proc/nvme-strom" */
static struct proc_dir_entry  *nvme_strom_proc = NULL;

/*
 * Pointers of symbols not exported.
 */
#ifndef CONFIG_KALLSYMS
#error Linux kernel has to be built with CONFIG_KALLSYMS
#endif
static int extra_symbols_are_valid = 0;
static int (* p_ext4_get_block)(struct inode *inode, sector_t offset,
								struct buffer_head *bh, int create);
static int (* p_xfs_get_blocks)(struct inode *inode, sector_t offset,
								struct buffer_head *bh, int create);

static void
nvme_strom_update_extra_symbols(void)
{
	unsigned long	addr;

	addr = kallsyms_lookup_name("ext4_get_block");
	p_ext4_get_block = (void *)addr;
	printk(KERN_INFO "ext4_get_block = %p\n", (void *)addr);

	addr = kallsyms_lookup_name("xfs_get_blocks");
	p_xfs_get_blocks = (void *)addr;
	printk(KERN_INFO "xfs_get_blocks = %p\n", (void *)addr);

	/* ok, extra symbols are valid */
	extra_symbols_are_valid = 1;
}

static inline int
ext4_get_block(struct inode *inode, sector_t offset,
			   struct buffer_head *bh, int create)
{
	if (unlikely(!extra_symbols_are_valid))
		nvme_strom_update_extra_symbols();
	if (!p_ext4_get_block)
		return -EINVAL;
	return p_ext4_get_block(inode, offset, bh, create);
}

static inline int
xfs_get_blocks(struct inode *inode, sector_t offset,
			   struct buffer_head *bh, int create)
{
	if (unlikely(!extra_symbols_are_valid))
		nvme_strom_update_extra_symbols();
	if (!p_xfs_get_blocks)
		return -EINVAL;
	return p_xfs_get_blocks(inode, offset, bh, create);
}






static int
nvme_strom_proc_open(struct inode *inode, struct file *file)
{
	return -EINVAL;
}

static int
nvme_strom_proc_release(struct inode *inode, struct file *file)
{
	return 0;
}

static long
nvme_strom_proc_ioctl(struct file *file,
					  unsigned int cmd,
					  unsigned long arg)
{
	return -EINVAL;
}



/*
 * nvme_strom_invalidate_extra_symbols
 *
 * invalidate address of symbols that are not (officially) exported to module
 */
static int
nvme_strom_invalidate_extra_symbols(struct notifier_block *nb,
									unsigned long action, void *data)
{
	extra_symbols_are_valid = 0;

	return 0;
}

/* device file operations */
static const struct file_operations nvme_strom_fops = {
	.owner			= THIS_MODULE,
	.open			= nvme_strom_proc_open,
	.release		= nvme_strom_proc_release,
	.unlocked_ioctl	= nvme_strom_proc_ioctl,
	.compat_ioctl	= nvme_strom_proc_ioctl,
};

/* notifier for symbol resolver */
static struct notifier_block nvme_strom_nb = {
	.notifier_call	= nvme_strom_invalidate_extra_symbols
};

static int	__init
nvme_strom_init(void)
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

static void __exit
nvme_strom_exit(void)
{
	unregister_module_notifier(&nvme_strom_nb);
	proc_remove(nvme_strom_proc);
	printk(KERN_INFO "/proc/nvme-strom unregistered\n");
}
module_exit(nvme_strom_exit);

MODULE_AUTHOR("KaiGai Kohei <kaigai@kaigai.gr.jp>");
MODULE_DESCRIPTION("SSD-to-GPU Direct Stream Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");


