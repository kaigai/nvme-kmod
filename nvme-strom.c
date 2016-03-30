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
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>


/* entry of /proc/nvme-strom */
static struct proc_dir_entry  *nvme_strom_proc = NULL;





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




/* device file operations */
static const struct file_operations nvme_strom_fops = {
	.owner			= THIS_MODULE,
	.open			= nvme_strom_proc_open,
	.release		= nvme_strom_proc_release,
	.unlocked_ioctl	= nvme_strom_proc_ioctl,
	.compat_ioctl	= nvme_strom_proc_ioctl,
};

static int	__init
nvme_strom_init(void)
{
	nvme_strom_proc = proc_create("nvme-strom",
								  0444,
								  NULL,
								  &nvme_strom_fops);
	if (!nvme_strom_proc)
		return -ENOMEM;
	printk(KERN_INFO "/proc/nvme-strom registered\n");

	return 0;
}
module_init(nvme_strom_init);

static void __exit
nvme_strom_exit(void)
{
	proc_remove(nvme_strom_proc);
	printk(KERN_INFO "/proc/nvme-strom unregistered\n");
}
module_exit(nvme_strom_exit);

MODULE_AUTHOR("KaiGai Kohei <kaigai@kaigai.gr.jp>");
MODULE_DESCRIPTION("SSD-to-GPU Direct Stream Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");


