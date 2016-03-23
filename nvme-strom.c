/*
 * NVMe-Strom
 *
 * A Linux kernel driver to support SSD-to-GPU direct stream.
 *
 *
 *
 *
 */
#include <linux/kernel.h>
#include <linux/module.h>


static int	__init
nvme_strom_init(void)
{
	printk(KERN_INFO "nvme_strom_init is called\n");

	return 0;
}
module_init(nvme_strom_init);

static void __exit
nvme_strom_exit(void)
{
	printk(KERN_INFO "nvme_strom_exit is called\n");
}
module_exit(nvme_strom_exit);

MODULE_AUTHOR("KaiGai Kohei <kaigai@kaigai.gr.jp>");
MODULE_DESCRIPTION("SSD-to-GPU Direct Stream Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");


