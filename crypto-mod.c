#include <linux/module.h>	/* required for every module */
#include <linux/kernel.h>	/* KERN_INFO, printk() */
#include <linux/init.h>		/* __init and __exit */
#include <linux/fs.h>		/* register_chrdev_region */
#include <linux/types.h>	/* dev_t definition */
#include <linux/kdev_t.h>	/* MAJOR(), MINOR(), MKDEV() */
#include <linux/cdev.h>		/* cdev_init, cdev_add, ... */

#include "crypto-ops.h"

#define CRYPTO_MAJOR 250
#define CRYPTO_MINOR 0

#define CRYPTO_NAME    "crypto"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Samuel Macpherson/Douglas Pukallus");
MODULE_DESCRIPTION("Crypto Device Driver");

/* Global Variables */
static dev_t dev_num;
static struct cdev cdev_st;

/* __init & __exit */
int __init init_module(void)
{

	int result;

	/* Create dev_t */
	dev_num = MKDEV(CRYPTO_MAJOR, CRYPTO_MINOR);

	/* Register Device */
	result = register_chrdev_region(dev_num, 1, CRYPTO_NAME);

	if (result < 0) {
		printk(KERN_WARNING "crypto: can't get major %d\n",
		       CRYPTO_MAJOR);
		return result;
	}
	/* Initialize File Operations */
	init_file_ops();

	/* Prepare device for system */
	cdev_init(&cdev_st, &fops);
	cdev_st.owner = THIS_MODULE;

	/* Device is active after this point! */
	(void) cdev_add(&cdev_st, dev_num, 1);

	printk(KERN_INFO "crypto: major=%d, minor=%d\n", MAJOR(dev_num),
	       MINOR(dev_num));

	return 0;
}

void __exit cleanup_module(void)
{
	/* Remove char device from system */
	cdev_del(&cdev_st);

	/* Clean up file operation structures */
	exit_file_ops();

	/* Unregister Device */
	(void) unregister_chrdev_region(dev_num, 1);

}
