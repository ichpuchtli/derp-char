#ifndef _CRYPTO_OPS_H_
#define _CRYPTO_OPS_H_

#include <linux/kernel.h>	/* KERN_INFO, printk() */
#include <linux/module.h>	/* required for every module */
#include <linux/fs.h>		/* register_chrdev_region */
#include <linux/slab.h>		/* kmalloc, kfree, ... */

#include <asm/uaccess.h>	/* copy_*_user */

#include "ioctl.h"

#define MIN(A, B)  (((A) < (B)) ? (A) : (B))

extern const struct file_operations fops;

int crypto_open(struct inode *inode, struct file *filp);
int crypto_release(struct inode *inode, struct file *filp);
ssize_t crypto_read(struct file *filp, char *buf, size_t len, loff_t * off);
ssize_t crypto_write(struct file *filp, const char *buf, size_t len,
		     loff_t * off);
int crypto_ioctl(struct inode *inode, struct file *filp, unsigned int cmd,
		 unsigned long arg);
int crypto_mmap(struct file *filp, struct vm_area_struct *vma);

void init_file_ops(void);
void exit_file_ops(void);

#endif