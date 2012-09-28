#ifndef _CRYPTO_OPS_H_
#define _CRYPTO_OPS_H_

#include <linux/kernel.h>	/* KERN_INFO, printk(), min */
#include <linux/module.h>	/* required for every module */
#include <linux/fs.h>		/* register_chrdev_region */
#include <linux/slab.h>		/* kmalloc, kfree, ... */
#include <linux/semaphore.h>	/* sema_init(), up(), down() */
#include <linux/list.h>		/* kmalloc, kfree, ... */

#include <linux/mm.h>
#include <asm-generic/mman-common.h>

#include <linux/circ_buf.h>	/* CIRC_CTN, ... */

#include <asm/uaccess.h>	/* copy_*_user */

#include "ioctl.h"
#include "cryptodev-1.0/cryptoapi.h"

extern const struct file_operations fops;

struct CryptoBuffer {

	struct list_head node;
	struct file *reader;
	struct file *writer;
	struct semaphore sem;

	unsigned int id;

	/* Circular Buffer */
	const char *start;
	size_t r_off;		/* tail in circular buffer terms */
	size_t w_off;		/* head in circular buffer terms */

};

struct CryptoHandle {

	struct crypto_smode *enc_st;
	struct CryptoBuffer *buf;
};

/*
 *File                 -> CryptoHandle -> CryptoBuffer
 *----------------        --------        ------------
 *| private_data-|------->| mode |        | sem      |
 *| ...          |        | buff-|------->| rp,wp    |
 *| ...          |        --------        | buffer   |
 *----------------                        | reader   |
 *                                       | id       |
 *                                       | refcount |
 *                                       ------------
 */

int crypto_open(struct inode *inode, struct file *filp);
int crypto_release(struct inode *inode, struct file *filp);
ssize_t crypto_read(struct file *filp, char *buf, size_t len, loff_t *off);
ssize_t crypto_write(struct file *filp, const char *buf, size_t len,
		     loff_t *off);
int crypto_ioctl(struct inode *inode, struct file *filp, unsigned int cmd,
		 unsigned long arg);
int crypto_mmap(struct file *filp, struct vm_area_struct *vma);

void init_file_ops(void);
void exit_file_ops(void);

#endif
