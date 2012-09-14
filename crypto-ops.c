#include "crypto-ops.h"

/* Global Variables */
static char *buffer_front;
static char *buffer_end;
static char *read_pointer;
static char *write_pointer;

void init_file_ops(void)
{

	/* Initialize Structures */
	buffer_front = kmalloc(PAGE_SIZE, GFP_KERNEL);

	if (buffer_front == (void *) NULL) {
		printk(KERN_WARNING "crypto: kmalloc returned zero!\n");
		return;
	}

	buffer_end = buffer_front + PAGE_SIZE;
	read_pointer = write_pointer = buffer_front;

}

void exit_file_ops(void)
{

	(void) kfree(buffer_front);
}

int crypto_open(struct inode *inode, struct file *filp)
{
	/* increase the refcount of the open module */
	try_module_get(THIS_MODULE);

	return 0;
}

int crypto_release(struct inode *inode, struct file *filp)
{
	/* decrease the refcount of the open module */
	module_put(THIS_MODULE);

	return 0;
}

ssize_t crypto_read(struct file * filp, char *buf, size_t len, loff_t * off)
{
	size_t read_len = write_pointer - read_pointer;
	size_t minimum = MIN(len, read_len);

	if (minimum == 0) {
		/* Nothing to read */
		return 0;
	}

	if (copy_to_user(buf, read_pointer, minimum) != 0) {
		printk(KERN_INFO
		       "crypto: copy_to_user failed to copy entire buffer!\n");
		return -ENOSYS;
	}

	read_pointer += minimum;

	return (ssize_t) minimum;

}

ssize_t crypto_write(struct file * filp, const char *buf, size_t len,
		     loff_t * off)
{

	size_t buffer_space;
	size_t minimum;

	if (read_pointer == write_pointer) {
		/* Read caught up, we can safely reset pointers */
		read_pointer = write_pointer = buffer_front;
	}

	buffer_space = buffer_end - write_pointer;
	minimum = MIN(len, buffer_space);

	if (minimum == 0) {
		/* buffer full, wait for read pointer to catch up */
		return -EINVAL;
	}

	if (copy_from_user(write_pointer, buf, minimum) != 0) {
		printk(KERN_INFO
		       "crypto: copy_from_user failed to copy entire buffer!\n");
		return -ENOSYS;
	}

	write_pointer += minimum;

	return (ssize_t) minimum;

}

int crypto_ioctl(struct inode *inode, struct file *filp, unsigned int cmd,
		 unsigned long arg)
{

	return -ENOTTY;
}

int crypto_mmap(struct file *filp, struct vm_area_struct *vma)
{
	return -ENOSYS;
}

const struct file_operations fops = {
	.open = crypto_open,
	.release = crypto_release,
	.read = crypto_read,
	.write = crypto_write,
/*    .ioctl = crypto_ioctl, */
	.mmap = crypto_mmap,
};
