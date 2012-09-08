#include <linux/module.h> /* required for every module */
#include <linux/kernel.h> /* KERN_INFO, printk() */
#include <linux/init.h> /* __init and __exit */
#include <linux/fs.h>  /* register_chrdev_region */
#include <linux/types.h> /* dev_t definition */
#include <linux/kdev_t.h> /* MAJOR(), MINOR(), MKDEV() */
#include <linux/slab.h> /* kmalloc, kfree, ... */
#include <linux/cdev.h> /* cdev_init, cdev_add, ... */

#include <asm/uaccess.h> /* copy_*_user */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Samuel Macpherson/Douglas Pukallus");
MODULE_DESCRIPTION("Crypto Device Driver");

#define CRYPTO_MAJOR 250
#define CRYPTO_MINOR 0

#define CRYPTO_NAME    "crypto"

#define MIN(a,b)  (((a) < (b)) ? (a) : (b))


//// Global Variables /////////////////////////////////////////////////////////
static dev_t dev_num;
static struct cdev cdev_st;

static char* buffer_front  = NULL;
static char* buffer_end    = NULL;
static char* read_pointer  = NULL;
static char* write_pointer = NULL;

//// File Operation Prototypes ////////////////////////////////////////////////

static int crypto_open(struct inode *inode, struct file *filp);
static int crypto_release(struct inode *inode, struct file *filp);
static ssize_t crypto_read(struct file *filp, char *buf, size_t len, loff_t * off);
static ssize_t crypto_write(struct file *filp, const char *buf, size_t len, loff_t * off);

static const struct file_operations fops = {
    .open = crypto_open,
    .release = crypto_release,
    .read = crypto_read,
    .write = crypto_write,
};

//// __init & __exit //////////////////////////////////////////////////////////
int __init init_module(void)
{

    int result;

    // Create dev_t
    dev_num = MKDEV(CRYPTO_MAJOR,CRYPTO_MINOR);

    // Register Device
    result = register_chrdev_region(dev_num, 1, CRYPTO_NAME);

    if( result < 0 ){
        printk(KERN_WARNING CRYPTO_NAME": can't get major %d\n", CRYPTO_MAJOR);
        return result;
    }

    // Initialize Structures
    buffer_front = kmalloc(PAGE_SIZE, GFP_KERNEL);

    if( buffer_front == (void*) NULL ) {
        printk(KERN_WARNING CRYPTO_NAME": kmalloc return zero!\n");
        return -1;
    }

    buffer_end = buffer_front + PAGE_SIZE;
    read_pointer = write_pointer = buffer_front;

    // Prepare device for system
    cdev_init(&cdev_st, &fops);
    cdev_st.owner = THIS_MODULE;

    // Device is active after this point!
    (void) cdev_add(&cdev_st, dev_num, 1);

    printk(KERN_INFO CRYPTO_NAME": major=%d, minor=%d\n", MAJOR(dev_num), MINOR(dev_num) );

    return 0;
}

void __exit cleanup_module(void)
{    

    (void) kfree(buffer_front);
    
    // Remove char device from system
    cdev_del(&cdev_st);

    // Unregister Device
    (void) unregister_chrdev_region(dev_num, 1);
}

//// File Operations //////////////////////////////////////////////////////////

static int crypto_open(struct inode *inode, struct file *filp)
{
    try_module_get(THIS_MODULE); /* increase the refcount of the open module */

    return 0;
}

static int crypto_release(struct inode *inode, struct file *filp)
{
    module_put(THIS_MODULE); /* decrease the refcount of the open module */

    return 0;
}

static ssize_t crypto_read(struct file *filp, char *buf, size_t len,
        loff_t * off)
{
    size_t read_len = write_pointer - read_pointer; 
    size_t minimum = MIN(len, read_len); 

    if( minimum == 0 ){
        // Nothing to read
        return 0;
    }
    
    if ( copy_to_user(buf, read_pointer, minimum ) != 0 ){
        printk(KERN_INFO CRYPTO_NAME": copy_to_user failed to copy entire buffer!\n");
        return -ENOSYS;
    }

    read_pointer += minimum;

    return (ssize_t) minimum; 

}

static ssize_t crypto_write(struct file *filp, const char *buf, size_t len, 
        loff_t * off)
{

    size_t buffer_space;
    size_t minimum;

    if( read_pointer == write_pointer ) {
        // Read caught up, we can safely reset pointers
        read_pointer = write_pointer = buffer_front;
    }

    buffer_space = buffer_end - write_pointer;
    minimum = MIN(len, buffer_space);

    if( minimum == 0 ) {
        // buffer full, wait for read pointer to catch up
        return -EINVAL;
    }

    if( copy_from_user( write_pointer, buf , minimum ) != 0 ) {
        printk(KERN_INFO CRYPTO_NAME": copy_from_user failed to copy entire buffer!\n");
        return -ENOSYS;
    }
    
    write_pointer += minimum;

    return (ssize_t) minimum;

}


