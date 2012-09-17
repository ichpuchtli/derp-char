#include "crypto-ops.h"

/* Internal Macro's */
/*****************************************************************************/
#define IS_WRITER(FLAGS) ( (FLAGS & O_WRONLY) || (FLAGS & O_RDWR) )
#define IS_READER(FLAGS) ( (FLAGS & O_RDONLY) || (FLAGS & O_RDWR) )
#define IS_RDWR(FLAGS)   ( FLAGS & O_RDWR )

#define BUFFER_SIZE (1 << 13)

#ifdef DEBUG
#define DUBUG(...) printk(KERN_WARNING "crypto: " __VA_ARGS__)
#else
#define DUBUG(...)
#endif

/* Internal Functions */
/*****************************************************************************/
static int create_buffer(void);
static int delete_buffer(struct file *filp, unsigned int buffer_id);
static int attach_buffer(struct file *filp, unsigned int buffer_id);
static int detach_buffer(struct file *filp);
static int set_crypto_mode(struct file *filp, unsigned long arg);
static int create_handle(struct file *filp);
static void free_buffer(CryptoBuffer * buff);
static void free_handle(struct file *filp);


/* Globals */
/*****************************************************************************/
static struct list_head DEVICE_BUFFERS;
static unsigned int BUFFER_COUNT;

static void free_handle(struct file *filp)
{

	CryptoHandle *handle = (CryptoHandle *) filp->private_data;


	/* free structure */
	kfree((void *) handle);

}

static void free_buffer(CryptoBuffer * buff)
{

	DUBUG("free buffer -> %d \n", buff->id);

	/* remove from buffer list */
	list_del((struct list_head *) buff);

	BUFFER_COUNT--;

	/* free buffer */
	kfree(buff->buffer);

	/* lastly free the structure */
	kfree((void *) buff);

}

static int create_handle(struct file *filp)
{

	CryptoHandle *handle;

	/* file structure is already opened */
	if (filp->private_data != NULL) {
		return -EFAULT;
	}

	/* allocate structure */
	handle = (CryptoHandle *) kmalloc(sizeof(CryptoHandle), GFP_KERNEL);

	if (handle == (void *) NULL) {
		DUBUG("kmalloc returned zero!\n");
		return -ENOMEM;
	}

	/* initialize mode */
	/* memset(handle->mode, 0xFF, sizeof(struct crypto_smode)); */

	handle->buff = NULL;

	filp->private_data = (void *) handle;

	return 0;

}

/* Create a buffer and return its identifier. This call takes no arguments.
 *
 * Example (where fd is an open file descriptor to the device):
 *
 *     int buffer_id = ioctl(fd, CRYPTO_IOCCREATE);
 *
 * Returns one of:
 *     >0 on success (buffer id)
 *     -ENOMEM if no memory was available to satisfy the request
 */
static int create_buffer(void)
{

	CryptoBuffer *buffstate;

	/* allocate the "BufferState Structure */
	buffstate = kmalloc(sizeof(CryptoBuffer), GFP_KERNEL);

	if (buffstate == (void *) NULL) {
		DUBUG("kmalloc returned zero!\n");
		return -ENOMEM;
	}

	/* add buffer to list of buffers */
	list_add((struct list_head *) buffstate, &DEVICE_BUFFERS);

	/* null reader/writer field */
	buffstate->reader = (struct file *) NULL;
	buffstate->writer = (struct file *) NULL;

	/* initialize semaphore */
	sema_init(&buffstate->sem, 1);

	/* allocate the buffer and map pointers */
	buffstate->buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);

	if (buffstate->buffer == (void *) NULL) {
		DUBUG("kmalloc returned zero!\n");

		return -ENOMEM;
	}

	buffstate->rp = buffstate->wp = (char *) buffstate->buffer;

	/* unique buffer id based on index into DEVICE_BUFFERS */
	buffstate->id = ++BUFFER_COUNT;

	DUBUG("buffer id:%d created!\n", BUFFER_COUNT);

	/* No one using buffer yet but add one so it's not thrown out */
	buffstate->refcount = 0;

	return buffstate->id;

}

/* Deletes a buffer identified by the integer argument given.
 *
 * Example (where fd is an open file descriptor to the device): 
 *
 *     unsigned int buffer_id = 2;
 *     int r = ioctl(fd, CRYPTO_IOCTDELETE, buffer_id);
 *
 * Returns one of:
 *     0 on success
 *     -EINVAL if the buffer specified does not exist
 *     -EOPNOTSUPP if the buffer has a positive reference count
 *         (except if the requesting fd is the only attached fd, which
 *         should succeed)
 *     -ENOMEM if no memory was available to satisfy the request
 */
static int delete_buffer(struct file *filp, unsigned int buffer_id)
{


	/* walk through buffer list find appropriate buffer */
	struct list_head *curr = &DEVICE_BUFFERS;
	CryptoBuffer *buff = NULL;
	CryptoHandle *handle = (CryptoHandle *) filp->private_data;

	while ((curr = curr->next) != &DEVICE_BUFFERS) {

		if (((CryptoBuffer *) curr)->id == buffer_id) {

			buff = (CryptoBuffer *) curr;

			break;

		}

	}

	/* the buffer specified does not exist */
	if (buff == NULL) {
		return -EINVAL;
	}

	/* down sem */
	(void) down_interruptible(&buff->sem);

	if (buff->refcount == 1) {

		/* this handle is not attached to this buffer */
		if (handle->buff != buff) {
			return -EOPNOTSUPP;
		}

		(void) detach_buffer(filp);

	}

	/* the buffer has another handle attached to it */
	if (buff->refcount > 1) {
		return -EOPNOTSUPP;
	}

	free_buffer(buff);

	return 0;

}

/* Returns one of:
 *     0 on success
 *     -EINVAL if the buffer specified does not exist
 *     -EOPNOTSUPP if the fd is already attached to a buffer
 *     -EALREADY if there is already a reader or writer attached
 *     -ENOMEM if no memory was available to satisfy the request
 */
static int attach_buffer(struct file *filp, unsigned int buffer_id)
{

	struct list_head *curr = &DEVICE_BUFFERS;
	CryptoHandle *handle = (CryptoHandle *) filp->private_data;
	CryptoBuffer *buff = NULL;

	/* down sem */
	(void) down_interruptible(&buff->sem);

	/* the fd is already attached to a buffer */
	if (handle->buff != NULL) {
		return -EOPNOTSUPP;
	}

	/* walk through buffer list find appropriate buffer */

	while ((curr = curr->next) != &DEVICE_BUFFERS) {

		if (((CryptoBuffer *) curr)->id == buffer_id) {

			buff = (CryptoBuffer *) curr;
			break;
		}
	}

	/* the buffer specified does not exist */
	if (buff == NULL) {
		return -EINVAL;
	}

	if (IS_WRITER(filp->f_flags)) {

		/* there is already a writer attached */
		if (buff->writer) {
			return -EALREADY;
		}

		buff->writer = filp;
		buff->refcount++;

	} else if (IS_READER(filp->f_flags)) {

		/* there is already a reader attached */
		if (buff->reader) {
			return -EALREADY;
		}

		buff->reader = filp;
		buff->refcount++;

	} else if (IS_RDWR(filp->f_flags)) {

		/* there is already a reader|writer attached */
		if (buff->writer) {
			return -EALREADY;
		}

		buff->writer = filp;
		buff->refcount++;

		/* there is already a reader|writer attached */
		if (buff->reader) {
			return -EALREADY;
		}

		buff->reader = filp;
		buff->refcount++;

	}

	handle->buff = buff;

	/* up sem */
	up(&buff->sem);

	return 0;
}

/* Detach from the already attached buffer. Since the driver knows which
 * buffer a file descriptor is attached to, this call takes no argument.
 *
 * Example (where fd is an open file descriptor to the device):
 *
 *     int r = ioctl(fd, CRYPTO_IOCDETACH);
 *
 * Returns one of:
 *     0 on success
 *     -EOPNOTSUPP if the fd is not attached to any buffer
 *     -ENOMEM if no memory was available to satisfy the request
 */

static int detach_buffer(struct file *filp)
{

	CryptoHandle *handle = (CryptoHandle *) filp->private_data;
	CryptoBuffer *buff = handle->buff;

	/* down sem */
	(void) down_interruptible(&buff->sem);

	/* the handle is not attached to any buffer */
	if (buff == NULL) {
		return -EOPNOTSUPP;
	}

	if (buff->reader == filp) {
		buff->reader = NULL;
		buff->refcount--;
	}

	if (buff->writer == filp) {
		buff->writer = NULL;
		buff->refcount--;
	}

	handle->buff = NULL;

	if (buff->refcount <= 0) {

		free_buffer(buff);

		return 0;
	}

	/* up sem */
	up(&buff->sem);

	return 0;

}

/* Sets the mode of standard I/O calls, given by the struct passed as an
 * argument. You must initialise this struct first. The fd does not have
 * to be attached to a buffer for this call to work, since the encryption
 * mode is a property of the file descriptor, not a buffer.
 *
 * This can be called multiple times to set different modes (for instance
 * to set the write mode, and then the read mode).
 *
 * Example to set the device to decrypt on read (where fd is an open file 
 * descriptor to the device):
 *
 *     struct crypto_smode m;
 *     m.dir = CRYPTO_READ;
 *     m.mode = CRYPTO_DEC;
 *     m.key = 0x5;
 *
 *     int r = ioctl(fd, CRYPTO_IOCSMODE, &m);
 *
 * The structure will be copied from the userspace process' address space
 * by the device driver.
 *
 * Returns one of:
 *     0 on success
 *     -ENOMEM if no memory was available to satisfy the request
 *     -EFAULT if the pointer given is outside the address space of the
 *              user process
 */
static int set_crypto_mode(struct file *filp, unsigned long arg)
{


	struct crypto_smode mode;
	CryptoHandle *handle = (CryptoHandle *) filp->private_data;
	unsigned int count = 0;

	if (handle == NULL) {
		/* should never happen need fd to call function anyway */
	}

	if (copy_from_user(&mode, (void *) arg, sizeof(struct crypto_smode))) {
		return -EFAULT;
	}

	if (mode.dir != CRYPTO_READ || mode.dir != CRYPTO_WRITE) {

		/* integrity error */
	}

	if (mode.mode != CRYPTO_DEC || mode.mode != CRYPTO_ENC || mode.mode
	    != CRYPTO_PASSTHROUGH) {

		/* integrity error */
	}

	while (mode.key[count] != '\0' && count < 255) {
		count++;
	}

	if (mode.key[count] != '\0') {

		/* integrity error */
		/* error key is not null terminated */
	}

	handle->mode = mode;

	return 0;

}

int crypto_open(struct inode *inode, struct file *filp)
{
	/* increase the refcount of the open module */
	try_module_get(THIS_MODULE);

	/* check user has the permission they are requesting */

	return create_handle(filp);
}

int crypto_release(struct inode *inode, struct file *filp)
{
	/* decrease the refcount of the open module */
	module_put(THIS_MODULE);

	/* detach_buffer */

	(void) detach_buffer(filp);

	/* free handle */
	free_handle(filp);

	return 0;
}

ssize_t crypto_read(struct file * filp, char *buf, size_t len, loff_t * off)
{

	CryptoHandle *handle = (CryptoHandle *) filp->private_data;
	CryptoBuffer *buff = handle->buff;
	struct crypto_smode crypto_enc;
	struct cryptodev_state crypto_state;
	ssize_t minimum;

	/* down sem */
	(void) down_interruptible(&buff->sem);

	crypto_enc = handle->mode;

	minimum = min(len, (size_t) (buff->wp - buff->rp));

	cryptodev_init(&crypto_state, crypto_enc.key, strlen(crypto_enc.key));

	/* check filp is a reader */
	if (buff->reader != filp) {

	}

	switch (crypto_enc.mode) {

	case CRYPTO_READ:

	case CRYPTO_WRITE:

	default:
		break;

	}

	switch (crypto_enc.dir) {

	case CRYPTO_ENC:

	case CRYPTO_DEC:

	case CRYPTO_PASSTHROUGH:

	default:
		break;

	}

	if (copy_to_user(buf, buff->rp, minimum)) {
		/* error not all data copied */
	}

	/* TODO implement circular buffer */
	buff->rp += minimum;

	/* up sem */
	up(&buff->sem);

	return minimum;
}

ssize_t crypto_write(struct file * filp, const char *buf, size_t len,
		     loff_t * off)
{

	CryptoHandle *handle = (CryptoHandle *) filp->private_data;
	CryptoBuffer *buff = handle->buff;

	/* down sem */
	(void) down_interruptible(&buff->sem);

	/* check filp for attached buffer */

	/* check filp is a writer */

	/* check mode for encryption */

	/* copy from user space and do crypt */

	/* update read/write pointers */

	/* up sem */
	up(&buff->sem);

	return 0;
}



int crypto_ioctl(struct inode *inode, struct file *filp, unsigned int cmd,
		 unsigned long arg)
{

	switch (cmd) {

	case CRYPTO_IOCCREATE:

		return create_buffer();

	case CRYPTO_IOCTDELETE:

		return delete_buffer(filp, (unsigned int) arg);

	case CRYPTO_IOCTATTACH:

		return attach_buffer(filp, (unsigned int) arg);

	case CRYPTO_IOCDETACH:

		return detach_buffer(filp);

	case CRYPTO_IOCSMODE:

		return set_crypto_mode(filp, arg);

	}

	/* should never reach here */
	return -ENOTTY;
}

int crypto_mmap(struct file *filp, struct vm_area_struct *vma)
{
	return -ENOSYS;
}

void init_file_ops(void)
{
	/* Initialize Linked List of Buffers */
	INIT_LIST_HEAD(&DEVICE_BUFFERS);
	BUFFER_COUNT = 0;

}

void exit_file_ops(void)
{

	if (BUFFER_COUNT != 0) {
		DUBUG("buffer_count -> %d \n", BUFFER_COUNT);
		/* error possible memory leak */
	}

	return;
}

const struct file_operations fops = {
	.open = crypto_open,
	.release = crypto_release,
	.read = crypto_read,
	.write = crypto_write,
	.ioctl = crypto_ioctl,
	.mmap = crypto_mmap,
};
