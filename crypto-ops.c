#include "crypto-ops.h"

/* Internal Macro's */
#define IS_WRITER(filp) (filp->f_mode & FMODE_WRITE)
#define IS_READER(filp) (filp->f_mode & FMODE_READ)

#define BUFFSIZE (1 << 13)

#ifdef DEBUG
#define DUBUG(...) printk(KERN_WARNING "crypto: " __VA_ARGS__)
#else
#define DUBUG(...) do { } while (0)
#endif

/* Internal Functions */
static int create_buffer(void);
static int delete_buffer(struct file *filp, unsigned int buffer_id);
static int attach_buffer(struct file *filp, unsigned int buffer_id);
static int detach_buffer(struct file *filp);
static int set_crypto_mode(struct file *filp, unsigned long arg);
static int create_handle(struct file *filp);
static void free_buffer(struct CryptoBuffer *buff);
static void free_handle(struct file *filp);
static void crypto_inplace(char *key, char *buf, size_t len);

/* Internal Globals */
static struct list_head BUF_SENTINAL;
static unsigned int BUF_COUNT;
struct semaphore BUF_LIST_SEM;

static void crypto_inplace(char *key, char *buf, size_t len)
{

	struct cryptodev_state state;

	/* allocate the buffer */
	char *buf_cpy = kmalloc(BUFFSIZE, GFP_KERNEL);

	if (buf_cpy == (void *) NULL) {

		DUBUG("(crypto_inplace) [Error] kmalloc returned zero\n");

		return;
	}

	memcpy(buf_cpy, buf, len);

	cryptodev_init(&state, key, strlen(key));

	cryptodev_docrypt(&state, buf_cpy, buf, len);

	kfree(buf_cpy);
}

static void free_handle(struct file *filp)
{

	struct CryptoHandle *chandle;

	chandle = (struct CryptoHandle *) filp->private_data;

	kfree(chandle->enc_st);

	kfree(chandle);
}

static void free_buffer(struct CryptoBuffer *buf)
{
	DUBUG("(free_buffer) ID->%d, Remaing->%d\n", buf->id, BUF_COUNT - 1);

	while (down_interruptible(&BUF_LIST_SEM))
		/* do nothing */ ;
	/* -------------------- Enter Critical Section -------------------- */

	list_del(&buf->node);
	BUF_COUNT--;

	/* -------------------- Leave Critical Section -------------------- */
	up(&BUF_LIST_SEM);

	/* free buffer */
	kfree(buf->start);

	/* lastly free the structure */
	kfree(buf);
}

static int create_handle(struct file *filp)
{

	struct CryptoHandle *chandle;

	/* file structure is already opened */
	if (filp->private_data != NULL) {
		DUBUG("(create_handle) [Error] file pointer already in use\n");
		return -EFAULT;
	}

	/* allocate structure */
	chandle = kmalloc(sizeof(struct CryptoHandle), GFP_KERNEL);

	if (chandle == (void *) NULL) {
		DUBUG("(create_handle) [Error] kmalloc returned zero\n");
		return -ENOMEM;
	}

	chandle->enc_st = kmalloc(sizeof(struct crypto_smode), GFP_KERNEL);

	if (chandle->enc_st == (void *) NULL) {
		DUBUG("(create_handle) [Error] kmalloc returned zero\n");
		kfree(chandle);
		return -ENOMEM;
	}

	/* initialize mode */
	memset((void *) chandle->enc_st, 0x00, sizeof(struct crypto_smode));

	chandle->enc_st->mode = CRYPTO_PASSTHROUGH;

	chandle->buf = NULL;

	filp->private_data = (void *) chandle;

	DUBUG("(create_handle) new handle created\n");

	return 0;

}

/* Create a buffer and return its identifier. This call takes no arguments.
 *
 *Example (where fd is an open file descriptor to the device):
 *
 *   int buffer_id = ioctl(fd, CRYPTO_IOCCREATE);
 *
 *Returns one of:
 *   >0 on success (buffer id)
 *   -ENOMEM if no memory was available to satisfy the request
 */
static int create_buffer(void)
{

	struct CryptoBuffer *cbuf;

	/* allocate the "BufferState Structure */
	cbuf = kmalloc(sizeof(struct CryptoBuffer), GFP_KERNEL);

	if (cbuf == (void *) NULL) {
		DUBUG("(create_buffer) [Error] kmalloc returned zero\n");
		return -ENOMEM;
	}

	/* allocate the buffer and map pointers */
	cbuf->start = kmalloc(BUFFSIZE, GFP_KERNEL);

	if (cbuf->start == (void *) NULL) {

		DUBUG("(create_buffer) [Error] kmalloc returned zero\n");

		kfree(cbuf);

		return -ENOMEM;
	}

	/* null reader/writer field */
	cbuf->reader = (struct file *) NULL;
	cbuf->writer = (struct file *) NULL;

	/* Zero reader/writer buffer offsets */
	cbuf->r_off = cbuf->w_off = 0;

	/* initialize semaphore */
	sema_init(&cbuf->sem, 1);

	/* unique buffer id based on index into list */
	cbuf->id = BUF_COUNT + 1;

	while (down_interruptible(&BUF_LIST_SEM))
		/* do nothing */ ;
	/* -------------------- Enter Critical Section -------------------- */

	list_add(&cbuf->node, &BUF_SENTINAL);
	BUF_COUNT++;

	/* -------------------- Leave Critical Section -------------------- */
	up(&BUF_LIST_SEM);

	DUBUG("(create_buffer) new Buffer ID->%d\n", BUF_COUNT);

	return cbuf->id;
}

/* Deletes a buffer identified by the integer argument given.
 *
 *Example (where fd is an open file descriptor to the device):
 *
 *   unsigned int buffer_id = 2;
 *   int r = ioctl(fd, CRYPTO_IOCTDELETE, buffer_id);
 *
 *Returns one of:
 *   0 on success
 *   -EINVAL if the buffer specified does not exist
 *   -EOPNOTSUPP if the buffer has a positive reference count
 *       (except if the requesting fd is the only attached fd, which
 *       should succeed)
 *   -ENOMEM if no memory was available to satisfy the request
 */
static int delete_buffer(struct file *filp, unsigned int buffer_id)
{

	struct CryptoBuffer *cbuf = NULL;
	struct CryptoBuffer *candidate;
	struct CryptoHandle *chandle;

	chandle = (struct CryptoHandle *) filp->private_data;

	while (down_interruptible(&BUF_LIST_SEM))
		/* do nothing */ ;
	/* -------------------- Enter Critical Section -------------------- */

	list_for_each_entry(candidate, &BUF_SENTINAL, node) {

		if (candidate->id == buffer_id) {

			cbuf = candidate;

			break;
		}
	}

	/* -------------------- Leave Critical Section -------------------- */
	up(&BUF_LIST_SEM);

	/* the buffer specified does not exist */
	if (cbuf == NULL) {

		DUBUG
		    ("(delete_buffer) [Error] buffer does not exists ID->%d\n",
		     buffer_id);

		return -EINVAL;
	}

	if ((cbuf->reader && cbuf->writer) && (cbuf->reader != cbuf->writer)) {

		DUBUG("(delete_buffer) [Error] buffer still attached ID->%d\n",
		      buffer_id);

		return -EOPNOTSUPP;
	}

	if (cbuf->writer == filp) {

		(void) detach_buffer(filp);

		if (chandle->buf == NULL)
			return 0;
	}

	if (cbuf->reader == filp) {

		(void) detach_buffer(filp);

		if (chandle->buf == NULL)
			return 0;
	}

	free_buffer(cbuf);

	return 0;
}

/* Returns one of:
 *   0 on success
 *   -EINVAL if the buffer specified does not exist
 *   -EOPNOTSUPP if the fd is already attached to a buffer
 *   -EALREADY if there is already a reader or writer attached
 *   -ENOMEM if no memory was available to satisfy the request
 */
static int attach_buffer(struct file *filp, unsigned int buffer_id)
{

	struct CryptoBuffer *cbuf = NULL;
	struct CryptoBuffer *candidate;
	struct CryptoHandle *chandle;
	int ecode = 0;

	chandle = (struct CryptoHandle *) filp->private_data;

	/* the fd is already attached to a buffer */
	if (chandle->buf != NULL)
		return -EOPNOTSUPP;

	while (down_interruptible(&BUF_LIST_SEM))
		/* do nothing */ ;

	/* -------------------- Enter Critical Section -------------------- */

	list_for_each_entry(candidate, &BUF_SENTINAL, node) {

		if (candidate->id == buffer_id) {

			cbuf = candidate;

			break;
		}
	}

	/* -------------------- Leave Critical Section -------------------- */
	up(&BUF_LIST_SEM);

	/* the buffer specified does not exist */
	if (cbuf == NULL)
		return -EINVAL;

	while (down_interruptible(&(cbuf->sem)))
		/* do nothing */ ;

	/* -------------------- Enter Critical Section -------------------- */

	do {

		if (IS_WRITER(filp)) {

			/* there is already a writer attached */
			if (cbuf->writer) {
				ecode = -EALREADY;
				break;
			}

			DUBUG("(attach_buffer) writer handle attached\n");

			cbuf->writer = filp;
		}

		if (IS_READER(filp)) {

			/* there is already a reader attached */
			if (cbuf->reader) {
				ecode = -EALREADY;
				break;
			}

			DUBUG("(attach_buffer) reader handle attached\n");

			cbuf->reader = filp;
		}

		chandle->buf = cbuf;

	} while (0);


	/* -------------------- Leave Critical Section -------------------- */
	up(&cbuf->sem);

	if (ecode)
		DUBUG("(attach_buffer) [Error] attaching buffer\n");

	return ecode;
}

/* Detach from the already attached buffer. Since the driver knows which
 *buffer a file descriptor is attached to, this call takes no argument.
 *
 *Example (where fd is an open file descriptor to the device):
 *
 *   int r = ioctl(fd, CRYPTO_IOCDETACH);
 *
 *Returns one of:
 *   0 on success
 *   -EOPNOTSUPP if the fd is not attached to any buffer
 *   -ENOMEM if no memory was available to satisfy the request
 */

static int detach_buffer(struct file *filp)
{

	struct CryptoHandle *chandle;
	struct CryptoBuffer *cbuf;

	chandle = (struct CryptoHandle *) filp->private_data;

	cbuf = chandle->buf;

	/* the handle is not attached to any buffer */
	if (cbuf == NULL) {
		DUBUG("(detach_buffer) [Error] handle not attached\n");
		return -EOPNOTSUPP;
	}

	while (down_interruptible(&cbuf->sem))
		/* do nothing */ ;

	/* -------------------- Enter Critical Section -------------------- */

	if (cbuf->reader == filp) {
		cbuf->reader = NULL;
		DUBUG("(detach_buffer) detached reader handle\n");
	}

	if (cbuf->writer == filp) {
		cbuf->writer = NULL;
		DUBUG("(detach_buffer) detached writer handle\n");
	}

	chandle->buf = NULL;

	if (cbuf->reader || cbuf->writer) {

		/* Buffer still held e.g. refcount > 0 */
		up(&cbuf->sem);

		return 0;
	}

	/* refcount == 0 so free buffer */
	free_buffer(cbuf);

	return 0;
}

/* Sets the mode of standard I/O calls, given by the struct passed as an
 *argument. You must initialise this struct first. The fd does not have
 *to be attached to a buffer for this call to work, since the encryption
 *mode is a property of the file descriptor, not a buffer.
 *
 *This can be called multiple times to set different modes (for instance
 *to set the write mode, and then the read mode).
 *
 *Example to set the device to decrypt on read (where fd is an open file
 *descriptor to the device):
 *
 *   struct crypto_smode m;
 *   m.dir = CRYPTO_READ;
 *   m.mode = CRYPTO_DEC;
 *   m.key = 0x5;
 *
 *   int r = ioctl(fd, CRYPTO_IOCSMODE, &m);
 *
 *The structure will be copied from the userspace process' address space
 *by the device driver.
 *
 *Returns one of:
 *   0 on success
 *   -ENOMEM if no memory was available to satisfy the request
 *   -EFAULT if the pointer given is outside the address space of the
 *            user process
 */
static int set_crypto_mode(struct file *filp, unsigned long arg)
{

	struct CryptoHandle *chandle;
	struct crypto_smode *kern_st;
	struct crypto_smode *user_st;

	chandle = (struct CryptoHandle *) filp->private_data;

	if (chandle == (struct CryptoHandle *) NULL)
		return -EOPNOTSUPP;

	kern_st = chandle->enc_st;

	user_st = (struct crypto_smode *) arg;

	if (copy_from_user(kern_st, user_st, sizeof(struct crypto_smode)))
		return -EFAULT;

	DUBUG("(set_crypto_mode) new mode set [%d,%d,%s]\n",
	      kern_st->dir, kern_st->mode, kern_st->key);

	return 0;
}

int crypto_open(struct inode *inode, struct file *filp)
{
	/* increase the refcount of the open module */
	try_module_get(THIS_MODULE);

	/* TODO check user has the permission they are requesting */

	return create_handle(filp);
}

int crypto_release(struct inode *inode, struct file *filp)
{
	/* decrease the refcount of the open module */
	module_put(THIS_MODULE);

	(void) detach_buffer(filp);

	free_handle(filp);

	return 0;
}

ssize_t crypto_read(struct file *filp, char *buf, size_t len, loff_t *off)
{

	struct CryptoHandle *chandle;
	struct CryptoBuffer *cbuf;
	struct crypto_smode *crypt;

	/* struct cryptodev_state dev_st; */
	size_t bytes = 0;

	chandle = (struct CryptoHandle *) filp->private_data;

	cbuf = chandle->buf;

	/* check buffer is attached to file pointer */
	if (cbuf == (struct CryptoBuffer *) NULL)
		return -EOPNOTSUPP;

	/* check filp is a reader */
	if (cbuf->reader != filp) {
		DUBUG("(crypto_read) [Error] file pointer is not a reader\n");
		return -EBADF;
	}

	crypt = chandle->enc_st;

	while (down_interruptible(&cbuf->sem))
		/* do nothing */ ;

	/* -------------------- Enter Critical Section -------------------- */

	/* Reduce len to number of available bytes */
	len = min_t(size_t, len, CIRC_CNT(cbuf->w_off, cbuf->r_off, BUFFSIZE));

	bytes = min_t(size_t, len, (size_t) CIRC_CNT_TO_END(cbuf->w_off,
							    cbuf->r_off,
							    BUFFSIZE));

	if (crypt->mode != CRYPTO_PASSTHROUGH) {
		crypto_inplace(crypt->key, (u8 *) cbuf->start + cbuf->w_off,
			    bytes);
	}

	if (copy_to_user(buf, cbuf->start + cbuf->r_off, bytes)) {

		DUBUG("(crypto_read) [Error] copy_to_user failed\n");
		return -EFAULT;
	}

	/* advance read offset */
	cbuf->r_off = (cbuf->r_off + bytes) & (BUFFSIZE - 1);

	if (crypt->mode != CRYPTO_PASSTHROUGH) {
		crypto_inplace(crypt->key, (u8 *) cbuf->start + cbuf->w_off,
			    len - bytes);
	}

	if (copy_to_user(buf + bytes, cbuf->start + cbuf->r_off, len - bytes)) {

		DUBUG("(crypto_read) [Error] copy_to_user failed\n");
		return -EFAULT;
	}

	/* advance read offset */
	cbuf->r_off = (cbuf->r_off + (len - bytes)) & (BUFFSIZE - 1);

	/* -------------------- Leave Critical Section -------------------- */
	up(&cbuf->sem);

	return len;
}

ssize_t crypto_write(struct file *filp, const char *buf, size_t len,
		     loff_t *off)
{

	struct CryptoHandle *chandle;
	struct CryptoBuffer *cbuf;
	struct crypto_smode *crypt;

	size_t bytes = 0;

	chandle = (struct CryptoHandle *) filp->private_data;

	cbuf = chandle->buf;

	if (cbuf->writer != filp) {
		DUBUG("(crypto_write) [Error] file pointer is not a writer\n");
		return -EOPNOTSUPP;
	}

	crypt = chandle->enc_st;

	while (down_interruptible(&cbuf->sem))
		/* do nothing */ ;

	/* -------------------- Enter Critical Section -------------------- */

	/* Reduce len to number of available bytes */
	len = min_t(size_t, len, CIRC_SPACE(cbuf->w_off, cbuf->r_off,
					    BUFFSIZE));

	bytes = min_t(size_t, len, (size_t) CIRC_SPACE_TO_END(cbuf->w_off,
							      cbuf->r_off,
							      BUFFSIZE));


	/* Need to do some crypto */
	if (crypt->mode != CRYPTO_PASSTHROUGH) {
		crypto_inplace(crypt->key, (u8 *) cbuf->start + cbuf->w_off,
			    bytes);
	}

	if (copy_from_user((void *) cbuf->start + cbuf->w_off, buf, bytes)) {

		DUBUG("(crypto_writer) [Error] copy_from_user failed\n");
		return -EFAULT;
	}
	/* advance writer offset */
	cbuf->w_off = (cbuf->w_off + bytes) & (BUFFSIZE - 1);

	/* Need to do some crypto */
	if (crypt->mode != CRYPTO_PASSTHROUGH) {
		crypto_inplace(crypt->key, (u8 *) cbuf->start + cbuf->w_off,
			    len - bytes);
	}

	if (copy_from_user((void *) cbuf->start + cbuf->w_off, buf + bytes,
			   len - bytes)) {

		DUBUG("(crypto_writer) [Error] copy_from_user failed\n");
		return -EFAULT;
	}

	/* advance write offset */
	cbuf->w_off = (cbuf->w_off + (len - bytes)) & (BUFFSIZE - 1);

	/* -------------------- Leave Critical Section -------------------- */
	up(&cbuf->sem);

	return bytes;
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

	return -ENOTTY;
}

/* called to map a buffer of kernel memory (len 4096 or 8192) and return a
 *pointer to the beginning of that buffer.
 *
 *the vm_area_struct contains:
 *- "unsigned long vm_start;" start and end virtual addresses
 *- "struct file *vm_file;" a pointer to the file struct associated with the
 * area
 *- "unsigned long vm_pgoff;" the offset of the area in a file. 0 = start of
 * file
 *- "unsigned long vm_page_prot;" RO/WO protection on the memory
 */

int crypto_mmap(struct file *filp, struct vm_area_struct *vma)
{

	struct CryptoHandle *chandle;
	struct CryptoBuffer *cbuf;
	size_t size;

	chandle = (struct CryptoHandle *) filp->private_data;

	cbuf = chandle->buf;

	/* check if flip passed through mmap() is attached to a buffer */
	if (cbuf == NULL)
		/* the handle is not attached to any buffer */
		return -EOPNOTSUPP;

	/* Set read only if write not explicitly declared */
	if (!(vma->vm_page_prot.pgprot & PROT_WRITE))
		vma->vm_page_prot.pgprot |= PROT_READ;

	/* set start of address range to start of our buffer
	 *(assumes page *alignment) */
	vma->vm_start = (unsigned long) cbuf->start;
	vma->vm_end = 8192UL - vma->vm_pgoff;
	size = vma->vm_end - vma->vm_start;

	/* ready to map, do final check of size to ensure alignment */
	if (size != 4096 || size != 8192)
		return -EIO;

	/* Build suitable page tables for the address range using
	 *remap_pfn_range */
	if (remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
			    size, vma->vm_page_prot))
		return -EAGAIN;

	return 0;
}

void init_file_ops(void)
{
	/* Initialize Linked List of Buffers */
	INIT_LIST_HEAD(&BUF_SENTINAL);

	BUF_COUNT = 0;

	sema_init(&BUF_LIST_SEM, 1);
}

void exit_file_ops(void)
{
	if (BUF_COUNT != 0)
		DUBUG("(exit_file_ops) [Error] buffer count not zero\n");
}

const struct file_operations fops = {
	.open = crypto_open,
	.release = crypto_release,
	.read = crypto_read,
	.write = crypto_write,
	.ioctl = crypto_ioctl,
	.mmap = crypto_mmap,
};
