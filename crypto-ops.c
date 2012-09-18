#include "crypto-ops.h"

/* Internal Macro's */
/*****************************************************************************/
#define IS_WRITER(FLAGS) ( (FLAGS & O_WRONLY) || (FLAGS & O_RDWR) )
#define IS_READER(FLAGS) ( (FLAGS & O_RDONLY) || (FLAGS & O_RDWR) )
#define IS_RDWR(FLAGS)   ( FLAGS & O_RDWR )

#define BUFFSIZE (1 << 13)

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
	kfree(buff->start);

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
	/* memset(handle->enc_st, 0xFF, sizeof(struct crypto_smode)); */

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

	/* TODO down list sem */
	/* add buffer to list of buffers */
	list_add((struct list_head *) buffstate, &DEVICE_BUFFERS);
	/* up list sem */

	/* null reader/writer field */
	buffstate->reader = (struct file *) NULL;
	buffstate->writer = (struct file *) NULL;

	/* initialize semaphore */
	sema_init(&buffstate->sem, 1);

	/* allocate the buffer and map pointers */
	buffstate->start = kmalloc(BUFFSIZE, GFP_KERNEL);

	if (buffstate->start == (void *) NULL) {
		DUBUG("kmalloc returned zero!\n");

		return -ENOMEM;
	}

	buffstate->r_off = buffstate->w_off = 0;

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

	/* the fd is already attached to a buffer */
	if (handle->buff != NULL) {
		return -EOPNOTSUPP;
	}

	/* down sem */
	(void) down_interruptible(&buff->sem);

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


	CryptoHandle *handle;
	struct crypto_smode* enc_st;
	unsigned int count = 0;
	

	handle = (CryptoHandle *) filp->private_data;

	/* handle is attached to a buffer so take sem */
	if( handle->buff != NULL){
	
		(void) down_interruptible(&handle->buff->sem);
	}

	enc_st = (struct crypto_smode*) handle ;

	if (copy_from_user(&enc_st,(void*) arg, sizeof(struct crypto_smode))) {
		return -EFAULT;
	}

	if (enc_st->dir != CRYPTO_READ || enc_st->dir != CRYPTO_WRITE) {

		/* integrity error */
	}

	if (enc_st->mode != CRYPTO_DEC || enc_st->mode != CRYPTO_ENC || 
			enc_st->mode != CRYPTO_PASSTHROUGH) {

		/* integrity error */
	}

	while (enc_st->key[count] != '\0' && count < 255) {
		count++;
	}

	if (enc_st->key[count] != '\0') {

		/* integrity error */
		/* error key is not null terminated */
	}

	/* handle is attached to a buffer so take sem */
	if( handle->buff != NULL){
	
		up(&handle->buff->sem);
	}
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

	CryptoHandle *chandle;
	CryptoBuffer *cbuff;

	/* struct cryptodev_state dev_st; */

	size_t chunk1 = 0;
	size_t chunk2 = 0;
	size_t minimum = 0;
	size_t bytes_read = 0;

	chandle = (CryptoHandle *) filp->private_data;

	cbuff = chandle->buff;

	/* check filp is a reader */
	if (cbuff->reader != filp) {
		return -EOPNOTSUPP;
	}

	/* down sem */
	(void) down_interruptible(&cbuff->sem);
/*****************************************************************************/

	chunk1 = CIRC_CNT_TO_END( cbuff->w_off, cbuff->r_off, BUFFSIZE);

	minimum = min( len, chunk1 );

	(void) copy_to_user(buf, (cbuff->start + cbuff->r_off), minimum);

	bytes_read += minimum;

	/* advance r_off should be zero if if len > chunk1*/
	cbuff->r_off = (cbuff->r_off + bytes_read) & (BUFFSIZE - 1);


	/* Read Wrap
	 *
	 * ---First copy_to_user
	 *
	 *  -chunk2-                -chhunk1-
	 *  ---------------------------------
	 *  | c | d |               | a | b |
	 *  --------^---------------^--------
	 *   	   w_off           r_off 
	 *
	 * ---Second copy_to_user
	 *
	 *  -chunk2-
	 *  ---------------------------------
	 *  | c | d |                       |
	 *  ^-------^------------------------
	 * r_off   w_off 
	 *
	 */

	if( len > bytes_read ){

		chunk2 = CIRC_CNT(cbuff->w_off,cbuff->r_off, BUFFSIZE);

		minimum = min( len - bytes_read, chunk2 ); 
		
		(void) copy_to_user(&buf[bytes_read], 
				(cbuff->start + cbuff->r_off), minimum);

		bytes_read += minimum;

		/* advance r_off */
		cbuff->r_off = (cbuff->r_off + minimum) & (BUFFSIZE - 1);

	}


/*****************************************************************************/
	up(&cbuff->sem);

	return bytes_read;
}

ssize_t crypto_write(struct file * filp, const char *buf, size_t len,
		     loff_t * off)
{

	CryptoHandle *chandle;
	CryptoBuffer *cbuff;

	size_t space1 = 0;
	size_t space2 = 0;
	size_t minimum = 0;
	size_t bytes_written = 0;

	chandle = (CryptoHandle *) filp->private_data;

	cbuff = chandle->buff;

	if( cbuff->writer != filp){
		/* not the writer to this file */
		return -EOPNOTSUPP;
	}

	/* down sem */
	(void) down_interruptible(&cbuff->sem);
/*****************************************************************************/

	space1 = CIRC_SPACE_TO_END( cbuff->w_off, cbuff->r_off, BUFFSIZE);

	minimum = min( len, space1 );

	(void) copy_from_user( (void*) (cbuff->start + cbuff->w_off), buf,
			minimum );

	bytes_written += minimum;

	/* advance w_off should be zero if if len > chunk1*/
	cbuff->w_off = (cbuff->w_off + bytes_written) & (BUFFSIZE - 1);

	if( len > bytes_written ){
	
		space2 = CIRC_SPACE(cbuff->w_off, cbuff->r_off, BUFFSIZE);
	
		minimum = min ( len - bytes_written , space2 );

		(void) copy_from_user( (void*) (cbuff->start + cbuff->w_off),
				&buf[bytes_written], minimum );

		bytes_written += minimum;

		/* advance w_off should be zero if if len > chunk1*/
		cbuff->w_off = (cbuff->w_off + minimum) & (BUFFSIZE - 1);
		
	}

/*****************************************************************************/

	/* up sem */
	up(&cbuff->sem);

	return bytes_written;
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

/* called to map a buffer of kernel memory (len 4096 or 8192) and return a
 * pointer to the beginning of that buffer.
 *
 * the vm_area_struct contains:
 * - "unsigned long vm_start;" start and end virtual addresses 
 * - "struct file *vm_file;" a pointer to the file struct associated with the
 *   area
 * - "unsigned long vm_pgoff;" the offset of the area in a file. 0 = start of
 *   file
 * - "unsigned long vm_page_prot;" RO/WO protection on the memory
 */

int crypto_mmap(struct file *filp, struct vm_area_struct *vma)
{
	
	CryptoHandle *chandle;
	CryptoBuffer *cbuff;
	size_t size;

	chandle = (CryptoHandle *) filp->private_data;

	cbuff = chandle->buff;
	
	/* check if flip passed through mmap() is attached to a buffer */
	if (cbuff == NULL) {
		/* the handle is not attached to any buffer */
		return -EOPNOTSUPP;
	}
	
	/* Set read only if write not explicitly declared */
	if(vma->vm_page_prot != PROT_WRITE) {
		vma->vm_page_prot = PROT_READ;
	}
	
	/* set start of address range to start of our buffer (assumes page 
	 * alignment)
	 */
	vma->vm_start = cbuff->start;
	vma->vm_end = 8192UL - vma->vm_pgoff;
	size = vma->vm_end - vma->vm_start;
	
	/* ready to map, do final check of size to ensure alignment*/
	if(size != 4096 || size != 8192) {
		return -EIO;
	}
	 
	 /* Build suitable page tables for the address range using
	  * remap_pfn_range 
	  */
	if (remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff, 
			size, vma->vm_page_prot)) {
		return -EAGAIN;
	}
	
	return 0;
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
