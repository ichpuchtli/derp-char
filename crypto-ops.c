#include "crypto-ops.h"


/* Internal Functions */
static int create_buffer(void);
static int delete_buffer(struct file* filp, unsigned int buffer_id);
static int attach_buffer(struct file* filp, unsigned int buffer_id);
static int detach_buffer(struct file* filp);
static int set_crypto_mode(struct file* filp, unsigned long arg);


/* Globals */
static struct list_head DEVICE_BUFFERS;
static unsigned int BUFFER_COUNT;


struct CryptoHandle {
	
	struct list_head node;
	struct crypto_smode mode;
	struct file* handle;
	struct BufferState* buff; 
};

struct BufferState {

        struct list_head node;
        struct file* reader; /* TODO struct CryptoHandle */
	struct file* writer;
	struct crypto_smode mode;
	struct semaphore sem;
        char* start;
	char* end;
	char* rp;
	char* wp;
        unsigned int id;
	unsigned int refcount;

};

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
static int create_buffer(void){

	struct BufferState* buffstate;

	/* allocate the "BufferState Structure */
	buffstate = kmalloc(sizeof(struct BufferState), GFP_KERNEL);

	if (buffstate == (void *) NULL) {
		printk(KERN_WARNING "crypto: kmalloc returned zero!\n");
		return -ENOMEM;
	}

	/* add buffer to list of buffers */
	list_add((struct list_head*) buffstate, &DEVICE_BUFFERS);	

	/* null reader/writer field */
	buffstate->reader = (struct file*) NULL;	
	buffstate->writer = (struct file*) NULL;	

	/* initialize semaphore */
	sema_init(&buffstate->sem, 1);

	/* allocate the buffer and map pointers */
	buffstate->start = kmalloc(8192,GFP_KERNEL);

	if (buffstate->start == (void *) NULL) {
		printk(KERN_WARNING "crypto: kmalloc returned zero!\n");
		return -ENOMEM;
	}

	buffstate->end = (char*) ((unsigned long) buffstate->start + 8192UL);

	buffstate->rp = buffstate->wp = buffstate->start;

	/* unique buffer id based on index into DEVICE_BUFFERS */
	buffstate->id = ++BUFFER_COUNT;

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
static int delete_buffer(struct file* filp, unsigned int buffer_id){


	/* walk through buffer list find appropriate buffer */
	struct list_head* curr = &DEVICE_BUFFERS;
	struct BufferState* buff = NULL;

	while( (curr = curr->next) != &DEVICE_BUFFERS){
	
		if( ((struct BufferState*) curr)->id == buffer_id ){

			buff = (struct BufferState*) curr;
		
			break;

		}

	}

	/* the buffer specified does not exist */
	if(buff == NULL){
		return -EINVAL;
	}
	
	/* down sem */

	/* buffer is not an open descriptor to the target */ 
	if( buff != (struct BufferState*) filp->private_data){
		return -EINVAL;
	}

	/* the buffer has another handle attached to it */
	if( buff->refcount > 1){
		return -EOPNOTSUPP;	
	}

	/* free buffer */

	return 0;

}

/* Returns one of:
 *     0 on success
 *     -EINVAL if the buffer specified does not exist
 *     -EOPNOTSUPP if the fd is already attached to a buffer
 *     -EALREADY if there is already a reader or writer attached
 *     -ENOMEM if no memory was available to satisfy the request
 */
static int attach_buffer(struct file* filp, unsigned int buffer_id){

	struct list_head* curr = &DEVICE_BUFFERS;
	struct BufferState* buff = NULL;

	/* down sem */

	/* the fd is already attached to a buffer */
	if( filp->private_data != NULL){
		return -EOPNOTSUPP;		
	}

	/* walk through buffer list find appropriate buffer */

	while( (curr = curr->next) != &DEVICE_BUFFERS){
	
		if( ((struct BufferState*) curr)->id == buffer_id ){

			buff = (struct BufferState*) curr;
			break;
		}
	}

	/* the buffer specified does not exist */
	if(buff == NULL){
		return -EINVAL;
	}

	if( IS_WRITER(filp->f_flags) ){
		
		/* there is already a reader|writer attached */
		if( buff->writer ){
			return -EALREADY;
		}

		buff->writer = filp;	

	}else if( IS_READER(filp->f_flags) ){
		
		/* there is already a reader|writer attached */
		if( buff->reader ){
			return -EALREADY;
		}

		buff->reader = filp;	

	}else if( IS_RDWR(filp->f_flags) ){

		/* there is already a reader|writer attached */
		if( buff->writer ){
			return -EALREADY;
		}

		buff->writer = filp;

		/* there is already a reader|writer attached */
		if( buff->reader ){
			return -EALREADY;
		}

		buff->reader = filp;

	}else{
		/* assume this case never happens */
	}

	filp->private_data = (void*) buff;

	buff->refcount++;

	/* up sem */

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

static int detach_buffer(struct file* filp){


	struct BufferState* buff;

	/* down sem */

	buff = (struct BufferState*) filp->private_data;

	/* the fd is not attached to any buffer */
	if( buff == NULL){
		return -EOPNOTSUPP;
	}

	if( buff->reader == filp){
		buff->reader = NULL;
		buff->refcount--;
	}

	if( buff->writer == filp){
		buff->writer = NULL;
		buff->refcount--;
	}


	if(buff->refcount == 0){
		/* free buffer */
	}

	filp->private_data = NULL;

	/* up sem */

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
static int set_crypto_mode(struct file* filp, unsigned long arg){


	struct crypto_smode mode;
	unsigned int count = 0;
	struct BufferState* buff;

	if( copy_from_user(&mode, (void*) arg, sizeof(struct crypto_smode))){
		return -EFAULT;
	}

	if( mode.dir != CRYPTO_READ || mode.dir != CRYPTO_WRITE){

		/* integrety error */
	}

	if(mode.mode != CRYPTO_DEC || mode.mode != CRYPTO_ENC || mode.mode
			!= CRYPTO_PASSTHROUGH ){

		/* integrety error */
	}


	while( mode.key[count] != '\0' && count < 255 ) { count++; }

	/* error key is not null terminated */	
	if( mode.key[count] != '\0' ){ }

	buff = (struct BufferState*) filp->private_data;

	/* TODO See IOCTL description: The fd does not have to be attached to
	 * a buffer for this call to work, since the encryption mode is a
	 * property of the file descriptor, not a buffer.
	 * Note: current implementation does not distinguish between buffer and
	 * file descriptor. May require something similar to the illustration
	 * below.
	 * 
	 * File                 -> CryptoHandle -> BufferState
	 *
	 * ----------------        --------        ------------
	 * | private_data-|------->| mode |        | sem      |
	 * | ...          |        | buff-|------->| rp,wp    |
	 * | ...          |        --------        | start    |
	 * ----------------                        | end      |
	 *                                         | id       |
	 *                                         | refcount |
	 *                                         ------------
	 */

	if( buff == NULL){ 
		return -EFAULT;	
	}

	buff->mode = mode;

	return 0;

}

int crypto_open(struct inode *inode, struct file *filp)
{
	/* increase the refcount of the open module */
	try_module_get(THIS_MODULE);

	/* check user has the permission they are requesting */
	return 0;
}

int crypto_release(struct inode *inode, struct file *filp)
{
	/* decrease the refcount of the open module */
	module_put(THIS_MODULE);

	/* detach_buffer */

	return 0;
}

ssize_t crypto_read(struct file * filp, char *buf, size_t len, loff_t * off)
{

	/* down sem */

	/* check filp is a reader */

	/* check mode for encryption */

	/* do crypt and copy to user space */

	/* update read/write pointers */
	
	/* up sem */

	return 0;
}

ssize_t crypto_write(struct file * filp, const char *buf, size_t len,
		     loff_t * off)
{
	
	/* down sem */
	
	/* check filp for attached buffer */

	/* check filp is a writer */
	
	/* check mode for encryption */

	/* copy from user space and do crypt */

	/* update read/write pointers */

	/* up sem */

	return 0;
}



int crypto_ioctl(struct inode *inode, struct file *filp, unsigned int cmd,
		 unsigned long arg)
{

	switch (cmd)
	{

		case CRYPTO_IOCCREATE:

			return create_buffer();

		case CRYPTO_IOCTDELETE:
			
			return delete_buffer(filp, (unsigned int) arg);

		case CRYPTO_IOCTATTACH:

			/* check permissions */
			/* i.e filp perm >= inode perm */	

			return attach_buffer(filp,(unsigned int) arg);

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
	/* Free all buffers */
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

