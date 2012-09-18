#include <linux/types.h>
#define u8 __u8
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <asm/errno.h>
#include <unistd.h>
#include "../ioctl.h"
#include <pthread.h>
#include <sys/ioctl.h>

void *read_thread(void *arg);
void *write_thread(void *arg);
void spawn_threads(FILE *fdIn, FILE *fdOut);

typedef struct {
	FILE *fpIn;
	FILE *fpOut;
}arg_struct;

//Global decs
volatile int threadEOFDetected = 0;
pthread_mutex_t running_mutex = PTHREAD_MUTEX_INITIALIZER;

int main(int argc, char *argv[]) {

	FILE *fpIn;
	FILE *fpOut;
	unsigned int readBuff, writeBuff;
	int ret_val; //used for error checking
	unsigned char *enc_key;

	if(argc == 2) {
		//first user
		enc_key = argv[1];
	} else {
		//second user
		enc_key = argv[4];
		readBuff = atoi(argv[3]);     //assign to read from second buffer
		writeBuff = atoi(argv[2]);	//assign to write to first buffer
	}

	struct crypto_smode readSt;
	readSt.dir = CRYPTO_READ;
	readSt.mode = CRYPTO_DEC;	//set to decrypt on read
	readSt.key = enc_key;	    //key from cmd line

	struct crypto_smode writeSt;
	writeSt.dir = CRYPTO_WRITE;
	writeSt.mode = CRYPTO_ENC;
	writeSt.key = enc_key;

	if((fpIn = fopen("/dev/crypto", "r")) == NULL) {
		fprintf(stderr, "failed to open read\n");
		return 0;
	}
	if((fpOut = fopen("/dev/crypto", "w")) == NULL) {
		fprintf(stderr, "failed to open write\n");
		return 0;
	}
	if(argc == 2) {
		//only set up buffers if first user
		if(readBuff = ioctl(fileno(fpIn), CRYPTO_IOCCREATE) < 1) {
			fprintf(stderr, "failed to set up read buffer\n");
			return 0;
		}
		if(writeBuff = ioctl(fileno(fpOut), CRYPTO_IOCCREATE) < 1) {
			fprintf(stderr, "failed to set up write buffer\n");
			return 0;
		}

		fprintf(stderr, "first_buffer_id: %d, second_buffer_id: %d\n", 
				readBuff, writeBuff);
	}
fprintf(stderr, "set up buffers\n");
	//after buffers have been assigned ID's, we now attach them
	ret_val = ioctl(fileno(fpIn), CRYPTO_IOCTATTACH, readBuff);
	if(ret_val == -EINVAL) {
		fprintf(stderr, "read buffer doesn't exist\n");
		return 0;
	} else if(ret_val == -EALREADY) {
		fprintf(stderr, "reader already attached\n");
		return 0;
	} else if(ret_val == -ENOMEM) {
		fprintf(stderr, "not enough memory\n");
		return 0;
	}

	ret_val = ioctl(fileno(fpOut), CRYPTO_IOCTATTACH, writeBuff);
	if(ret_val == -EINVAL) {
		fprintf(stderr, "write buffer doesn't exist\n");
		return 0;
	} else if(ret_val == -EALREADY) {
		fprintf(stderr, "writer already attached\n");
		return 0;
	} else if(ret_val == -ENOMEM) {
		fprintf(stderr, "not enough memory\n");
		return 0;
	}
fprintf(stderr, "attached buffers\n");
	//set read/write modes for fp's
	if(ioctl(fileno(fpIn), CRYPTO_IOCSMODE, &readSt) < 0) {
		fprintf(stderr, "failed to set read mode on buffer\n");
		return 0;
	}
	if(ioctl(fileno(fpOut), CRYPTO_IOCSMODE, &writeSt) < 0) {
		fprintf(stderr, "failed to set write mode on buffer\n");
		return 0;
	}

	//alrighty now start our IPC via the device driver
	spawn_threads(fpIn, fpOut);

	/* upon threads finishing close buffer references */

	//detach fd's from buffers so we can delete buffers
	ioctl(fileno(fpIn), CRYPTO_IOCDETACH);
	ioctl(fileno(fpOut), CRYPTO_IOCDETACH);

	//sweet, now we're detached. delete buffers.
	ret_val = ioctl(fileno(fpIn), CRYPTO_IOCTDELETE, readBuff);
	ret_val = ioctl(fileno(fpOut), CRYPTO_IOCTDELETE, writeBuff);

	fclose(fpIn);
	fclose(fpOut);

	return 0;

}

/*
 * Used to spawn off the reading and writing threads
 */
void spawn_threads (FILE *fpIn, FILE *fpOut) {

	pthread_t readThread;
	pthread_t writeThread;

	arg_struct args;
	args.fpIn = fpIn;
	args.fpOut = fpOut;

	pthread_create(&readThread, NULL, read_thread, (void*)&args);
	pthread_create(&writeThread, NULL, write_thread, (void*)&args);

	pthread_detach(readThread);
	pthread_detach(writeThread);
	
	while(!threadEOFDetected) {
		//avoid spinlock :)
		sleep(1);
	}
}

/*
 * Will read _from_ the device driver and write _to_ the user
 */
void* read_thread(void *arg) {

	arg_struct *args = arg;
	char *uOutput = (char *)malloc(1024 * sizeof(char));

	while(!feof(args->fpIn) && !threadEOFDetected) {
		fgets(uOutput, sizeof(uOutput), args->fpIn);

		//check if we ran out of space
		while(uOutput[strlen(uOutput)-1] != '\n') {
			//gimmie more space
			uOutput = (char *)realloc(uOutput, (((strlen(uOutput)) + 512) 
					* sizeof(char)));
			fgets(uOutput, sizeof(uOutput), args->fpIn);
		}
		fprintf(stdout, "%s", uOutput);
	}

	//alert other thread of EOF
	pthread_mutex_lock(&running_mutex);
	threadEOFDetected = 1;
	pthread_mutex_unlock(&running_mutex);

	pthread_exit(NULL);

}

/*
 * Will read _from_ the user and write _to_ the device driver
 */
void* write_thread(void *arg) {

	arg_struct *args = arg;
	char *uInput = (char *)malloc(1024 * sizeof(char));

	while(!feof(stdin) && !threadEOFDetected) {
		fgets(uInput, sizeof(uInput), stdin);

		//check if we ran out of space in array
		while(uInput[strlen(uInput)-1] != '\n') {
			//gimmie more space
			uInput = (char *)realloc(uInput, (((strlen(uInput)) + 512)
			        * sizeof(char)));
			fgets(uInput, sizeof(uInput), args->fpOut);
		}
		fprintf(args->fpOut, "%s", uInput);
	}
	//alert other thread of EOF
	pthread_mutex_lock(&running_mutex);
	threadEOFDetected = 1;
	pthread_mutex_unlock(&running_mutex);

	pthread_exit(NULL);

}
