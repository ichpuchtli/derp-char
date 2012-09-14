#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "../ioctl.h"
#include <pthread.h>

void *read_thread(void *arg);
void *write_thread(void *arg);
void spawn_threads(FILE * fdIn, FILE * fdOut);

typedef struct {
	FILE *fdIn;
	FILE *fdOut;
} arg_struct;

//Global decs
volatile int threadEOFDetected = 0;
pthread_mutex_t running_mutex = PTHREAD_MUTEX_INITIALIZER;

int main(int argc, char *argv[])
{

	FILE *fdIn;
	FILE *fdOut;
	int readBuff, writeBuff;
	int ret_val;		//used for error checking
	char enc_key[256];

	if (argc == 2) {
		//first user
		strcpy(enc_key, argv[1]);
	} else {
		//second user
		strcpy(enc_key, argv[4]);
		readBuff = atoi(argv[3]);	//assign to read from second buffer
		writeBuff = atoi(argv[2]);	//assign to write to first buffer
	}

	struct crypto_smode readSt;
	readSt.dir = CRYPTO_READ;
	readSt.mode = CRYPTO_DEC;	//set to decrypt on read
	readSt.key = argv[1];	//key from cmd line

	struct crypto_smode writeSt;
	writeSt.dir = CRYPTO_WRITE;
	writeSt.mode = CRYPTO_ENC;
	writeSt.key = argv[1];

	fdIn = fopen("/dev/crypto", "r");
	fdOut = fopen("/dev/crypto", "w");

	if (argc == 2) {
		//only set up buffers if first user
		if ((readBuff = ioctl(fdIn, CRYPTO_IOCREATE)) <= 0) {
			//error
			return 0;
		}
		if ((writeBuff = ioctl(fdOut, CRPYTO_IOCREATE)) <= 0) {
			//error
			return 0;
		}

		fprintf(stderr, "first_buffer_id: %d, second_buffer_id: %d\n",
			readBuff, writeBuff);
	}
	//after buffers have been assigned ID's, we now attach them
	ret_val = ioctl(fdIn, CRYPTO_IOCTATTACH, readBuff);
	if (ret_val == -EINVAL) {
		fprintf(stderr, "read buffer doesn't exist\n");
		return 0;
	} else if (ret_val == -EALREADY) {
		fprintf(stderr, "reader already attached\n");
		return 0;
	} else if (ret_val == -ENOMEM) {
		fprintf(stderr, "not enough memory\n");
		return 0;
	}

	ret_val = ioctl(fdOut, CRYPTO_IOCTATTACH, writeBuff);
	if (ret_val == -EINVAL) {
		fprintf(stderr, "write buffer doesn't exist\n");
		return 0;
	} else if (ret_val == -EALREADY) {
		fprintf(stderr, "writer already attached\n");
		return 0;
	} else if (ret_val == -ENOMEM) {
		fprintf(stderr, "not enough memory\n");
		return 0;
	}
	//set read/write modes for fd's
	if (ioctl(fdIn, CRYPTO_IOCSMODE, &readSt) < 0) {
		//error
		return 0;
	}
	if (ioctl(fdOut, CRYPTO_IOCSMODE, &writeSt) < 0) {
		//error
		return 0;
	}
	//alrighty now start our IPC via the device driver
	spawn_threads(fdIn, fdOut);

	/* upon threads finishing close buffer references */

	//detach fd's from buffers so we can delete buffers
	ioctl(fdIn, CRYPTO_IODETACH);
	ioctl(fdOut, CRYPTO_IODETACH);

	//sweet, now we're detached. delete buffers.
	ret_val = ioctl(fdIn, CRYPTO_IOCTDELETE, readBuff);
	ret_val = ioctl(fdOut, CRYPTO_IOCTDELETE, writeBuff);

	fclose(fdIn);
	fclose(fdOut);

	return 0;

}

/*
 * Used to spawn off the reading and writing threads
 */
void spawn_threads(FILE * fdIn, FILE * fdOut)
{

	pthread_t readThread;
	pthread_t writeThread;

	arg_struct args;
	args.fdIn = fdIn;
	args.fdOut = fdOut;

	pthread_create(&readThread, NULL, read_thread, (void *) &args);
	pthread_create(&writeThread, NULL, write_thread, (void *) &args);

	pthread_detach(readThread);
	pthread_detach(writeThread);

	while (!threadEOFDetected) {
		//avoid spinlock :)
		sleep(1);
	}
}

/*
 * Will read _from_ the device driver and write _to_ the user
 */
void *read_thread(void *arg)
{

	arg_struct *args = arg;
	char *uOutput = (char *) malloc(1024 * sizeof(char));

	while (!feof(args->fdIn) && !threadEOFDetected) {
		fgets(uOutput, sizeof(uOutput), args->fdIn);

		//check if we ran out of space
		while (uOutput[strlen(uOutput) - 1] != '\n') {
			//gimmie more space
			uOutput =
			    (char *) realloc(uOutput,
					     (((strlen(uOutput)) + 512)
					      * sizeof(char)));
			fgets(uOutput, sizeof(uOutput), args->fdIn);
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
void *write_thread(void *arg)
{

	arg_struct *args = arg;
	char *uInput = (char *) malloc(1024 * sizeof(char));

	while (!feof(stdin) && !threadEOFDetected) {
		fgets(uInput, sizeof(uInput), stdin);

		//check if we ran out of space in array
		while (uOutput[strlen(uOutput) - 1] != '\n') {
			//gimmie more space
			uOutput =
			    (char *) realloc(uOutput,
					     (((strlen(uOutput)) + 512)
					      * sizeof(char)));
			fgets(uOutput, sizeof(uOutput), args->fdIn);
		}
		fprintf(args->fdOut, "%s", uInput);
	}
	//alert other thread of EOF
	pthread_mutex_lock(&running_mutex);
	threadEOFDetected = 1;
	pthread_mutex_unlock(&running_mutex);

	pthread_exit(NULL);

}
