#ifndef _CRYPTODEV_API_H
#define _CRYPTODEV_API_H

/* cryptodev - An RC4 crypto coprocessor
 * Written by Sam Kingston <s.kingston@uq.edu.au>, July 2012
 *
 * This header file provides the API declarations for the cryptodev coprocessor.
 *
 * The coprocessor implements the RC4 alogorithm described in "RC4 Stream
 * Cipher and Its Variants" by Paul and Maitra, and can be used by any kernel
 * module for general purpose crypto operations.
 *
 * Any module wishing to make use of this coprocessor must be compiled against
 * the Modules.symvars file present in this directory. If you get undefined
 * symbol errors whilst compiling, you must adjust your Makefile to point to
 * this directory with the KBUILD_EXTMOD variable.
 *
 * To use the coprocessor, you must first initialise the state machine by
 * calling cryptodev_init() with a pointer to a state structure, the key to use
 * for crypto, and the length of the key.
 *
 * You may then call cryptodev_docrypt() with the initialised state structure
 * (`state`), the input string (`in`), the output string (`out`, which must be
 * pre-allocated), and the size of the output buffer (`buflen`). The device
 * will write no more bytes than specified by the `buflen` argument. This
 * function is used by both encryption (by passing plaintext as the `in`
 * argument), and decryption (by passing the ciphertext as the `in` argument).
 *
 * cryptodev_init() must be called whenever the stream changes (for instance in
 * between separate invocations of the device).
 *
 * The device will not free any pointers you pass it, so be sure to clean up
 * any allocated memory after finishing. You do not need to call a cleanup
 * function in the device itself, as all the state is stored in the state
 * structure given.
 *
 * If you read this far, monkeys!! That is all.
 */

/* struct cryptodev_state: stores the state of encryption/decryption */
struct cryptodev_state {
    u8 perm[256]; /* 255 ASCII characters + terminating NULL byte */
    u8 index1;
    u8 index2;
};

/* cryptodev_init(): initialise the state for encryption/decryption.
 *   Sets the key ready for crypto functions. The key (including terminating
 *   NULL byte) must be no larger than 256 bytes.
 */
extern void cryptodev_init(struct cryptodev_state *const state, const u8 *key, int keylen);

/* cryptodev_docrypt: general encryption/decryption function.
 *   Encrypts or decrypts the block given with the (pre-initialised) state
 *   structure and stores the result in `out`. This function will perform both
 *   encryption and decryption. Ensure that `buflen` is the size of the buffer
 *   pointed to by `out`, and the device will not write more bytes than this.
 */
extern void cryptodev_docrypt(struct cryptodev_state *const state, const u8 *in, u8 *out, int buflen);

#endif
