#ifndef HAJCRYPT_MD5_H
#define HAJCRYPT_MD5_H

#include <stdint.h>
#include <stddef.h>

#include "hash.h"

#define MD5_DIGEST_INFO_HEADER_LEN 18
#define MD5_DIGEST_LEN 16

extern const t_hash		g_md5Hash;
extern const uint8_t	g_md5DigestInfoHeader[];

/**
 * @brief MD5 context structure to hold state during hashing.
 * Contains:
 * - state: 4 32-bit words (A, B, C, D) that hold the current hash state
 * - bitlen: total length of the input message in bits
 * - buffer: 512-bit (64-byte) block to hold input data before processing
 * This structure is used internally by the MD5 implementation to maintain state across multiple calls to update
 */
typedef struct s_md5Ctx
{
	uint32_t	state[4] __attribute__((aligned(16))); /* A, B, C, D state variables */
	uint64_t	bitlen;		/* total message length in bits */
	uint8_t		buffer[64];	/* 512-bit message block */
}   t_md5Ctx;

/* ------------------------ core MD5 functions ------------------------ */

/**
 * @brief Initializes MD5 context with initial state constants.
 * The initial state is defined by the MD5 specification and consists of specific 32-bit values for A, B, C, D.
 * @param ctx - pointer to MD5 context structure to initialize
 */
void	md5Init(void *ctx);

/**
 * @brief Updates the MD5 context with new input data.
 * This function can be called multiple times with chunks of the message to be hashed.
 * It processes 512-bit blocks of data and updates the internal state accordingly.
 * @param ctx - pointer to MD5 context structure to update
 * @param data - pointer to input data to hash
 * @param len - length of the input data in bytes
 */
void	md5Update(void *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finalizes the MD5 hash computation and produces the final digest.
 * This function should be called after all input data has been processed with md5Update.
 * It performs any necessary padding and appends the message length, then computes the final hash value.
 * @param digest - pointer to a buffer (at least 16 bytes) where the final 128-bit (16-byte) MD5 digest will be stored
 * @param ctx - pointer to MD5 context structure that has been updated with all input data
 */
void	md5Final(uint8_t *digest, void *ctx);

/**
 * @brief Performs a md5 Hash of the input data in one step (initialization, update, finalization).
 * This is a convenience function for hashing data that is available all at once, without needing to manage the context manually.
 * @param data - pointer to input data to hash
 * @param len - length of the input data in bytes
 * @param digest - pointer to a buffer (at least 16 bytes) where the final MD5 digest will be stored
 */
void	md5Hash(const uint8_t *data, size_t len, uint8_t *digest);

/* Internal function to perform the MD5 transformation on a single 512-bit block.
 * This function is called by md5Update when a full block of data is ready to be processed.
 * It takes the current state (A, B, C, D) and the 512-bit block of input data, and updates the state according to the MD5 algorithm.
 * @param state - array of 4 uint32_t representing the current state (A, B, C, D)
 * @param block - 64-byte array containing the 512-bit block of input data to process
 */
void	md5Transform(uint32_t state[4], const uint8_t block[64]);

#endif /* HAJCRYPT_MD5_H */
