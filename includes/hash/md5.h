#ifndef HAJCRYPT_MD5_H
#define HAJCRYPT_MD5_H

#include <stdint.h>
#include <stddef.h>

#include "../../hajlib/include/hmath.h"

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
	uint32_t	state[4];	/* A, B, C, D */
	uint64_t	bitlen;		/* total message length in bits */
	uint8_t		buffer[64];	/* 512-bit message block */
}   t_md5Ctx;

/* ------------------------ core MD5 functions ------------------------ */

/**
 * @brief Initializes the MD5 context.
 * Sets state to initial values and clears buffer/bit length.
 */
void	md5Init(void *ctx);

/**
 * @brief Updates MD5 context with data chunk.
 * Can be called multiple times for streaming data.
 */
void	md5Update(void *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finalizes the MD5 digest.
 * Writes the resulting 16-byte hash to `digest`.
 */
void	md5Final(uint8_t *digest, void *ctx);

void	md5Transform(uint32_t state[4], const uint8_t block[64]);

#endif /* HAJCRYPT_MD5_H */
