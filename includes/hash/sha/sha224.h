#ifndef HAJCRYPT_SHA224_H
#define HAJCRYPT_SHA224_H

#include "../hash.h"
#include "shaCommon.h"

/**
 * @brief SHA‑224 context structure
 *
 * Contains:
 * - state: 8 × 32‑bit words (h0..h7)
 * - totalLen: total message length in bytes
 * - bufferLen: number of bytes currently in buffer
 * - buffer: 64‑byte block buffer
 */
typedef struct s_sha224Ctx {
	uint32_t	state[8] __attribute__((aligned(8)));
	uint64_t	totalLen;
	size_t		bufferLen;
	uint8_t		buffer[SHA224_BLOCK_SIZE];
} t_sha224Ctx;

/**
 * @brief Initializes a SHA-224 hash context.
 * 
 * Sets up the SHA-224 context structure with initial values required for
 * SHA-224 hashing operations. This function must be called before performing
 * any hash updates or finalization.
 * 
 * @param ctx Pointer to the SHA-224 context structure to be initialized.
 *            The context must be allocated by the caller and have sufficient
 *            size to store SHA-224 state information.
 */
void	sha224Init(void *ctx);

/**
 * @brief Updates the SHA-224 hash context with new data.
 * 
 * Processes the provided data and updates the internal state of the SHA-224
 * hash context. This function can be called multiple times to hash data
 * in chunks.
 * 
 * @param ctx Pointer to the SHA-224 context structure to be updated.
 * @param data Pointer to the input data buffer to be hashed.
 * @param len Number of bytes in the data buffer to process.
 */
void	sha224Update(void *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finalizes SHA-224 hashing and produces the digest.
 * 
 * Completes the SHA-224 hashing process and writes the final 224-bit (28-byte)
 * hash digest to the provided buffer. This function should be called after
 * all data has been processed with sha224Update().
 * 
 * @param digest Pointer to a buffer where the 28-byte SHA-224 digest will be stored.
 *               Must be at least 28 bytes in size.
 * @param ctx    Pointer to the SHA-224 context structure initialized by sha224Init()
 *               and updated by sha224Update(). The context is finalized after this call.
 */
void	sha224Final(uint8_t *digest, void *ctx);

/**
 * @brief Computes the SHA-224 hash of the given data.
 *
 * @param data Pointer to the input data to be hashed.
 * @param len The length of the input data in bytes.
 * @param digest Pointer to a buffer where the computed SHA-224 hash will be stored.
 *               The buffer must be at least 28 bytes in size (SHA-224 produces a 224-bit hash).
 */
void	sha224Hash(const uint8_t *data, size_t len, uint8_t *digest);

extern const t_hash g_sha224Hash;

#endif /* HAJCRYPT_SHA224_H */
