#ifndef HAJCRYPT_SHA1_H
#define HAJCRYPT_SHA1_H

#include "../hash.h"
#include "shaCommon.h"

/**
 * @brief SHA‑1 context structure
 *
 * Contains:
 * - state: 5 × 32‑bit words (h0..h4)
 * - totalLen: total message length in bytes
 * - bufferLen: number of bytes currently in buffer
 * - buffer: 64‑byte block buffer
 */
typedef struct s_sha1Ctx {
	uint32_t	state[5] __attribute__((aligned(8)));
	uint64_t	totalLen;
	size_t		bufferLen;
	uint8_t		buffer[SHA1_BLOCK_SIZE];
} t_sha1Ctx;

/**
 * @brief Initializes a SHA-1 hash context.
 * 
 * Sets up the SHA-1 context structure with initial values required for
 * SHA-1 hashing operations. This function must be called before performing
 * any hash updates or finalization.
 * 
 * @param ctx Pointer to the SHA-1 context structure to be initialized.
 *            The context must be allocated by the caller and have sufficient
 *            size to store SHA-1 state information.
 */
void	sha1Init(void *ctx);

/**
 * @brief Updates the SHA-1 hash context with new data.
 * 
 * Processes the provided data and updates the internal state of the SHA-1
 * hash context. This function can be called multiple times to hash data
 * in chunks.
 * 
 * @param ctx Pointer to the SHA-1 context structure to be updated.
 * @param data Pointer to the input data buffer to be hashed.
 * @param len Number of bytes in the data buffer to process.
 */
void	sha1Update(void *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finalizes SHA-1 hashing and produces the digest.
 * 
 * Completes the SHA-1 hashing process and writes the final 160-bit (20-byte)
 * hash digest to the provided buffer. This function should be called after
 * all data has been processed with sha1Update().
 * 
 * @param digest Pointer to a buffer where the 20-byte SHA-1 digest will be stored.
 *               Must be at least 20 bytes in size.
 * @param ctx    Pointer to the SHA-1 context structure initialized by sha1Init()
 *               and updated by sha1Update(). The context is finalized after this call.
 */
void	sha1Final(uint8_t *digest, void *ctx);

/**
 * @brief Computes the SHA-1 hash of the given data.
 *
 * @param data Pointer to the input data to be hashed.
 * @param len The length of the input data in bytes.
 * @param digest Pointer to a buffer where the computed SHA-1 hash will be stored.
 *               The buffer must be at least 20 bytes in size (SHA-1 produces a 160-bit hash).
 */
void	sha1Hash(const uint8_t *data, size_t len, uint8_t *digest);

extern const t_hash		g_sha1Hash;
extern const uint8_t	g_sha1DigestInfoHeader[];

#endif /* HAJCRYPT_SHA1_H */
