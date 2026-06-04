#ifndef HAJCRYPT_SHA384_H
#define HAJCRYPT_SHA384_H

#include "../hash.h"
#include "shaCommon.h"

/**
 * @brief SHA‑384 context structure
 *
 * Contains:
 * - state: 8 × 64‑bit words (h0..h7)
 * - totalLen: total message length in bytes
 * - bufferLen: number of bytes currently in buffer
 * - buffer: 128‑byte block buffer
 */
typedef struct s_sha384Ctx {
	uint64_t	state[8] __attribute__((aligned(16)));
	uint64_t	totalLen;
	size_t		bufferLen;
	uint8_t		buffer[SHA384_BLOCK_SIZE];
} t_sha384Ctx;

/**
 * @brief Initializes a SHA-384 hash context.
 *
 * Sets up the SHA-384 context structure with initial values required for
 * SHA-384 hashing operations. This function must be called before performing
 * any hash updates or finalization.
 *
 * @param ctx Pointer to the SHA-384 context structure to be initialized.
 *            The context must be allocated by the caller and have sufficient
 *            size to store SHA-384 state information.
 */
void	sha384Init(void *ctx);

/**
 * @brief Updates the SHA-384 hash context with new data.
 *
 * Processes the provided data and updates the internal state of the SHA-384
 * hash context. This function can be called multiple times to hash data
 * in chunks.
 *
 * @param ctx Pointer to the SHA-384 context structure to be updated.
 * @param data Pointer to the input data buffer to be hashed.
 * @param len Number of bytes in the data buffer to process.
 */
void	sha384Update(void *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finalizes SHA-384 hashing and produces the digest.
 *
 * Completes the SHA-384 hashing process and writes the final 384-bit (48-byte)
 * hash digest to the provided buffer. This function should be called after
 * all data has been processed with sha384Update().
 *
 * @param digest Pointer to a buffer where the 48-byte SHA-384 digest will be stored.
 *               Must be at least 48 bytes in size.
 * @param ctx    Pointer to the SHA-384 context structure initialized by sha384Init()
 *               and updated by sha384Update(). The context is finalized after this call.
 */
void	sha384Final(uint8_t *digest, void *ctx);

/**
 * @brief Computes the SHA-384 hash of the given data.
 *
 * @param data Pointer to the input data to be hashed.
 * @param len The length of the input data in bytes.
 * @param digest Pointer to a buffer where the computed SHA-384 hash will be stored.
 *               The buffer must be at least 48 bytes in size (SHA-384 produces a 384-bit hash).
 */
void	sha384Hash(const uint8_t *data, size_t len, uint8_t *digest);

extern const t_hash g_sha384Hash;

#endif /* HAJCRYPT_SHA384_H */
