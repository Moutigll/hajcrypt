#ifndef HAJCRYPT_SHA256_H
#define HAJCRYPT_SHA256_H

#include "../hash.h"
#include "shaCommon.h"

/**
 * @brief SHA‑256 context structure
 *
 * Contains:
 * - state: 8 × 32‑bit words (h0..h7)
 * - totalLen: total message length in bytes
 * - bufferLen: number of bytes currently in buffer
 * - buffer: 64‑byte block buffer
 */
typedef struct s_sha256Ctx {
	uint32_t	state[8] __attribute__((aligned(8)));
	uint64_t	totalLen;
	size_t		bufferLen;
	uint8_t		buffer[SHA256_BLOCK_SIZE];
} t_sha256Ctx;

/**
 * @brief Initializes a SHA-256 hash context.
 *
 * Sets up the SHA-256 context structure with initial values required for
 * SHA-256 hashing operations. This function must be called before performing
 * any hash updates or finalization.
 *
 * @param ctx Pointer to the SHA-256 context structure to be initialized.
 *            The context must be allocated by the caller and have sufficient
 *            size to store SHA-256 state information.
 */
void	sha256Init(void *ctx);

/**
 * @brief Updates the SHA-256 hash context with new data.
 *
 * Processes the provided data and updates the internal state of the SHA-256
 * hash context. This function can be called multiple times to hash data
 * in chunks.
 *
 * @param ctx Pointer to the SHA-256 context structure to be updated.
 * @param data Pointer to the input data buffer to be hashed.
 * @param len Number of bytes in the data buffer to process.
 */
void	sha256Update(void *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finalizes SHA-256 hashing and produces the digest.
 *
 * Completes the SHA-256 hashing process and writes the final 256-bit (32-byte)
 * hash digest to the provided buffer. This function should be called after
 * all data has been processed with sha256Update().
 *
 * @param digest Pointer to a buffer where the 32-byte SHA-256 digest will be stored.
 *               Must be at least 32 bytes in size.
 * @param ctx    Pointer to the SHA-256 context structure initialized by sha256Init()
 *               and updated by sha256Update(). The context is finalized after this call.
 */
void	sha256Final(uint8_t *digest, void *ctx);

/**
 * @brief Computes the SHA-256 hash of the given data.
 *
 * @param data Pointer to the input data to be hashed.
 * @param len The length of the input data in bytes.
 * @param digest Pointer to a buffer where the computed SHA-256 hash will be stored.
 *               The buffer must be at least 32 bytes in size (SHA-256 produces a 256-bit hash).
 */
void	sha256Hash(const uint8_t *data, size_t len, uint8_t *digest);

extern const t_hash		g_sha256Hash;
extern const uint8_t	g_sha256DigestInfoHeader[];

#endif /* HAJCRYPT_SHA256_H */
