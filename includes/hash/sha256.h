#ifndef  HAJCRYPT_SHA256_H
#define  HAJCRYPT_SHA256_H

#include <stddef.h>
#include <stdint.h>

/* SHA-256 context structure to hold state during hashing.
 * Contains:
 * - state: 8 32-bit words that hold the current hash state
 * - totalLen: total length of the input message in bits
 * - buffer: 512-bit (64-byte) block to hold input data before processing
 * - bufferLen: current length of data in the buffer
 * This structure is used internally by the SHA-256 implementation to maintain state across multiple calls to update
 */
typedef struct s_sha256Ctx {
	uint32_t state[8] __attribute__((aligned(4)));
	uint64_t totalLen;
	uint32_t bufferLen;
	uint8_t buffer[64] __attribute__((aligned(4)));
} t_sha256Ctx;

/**
 * @brief Initializes SHA-256 context with initial state constants.
 * The initial state is defined by the SHA-256 specification and consists of specific 32-bit values for each of the 8 state variables.
 * @param ctx - pointer to SHA-256 context structure to initialize
 */
void	sha256Init(void *ctx);

/**
 * @brief Updates the SHA-256 context with new input data.
 * This function can be called multiple times with chunks of the message to be hashed.
 * It processes 512-bit blocks of data and updates the internal state accordingly.
 * @param ctx - pointer to SHA-256 context structure to update
 * @param data - pointer to input data to hash
 * @param len - length of the input data in bytes
 */
void	sha256Update(void *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finalizes the SHA-256 hash computation and produces the final digest.
 * This function should be called after all input data has been processed with sha256Update.
 * It performs any necessary padding and appends the message length, then computes the final hash value.
 * @param digest - pointer to a buffer (at least 32 bytes) where the final 256-bit (32-byte) SHA-256 digest will be stored
 * @param ctx - pointer to SHA-256 context structure that has been updated with all input data
 */
void	sha256Final(uint8_t *digest, void *ctx);

void	sha256Transform(uint32_t *state, const uint8_t *data);

void	sha256Transform_arm64(uint32_t *state, const uint8_t *data);

void	sha256Transform_x86_64(uint32_t *state, const uint8_t *data);

#endif /* HAJCRYPT_SHA256_H */
