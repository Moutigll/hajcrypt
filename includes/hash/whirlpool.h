#ifndef HAJCRYPT_WHIRLPOOL_H
#define HAJCRYPT_WHIRLPOOL_H

#include <stdint.h>
#include <stddef.h>

#include "hash.h"

/* Whirlpool polynomial for GF(2^8): x^8 + x^4 + x^3 + x^2 + 1 (0x11D) */
#define WHIRLPOOL_POLY 0x11D

extern const t_hash g_whirlpoolHash;

/* Whirlpool context structure to hold state during hashing.
 * Contains:
 * - state: 512-bit (64-byte) array that holds the current hash state
 * - totalLen: total length of the input message in bits
 * - buffer: 512-bit (64-byte) block to hold input data before processing
 * - bufferLen: current length of data in the buffer
 * This structure is used internally by the Whirlpool implementation to maintain state across multiple calls to update
 */
typedef struct s_whirlpoolCtx {
	uint64_t state[8] __attribute__((aligned(8)));	// 8 × 64 bits = 64 octets
	uint64_t totalLen;								// Length of the message in bits
	uint8_t buffer[64] __attribute__((aligned(8)));
	size_t bufferLen;								// Number of bytes currently in the buffer
} t_whirlpoolCtx;

/**
 * @brief Initializes Whirlpool context with initial state constants.
 * The initial state is defined by the Whirlpool specification and consists of specific 512-bit values for
 * @param ctx - pointer to Whirlpool context structure to initialize
 */
void whirlpoolInit(void *ctx);

/**
 * @brief Updates the Whirlpool context with new input data.
 * This function can be called multiple times with chunks of the message to be hashed.
 * It processes 512-bit blocks of data and updates the internal state accordingly.
 * @param ctx - pointer to Whirlpool context structure to update
 * @param data - pointer to input data to hash
 * @param len - length of the input data in bytes
 */
void whirlpoolUpdate(void *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finalizes the Whirlpool hash computation and produces the final digest.
 * This function should be called after all input data has been processed with whirlpoolUpdate.
 * It performs any necessary padding and appends the message length, then computes the final hash value.
 * @param digest - pointer to a buffer (at least 64 bytes) where the final 512-bit (64-byte) Whirlpool digest will be stored
 * @param ctx - pointer to Whirlpool context structure that has been updated with all input data
 */
void whirlpoolFinal(uint8_t *digest, void *ctx);

/**
 * @brief Perfoms a Whirlpool Hash of the input data in one step (initialization, update, finalization).
 * This is a convenience function for hashing data that is available all at once, without needing to manage the context manually.
 * @param data - pointer to input data to hash
 * @param len - length of the input data in bytes
 * @param digest - pointer to a buffer (at least 64 bytes) where the final Whirlpool digest will be stored
 */
 void whirlpoolHash(const uint8_t *data, size_t len, uint8_t *digest);

/**
 * @brief Performs a single Whirlpool transformation on a 512-bit state using a 512-bit block.
 * This function is used internally by the Whirlpool implementation to process input data blocks.
 * @param state - pointer to the 512-bit (8 × 64-bit) state array to be transformed
 * @param block - pointer to the 512-bit (64-byte) input block to be processed
 */
void whirlpoolTransform(uint64_t *state, const uint8_t *block);

/**
 * @brief Optimized version of the Whirlpool transformation using T-tables.
 * This function is an optimized implementation of the Whirlpool transformation that uses precomputed T-tables
 * to combine the SubBytes, ShiftColumns, and MixRows steps into efficient table lookups and XOR operations.
 * It is used internally by the Whirlpool implementation to process input data blocks more efficiently.
 * @param H - pointer to the 512-bit (8 × 64-bit) state array to be transformed
 * @param block - pointer to the 512-bit (64-byte) input block to be processed
 */
void whirlpoolTransformOpt(uint64_t *H, const uint8_t *block);

#endif /* HAJCRYPT_WHIRLPOOL_H */
