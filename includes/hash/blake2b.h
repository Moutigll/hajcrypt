#ifndef HAJCRYPT_BLAKE2B_H
#define HAJCRYPT_BLAKE2B_H

#include <stddef.h>
#include <stdint.h>

#include "hash.h"

#define BLAKE2B_BLOCK_SIZE 128
#define BLAKE2B_DIGEST_SIZE 64
#define BLAKE2B_KEY_SIZE 64

extern const t_hash g_blake2bHash;

/**
 * @brief Blake2b context structure
 * 
 * Contains:
 * - h: 8 64-bit words that hold the current hash state
 * - t: total length counter (2 words for 128-bit counter)
 * - f: last block flag
 * - buffer: 128-byte block buffer
 * - buflen: current length in buffer
 * - outlen: desired output length (1-64)
 */
typedef struct s_blake2bCtx {
	uint64_t h[8] __attribute__((aligned(8)));
	uint64_t t[2];
	uint8_t  f;
	uint8_t  buffer[BLAKE2B_BLOCK_SIZE] __attribute__((aligned(8)));
	size_t   buflen;
	size_t   outlen;
} t_blake2bCtx;

/**
 * @brief Initialize Blake2b context with default parameters
 * 
 * @param ctx Pointer to context structure
 * @param outlen Desired output length in bytes (1-64)
 */
void	blake2bInit(void *ctx);

void	blake2bSetOutlen(void *ctx, size_t outlen);

/**
 * @brief Initialize Blake2b context with key (for MAC)
 * 
 * @param ctx Pointer to context structure
 * @param key Key bytes
 * @param keyLen Key length (0-64)
 * @param outlen Desired output length
 */
void	blake2bInitKeyed(void *ctx, const uint8_t *key, size_t keyLen, size_t outlen);

/**
 * @brief Update Blake2b context with new data
 * 
 * @param ctx Pointer to context
 * @param data Input data
 * @param len Data length
 */
void	blake2bUpdate(void *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finalize Blake2b and produce digest
 * 
 * @param digest Output buffer (must be at least outlen bytes)
 * @param ctx Pointer to context
 */
void	blake2bFinal(uint8_t *digest, void *ctx);

/**
 * @brief One-shot Blake2b hash
 * 
 * @param data Input data
 * @param datalen Data length
 * @param digest Output buffer
 * @param digestlen Desired output length
 */
void	blake2b(const uint8_t *data, size_t datalen, uint8_t *digest, size_t digestlen);

/**
 * @brief One-shot Blake2b MAC
 * 
 * @param key Key bytes
 * @param keyLen Key length
 * @param data Input data
 * @param datalen Data length
 * @param digest Output buffer
 * @param digestlen Desired output length
 */
void	blake2bMac(const uint8_t	*key,
				   size_t			keyLen,
				  const uint8_t		*data,
				  size_t			datalen,
				  uint8_t			*digest,
				  size_t			digestlen);

void	blake2bCompress(t_blake2bCtx *ctx, const uint8_t *block);

#endif /* HAJCRYPT_BLAKE2B_H */
