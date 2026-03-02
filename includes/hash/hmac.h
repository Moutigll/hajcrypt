#ifndef HAJCRYPT_HMAC_H
#define HAJCRYPT_HMAC_H

#include <stddef.h>
#include <stdint.h>

#include "whirlpool.h"

#define HASH_MAX_CTX_SIZE sizeof(t_whirlpoolCtx)

/**
 * @struct s_hashAlgo
 * @brief Structure defining the interface and metadata for a hash algorithm
 *
 * This structure encapsulates the function pointers and configuration parameters
 * needed to implement a generic hash algorithm. It allows for abstraction over
 * different hash algorithms (SHA-256, MD5, etc.) through a common interface.
 *
 * @member hashInit
 *		Function pointer to initialize the hash context.
 *		@param ctx Pointer to the hash algorithm context structure
 *
 * @member hashUpdate
 *		Function pointer to update the hash with input data.
 *		@param ctx Pointer to the hash algorithm context structure
 *		@param data Pointer to the input data to hash
 *		@param len Number of bytes to process from data
 *
 * @member hashFinal
 *		Function pointer to finalize the hash and retrieve the digest.
 *		@param digest Pointer to buffer where the final hash digest will be written
 *		@param ctx Pointer to the hash algorithm context structure
 *
 * @member blockSize
 *		The block size (in bytes) of the hash algorithm's internal processing unit
 *
 * @member digestSize
 *		The output digest size (in bytes) produced by the hash algorithm
 *
 * @member ctxSize
 *		The size (in bytes) of the context structure required by the algorithm
 */
typedef struct s_hashAlgo
{
	void	(*hashInit)(void *ctx);
	void	(*hashUpdate)(void *ctx, const uint8_t *data, size_t len);
	void	(*hashFinal)(uint8_t *digest, void *ctx);
	size_t	blockSize;
	size_t	digestSize;
	size_t	ctxSize;
}	t_hashAlgo;

typedef struct s_hmacCtx
{
	const t_hashAlgo *algo;
	uint8_t		  innerCtx[HASH_MAX_CTX_SIZE];
	uint8_t		  outerCtx[HASH_MAX_CTX_SIZE];
}   t_hmacCtx;


/**
 * @brief Initializes an HMAC context with the specified algorithm and key.
 *
 * @param ctx Pointer to the HMAC context structure to initialize.
 * @param algo Pointer to the hash algorithm to use for HMAC operations.
 * @param key Pointer to the key bytes used for HMAC computation.
 * @param keyLen Length of the key in bytes.
 *
 * @return void
 *
 * @note The context must be allocated before calling this function.
 * @note The key and algorithm pointers must remain valid for the lifetime
 *			of the context or until it is reinitialized.
 */
void	hmacInit(t_hmacCtx			*ctx,
			  const t_hashAlgo	*algo,
			  const uint8_t		*key,
			  size_t			keyLen);

/**
 * @brief Finalizes the HMAC computation and retrieves the message authentication code
 * 
 * @param ctx Pointer to the HMAC context containing the state of the HMAC computation
 * @param digest Pointer to a buffer where the computed HMAC digest will be stored
 * 
 * @return void
 * 
 * @note The caller is responsible for allocating sufficient memory for the digest buffer.
 *		 The size should match the underlying hash algorithm's output size.
 * 
 * @see hmacInit, hmacUpdate
 */
void	hmacFinal(t_hmacCtx *ctx, uint8_t *digest);

/* ------------------ Convenience HMAC functions for specific algorithms ------------------ */

/** * @brief Initializes an HMAC context for SHA-256 using the provided key.
 *
 * @param ctx Pointer to the HMAC context structure to initialize.
 * @param key Pointer to the key bytes used for HMAC computation.
 * @param keyLen Length of the key in bytes.
 *
 * @return void
 */
void	sha256HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen);

/** * @brief Initializes an HMAC context for MD5 using the provided key.
 *
 * @param ctx Pointer to the HMAC context structure to initialize.
 * @param key Pointer to the key bytes used for HMAC computation.
 * @param keyLen Length of the key in bytes.
 *
 * @return void
 */
void	md5HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen);

/** * @brief Initializes an HMAC context for Whirlpool using the provided key.
 *
 * @param ctx Pointer to the HMAC context structure to initialize.
 * @param key Pointer to the key bytes used for HMAC computation.
 * @param keyLen Length of the key in bytes.
 *
 * @return void
 */
void	whirlpoolHmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen);

#endif /* HAJCRYPT_HMAC_H */
