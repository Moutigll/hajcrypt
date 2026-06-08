#ifndef HAJCRYPT_HMAC_H
#define HAJCRYPT_HMAC_H

#include "md5.h"
#include "sha.h"
#include "whirlpool.h"

typedef union u_hashMaxCtx
{
	t_md5Ctx		md5;
	t_sha1Ctx		sha1;
	t_sha224Ctx		sha224;
	t_sha256Ctx		sha256;
	t_sha384Ctx		sha384;
	t_sha512Ctx		sha512;
	t_sha512_224Ctx	sha512_224;
	t_sha512_256Ctx	sha512_256;
	t_whirlpoolCtx	whirlpool;
}	t_hashMaxCtx;

#define HASH_MAX_CTX_SIZE	sizeof(t_hashMaxCtx)

typedef struct s_hmacCtx
{
	const t_hash	*algo;
	uint8_t			innerCtx[HASH_MAX_CTX_SIZE] __attribute__((aligned(16)));
	uint8_t			outerCtx[HASH_MAX_CTX_SIZE] __attribute__((aligned(16)));
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
				  const t_hash		*algo,
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

/**
 * @brief Performs an HMAC computation in a single step using the specified algorithm, key, and data.
 *
 * @param algo Pointer to the hash algorithm to use for HMAC operations.
 * @param key Pointer to the key bytes used for HMAC computation.
 * @param keyLen Length of the key in bytes.
 * @param data Pointer to the input data to be authenticated.
 * @param dataLen Length of the input data in bytes.
 * @param out Pointer to a buffer where the computed HMAC digest will be stored.
 * @return void
 */
void	hmac(const t_hash		*algo,
			 const uint8_t		*key,	size_t	keyLen,
			 const uint8_t		*data,	size_t	dataLen,
			 uint8_t			*out);

/* ------------------ Convenience HMAC functions for specific algorithms ------------------ */

/**
 * @brief Initializes an HMAC context for SHA-1 using the provided key.
 *
 * @param ctx Pointer to the HMAC context structure to initialize.
 * @param key Pointer to the key bytes used for HMAC computation.
 * @param keyLen Length of the key in bytes.
 * @return void
 */
void	sha1HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen);

/**
 * @brief Initializes an HMAC context for SHA-224 using the provided key.
 *
 * @param ctx Pointer to the HMAC context structure to initialize.
 * @param key Pointer to the key bytes used for HMAC computation.
 * @param keyLen Length of the key in bytes.
 * @return void
 */
void	sha224HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen);

/**
 * @brief Initializes an HMAC context for SHA-256 using the provided key.
 *
 * @param ctx Pointer to the HMAC context structure to initialize.
 * @param key Pointer to the key bytes used for HMAC computation.
 * @param keyLen Length of the key in bytes.
 *
 * @return void
 */
void	sha256HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen);

/**
 * @brief Initializes an HMAC context for SHA-384 using the provided key.
 *
 * @param ctx Pointer to the HMAC context structure to initialize.
 * @param key Pointer to the key bytes used for HMAC computation.
 * @param keyLen Length of the key in bytes.
 *
 * @return void
 */
void	sha384HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen);

/**
 * @brief Initializes an HMAC context for SHA-512 using the provided key.
 *
 * @param ctx Pointer to the HMAC context structure to initialize.
 * @param key Pointer to the key bytes used for HMAC computation.
 * @param keyLen Length of the key in bytes.
 *
 * @return void
 */
void	sha512HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen);

/**
 * @brief Initializes an HMAC context for SHA-512/224 using the provided key.
 *
 * @param ctx Pointer to the HMAC context structure to initialize.
 * @param key Pointer to the key bytes used for HMAC computation.
 * @param keyLen Length of the key in bytes.
 *
 * @return void
 */
void	sha512_224HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen);

/**
 * @brief Initializes an HMAC context for SHA-512/256 using the provided key.
 *
 * @param ctx Pointer to the HMAC context structure to initialize.
 * @param key Pointer to the key bytes used for HMAC computation.
 * @param keyLen Length of the key in bytes.
 *
 * @return void
 */
void	sha512_256HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen);

/**
 * @brief Initializes an HMAC context for MD5 using the provided key.
 *
 * @param ctx Pointer to the HMAC context structure to initialize.
 * @param key Pointer to the key bytes used for HMAC computation.
 * @param keyLen Length of the key in bytes.
 *
 * @return void
 */
void	md5HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen);

/**
 * @brief Initializes an HMAC context for Whirlpool using the provided key.
 *
 * @param ctx Pointer to the HMAC context structure to initialize.
 * @param key Pointer to the key bytes used for HMAC computation.
 * @param keyLen Length of the key in bytes.
 *
 * @return void
 */
void	whirlpoolHmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen);

#endif /* HAJCRYPT_HMAC_H */
