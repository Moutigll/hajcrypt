#ifndef HAJCRYPT_HMAC_H
#define HAJCRYPT_HMAC_H

#include <stddef.h>
#include <stdint.h>

#define HASH_MAX_CTX_SIZE 256

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
	uint8_t		  innerCtx[HASH_MAX_CTX_SIZE] __attribute__((aligned(16)));
	uint8_t		  outerCtx[HASH_MAX_CTX_SIZE] __attribute__((aligned(16)));
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
 * @note To update you can simply do ```ctx->algo->hashUpdate(ctx->innerCtx, data, dataLen)```
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
void	hmac(const t_hashAlgo	*algo,
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

extern const t_hashAlgo	g_sha1Algo;
extern const t_hashAlgo	g_sha224Algo;
extern const t_hashAlgo	g_sha256Algo;
extern const t_hashAlgo	g_sha384Algo;
extern const t_hashAlgo	g_sha512Algo;
extern const t_hashAlgo	g_sha512_224Algo;
extern const t_hashAlgo	g_sha512_256Algo;
extern const t_hashAlgo	g_md5Algo;
extern const t_hashAlgo	g_whirlpoolAlgo;



/* --------------- HMAC_DRBG ---------------  */



# define HMAC_DRBG_MAX_OUTPUT		64
# define HMAC_DRBG_MAX_REQUEST		65536	/* Max bytes per generate call (2^16) */
# define HMAC_DRBG_RESEED_INTERVAL	10000	/* Reseed after this many generate calls */

/**
 * @brief HMAC_DRBG context structure
 *
 * This structure holds the state for a deterministic random bit generator
 * based on HMAC as defined in NIST SP 800-90A Rev. 1.
 */
typedef struct s_hmacDrbg
{
	uint8_t				K[64];			/* Key of length hashLen */
	uint8_t				V[64];			/* Value of length hashLen */
	const t_hashAlgo	*hash;			/* Hash algorithm for HMAC */
	size_t				hashLen;		/* Length of hash output in bytes */
	uint64_t			reseedCounter;	/* Number of generate calls since last reseed */
}	t_hmacDrbg;

/**
 * @brief Update the DRBG internal state (HMAC_DRBG_Update)
 *
 * This function updates the internal state (K, V) using the provided data.
 * It follows the specification: K = HMAC(K, V || 0x00 || data) followed
 * by V = HMAC(K, V), and optionally repeated with 0x01 if data is not NULL.
 *
 * @param drbg		DRBG context
 * @param data		Additional data to mix into the state (may be NULL)
 * @param dataLen	Length of the data in bytes
 */
void	hmacDrbgUpdate(t_hmacDrbg *drbg, const uint8_t *data, size_t dataLen);

/**
 * @brief Reseed the DRBG (HMAC_DRBG_Reseed)
 *
 * This function reseeds the DRBG with fresh entropy and optional
 * additional input. The entropy must come from a trusted source
 * and meet the security strength requirements.
 *
 * @param drbg			DRBG context
 * @param entropy		Fresh entropy input
 * @param entropyLen	Length of entropy in bytes
 * @param additional	Additional input (may be NULL)
 * @param additionalLen	Length of additional input in bytes
 */
void	hmacDrbgReseed(t_hmacDrbg	*drbg,
					  const uint8_t	*entropy,		size_t	entropyLen,
					  const uint8_t	*additional,	size_t	additionalLen);

/**
 * @brief Generate pseudorandom output (HMAC_DRBG_Generate)
 *
 * This function produces a requested number of pseudorandom bytes.
 * Returns 0 if outLen exceeds HMAC_DRBG_MAX_REQUEST or if reseed
 * is required (caller must reseed first).
 *
 * @param drbg		DRBG context
 * @param out		Output buffer for random bytes
 * @param outLen	Number of bytes to generate
 * @return			1 on success, 0 on error
 */
int	hmacDrbgGenerate(t_hmacDrbg *drbg, uint8_t *out, size_t outLen);

/**
 * @brief Initialise the DRBG (HMAC_DRBG_Instantiate)
 *
 * This function initialises a new HMAC_DRBG instance with entropy,
 * a nonce, and optional personalisation string.
 *
 * @param drbg		DRBG context to initialise
 * @param hash		Hash algorithm for HMAC
 * @param entropy	Entropy input (must be at least security_strength bits)
 * @param entropyLen	Length of entropy in bytes
 * @param nonce		Nonce (at least 1/2 security_strength bits)
 * @param nonceLen	Length of nonce in bytes
 * @param personal	Personalisation string (may be NULL)
 * @param personalLen	Length of personalisation string in bytes
 * @return			1 on success, 0 on error
 */
int	hmacDrbgInit(t_hmacDrbg		*drbg,		const t_hashAlgo	*hash,
				 const uint8_t	*entropy,	size_t				entropyLen,
				 const uint8_t	*nonce,		size_t				nonceLen,
				 const uint8_t	*personal,	size_t				personalLen);

#endif /* HAJCRYPT_HMAC_H */
