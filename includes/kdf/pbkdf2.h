#ifndef HAJCRYPT_PBKDF2_H
#define HAJCRYPT_PBKDF2_H

#include "../hash/hash.h"

/**
 * @struct s_pbkdf2Ctx
 * @brief Contains all PBKDF2 parameters
 * 
 * This structure holds the fixed parameters for PBKDF2:
 * - hash: which algorithm to use
 * - pass: the password
 * - passLen: password length
 * - salt: the salt value
 * - saltLen: salt length
 * - iter: number of iterations
 */
typedef struct s_pbkdf2Ctx
{
	const t_hash	*hash;
	const uint8_t	*pass;
	size_t			passLen;
	const uint8_t	*salt;
	size_t			saltLen;
	uint32_t		iter;
}	t_pbkdf2Ctx;


/**
 * @brief Initialize a PBKDF2 context with the specified parameters.
 *
 * @param ctx Pointer to the PBKDF2 context structure to be initialized.
 * @param hash Pointer to the hash function structure to be used for derivation.
 * @param pass Pointer to the password buffer.
 * @param passLen Length of the password in bytes.
 * @param salt Pointer to the salt buffer.
 * @param saltLen Length of the salt in bytes.
 * @param iter Number of iterations to perform in the PBKDF2 algorithm.
 *
 * @return Returns 0 on success, or a non-zero error code on failure.
 */
int	pbkdf2Init(t_pbkdf2Ctx		*ctx,
			  const t_hash		*hash,
			  const uint8_t		*pass,
			  size_t			passLen,
			  const uint8_t		*salt,
			  size_t			saltLen,
			  uint32_t			iter);


/**
 * @brief Derives cryptographic key material using PBKDF2 algorithm
 * 
 * @param ctx Pointer to the PBKDF2 context containing configuration and parameters
 * @param out Pointer to output buffer where derived key material will be stored
 * @param outLen Length in bytes of the output buffer and derived key material to generate
 * 
 * @return 0 on success, non-zero error code on failure
 */
int	pbkdf2Derive(const t_pbkdf2Ctx	*ctx,
				 uint8_t			*out,
				 size_t				outLen);


/**
 * @brief Derives cryptographic key and initialization vector using PBKDF2.
 *
 * @param ctx Pointer to the PBKDF2 context containing algorithm parameters
 *            and configuration.
 * @param key Pointer to the buffer where the derived key will be stored.
 *            Must be allocated with at least keyLen bytes.
 * @param iv Pointer to the buffer where the derived initialization vector
 *           will be stored. Must be allocated with at least ivLen bytes.
 * @param keyLen The desired length of the derived key in bytes.
 * @param ivLen The desired length of the derived initialization vector in bytes.
 *
 * @return int Returns 0 on success, or a non-zero error code on failure.
 *
 * @note The caller is responsible for allocating sufficient memory for both
 *       key and iv buffers before calling this function.
 * @note The PBKDF2 context must be properly initialized before use.
 */
int	pbkdf2DeriveKeyIv(const t_pbkdf2Ctx	*ctx,
					  uint8_t			*key,
					  uint8_t			*iv,
					  size_t			keyLen,
					  size_t			ivLen);

#endif
