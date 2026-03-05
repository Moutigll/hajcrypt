#ifndef HAJCRYPT_HASH_H
#define HAJCRYPT_HASH_H

#include <stddef.h>
#include <stdint.h>

#include "hmac.h"

/**
 * @struct s_hash
 * @brief Hash algorithm interface structure
 * 
 * Defines a hash algorithm implementation with function pointers for
 * initialization, updating, and finalization operations, along with
 * HMAC support and metadata about the hash algorithm.
 * 
 * @var s_hash::name
 *     Pointer to the null-terminated name of the hash algorithm (e.g., "SHA256")
 * 
 * @var s_hash::init
 *     Function pointer to initialize the hash context.
 *     @param ctx Pointer to the hash context structure
 * 
 * @var s_hash::update
 *     Function pointer to update the hash with data.
 *     @param ctx Pointer to the hash context structure
 *     @param data Pointer to the data to hash
 *     @param len Length of the data in bytes
 * 
 * @var s_hash::final
 *     Function pointer to finalize the hash and produce the digest.
 *     @param digest Pointer to buffer where the digest will be stored
 *     @param ctx Pointer to the hash context structure
 * 
 * @var s_hash::hmacInit
 *     Function pointer to initialize HMAC context with a key.
 *     @param ctx Pointer to the HMAC context structure
 *     @param key Pointer to the HMAC key
 *     @param keyLen Length of the key in bytes
 * 
 * @var s_hash::ctxSize
 *     Size in bytes of the hash context structure
 * 
 * @var s_hash::digestSize
 *     Size in bytes of the hash digest output
 */
typedef struct s_hash
{
	char	*name;
	void	(*init)(void *ctx);
	void	(*update)(void *ctx, const uint8_t *data, size_t len);
	void	(*final)(uint8_t *digest, void *ctx);
	void	(*hmacInit)(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen);
	size_t	ctxSize;
	size_t	digestSize;
}	t_hash;


typedef struct paddParams
{
	size_t	blockSize;			/* Block size in bytes (64 for MD5/SHA-256) */
	int		isLittleEndian;		/* 1 if little-endian, 0 if big-endian */
	size_t	msgLen;				/* Original message length in bytes */
	size_t	lengthFieldSize;	/* Size of the length field in bytes (8 for MD5/SHA-256), (32 for Whirlpool) */
}   t_paddParams;

/**
 * @brief Pads the input message according to the specifications of the hash function.
 * This function takes an input message and pads it to ensure that its length is a multiple of the block size required by the hash function.
 * The padding scheme involves appending a '1' bit, followed by '0' bits, and finally appending the original message length in bits as a 64-bit integer. *
 * @param dst - pointer to the destination buffer where the padded message will be stored
 * @param lastBlock - pointer to the last block of the original message
 * @param lastLen - length of the last block in bytes
 * @param params - pointer to a t_paddParams structure containing the block size, endianness, and original message length
 * @return the length of the padded message in bytes, or 0 if an error occurs
 */
size_t padMessage(uint8_t		*dst,
				  const uint8_t	*lastBlock,
				  size_t		lastLen,
				  t_paddParams	*params);

/**
 * @brief Loads a 32-bit word from a byte array, considering the specified endianness.
 * @param ptr - pointer to the byte array from which a 32-bit word will be loaded
 * @param isLittleEndian - flag indicating whether the byte order is little-endian (1) or big-endian (0)
 * @return the 32-bit word constructed from the byte array
 */
uint32_t loadWord32(const uint8_t *ptr, int isLittleEndian);

#endif	/* HAJCRYPT_HASH_H */
