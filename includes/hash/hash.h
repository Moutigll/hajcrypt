#ifndef HAJCRYPT_HASH_H
#define HAJCRYPT_HASH_H

#include <stddef.h>
#include <stdint.h>

typedef struct paddParams
{
	size_t	blockSize;		/* Block size in bytes (64 for MD5/SHA-256) */
	int		isLittleEndian;	/* 1 if little-endian, 0 if big-endian */
	size_t	msgLen;			/* Original message length in bytes */
}   t_paddParams;

/**
 * @brief Pads the input message according to the specifications of the hash function.
 * This function takes an input message and pads it to ensure that its length is a multiple of the block size required by the hash function.
 * The padding scheme involves appending a '1' bit, followed by '0' bits, and finally appending the original message length in bits as a 64-bit integer. *
 * @param lastBlock - pointer to the last block of the original message
 * @param lastLen - length of the last block in bytes
 * @param params - pointer to a t_paddParams structure containing the block size, endianness, and original message length
 * @param newLen - pointer to a size_t variable where the length of the padded message will be stored
 * @return pointer to the newly allocated padded message, or NULL if memory allocation fails. The caller is responsible for freeing this memory.
 */
uint8_t *padMessage(const uint8_t	*lastBlock,
					size_t			lastLen,
					t_paddParams	*params,
					size_t			*newLen);

/**
 * @brief Loads a 32-bit word from a byte array, considering the specified endianness.
 * @param ptr - pointer to the byte array from which a 32-bit word will be loaded
 * @param isLittleEndian - flag indicating whether the byte order is little-endian (1) or big-endian (0)
 * @return the 32-bit word constructed from the byte array
 */
uint32_t loadWord32(const uint8_t *ptr, int isLittleEndian);

#endif	/* HAJCRYPT_HASH_H */
