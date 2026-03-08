#ifndef HAJCRYPT_BLOWFISH_H
#define HAJCRYPT_BLOWFISH_H

#include <stddef.h>
#include <stdint.h>

#include "cipher.h"

#define BLOWFISH_BLOCK_SIZE			8
#define BLOWFISH_MIN_KEY_SIZE		4	/* 32 bits */
#define BLOWFISH_MAX_KEY_SIZE		56	/* 448 bits */
#define BLOWFISH_DEFAULT_KEY_SIZE	16	/* 128 bits */
#define BLOWFISH_IV_SIZE			8

/**
 * @brief Blowfish ECB (Electronic Codebook) context structure.
 * 
 * Maintains state for Blowfish encryption/decryption in ECB mode.
 * ECB mode processes each block independently.
 * 
 * Contains the expanded key schedule (P-array and S-boxes) as defined
 * by the Blowfish specification, plus buffering for partial blocks.
 */
typedef struct s_blowfishEcbCtx
{
	uint32_t			P[18];			/* 18 P-array subkeys */
	uint32_t			S[4][256];		/* 4 S-boxes of 256 entries each */
	uint8_t				buffer[8];		/* Buffer for partial block */
	size_t				bufferLen;		/* Number of bytes in buffer */
	t_cipherDirection	dir;			/* Encryption or decryption mode */
}	t_blowfishEcbCtx;

/* ---------- Core Blowfish operations ---------- */

/**
 * @brief Initializes the Blowfish key schedule from a variable-length key.
 *
 * Blowfish accepts keys from 32 to 448 bits (4 to 56 bytes).
 * The key is used to initialize the P-array and S-boxes through the
 * key expansion process defined in the Blowfish specification.
 * 
 * @param ctx Pointer to Blowfish context containing P and S arrays
 * @param key Key bytes
 * @param keyLen Length of key in bytes (4-56)
 */
void	blowfishInitKey(t_blowfishEcbCtx *ctx, const uint8_t *key, size_t keyLen);

/**
 * @brief Encrypts a single 64-bit block using Blowfish.
 *
 * Blowfish operates on 64-bit blocks divided into two 32-bit halves (L and R).
 * The encryption process consists of 16 rounds of Feistel network using the
 * P-array, followed by a final swap and XOR with the last two P-array entries.
 * 
 * @param ctx Pointer to Blowfish context with initialized key schedule
 * @param block 64-bit plaintext block
 * @return 64-bit ciphertext block
 */
uint64_t	blowfishEncryptBlock(const t_blowfishEcbCtx *ctx, uint64_t block);

/**
 * @brief Decrypts a single 64-bit block using Blowfish.
 *
 * Decryption uses the same P-array and S-boxes as encryption, but applies
 * the P-array entries in reverse order. The Feistel network structure makes
 * encryption and decryption symmetric except for key order.
 * 
 * @param ctx Pointer to Blowfish context with initialized key schedule
 * @param block 64-bit ciphertext block
 * @return 64-bit plaintext block
 */
uint64_t	blowfishDecryptBlock(const t_blowfishEcbCtx *ctx, uint64_t block);

#endif /* HAJCRYPT_BLOWFISH_H */
