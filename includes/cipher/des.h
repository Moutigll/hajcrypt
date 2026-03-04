#ifndef HAJCRYPT_DES_H
#define HAJCRYPT_DES_H

#include <stddef.h>
#include <stdint.h>

#include "cipher.h"

/**
 * @brief DES ECB (Electronic Codebook) context structure.
 * 
 * Maintains state for DES encryption/decryption in ECB mode.
 * ECB mode processes each block independently.
 */
typedef struct s_desEcbCtx
{
	uint64_t		subkeys[16];	/* 16 round subkeys (48 bits each) */
	uint8_t			buffer[8];		/* Buffer for partial block */
	size_t			bufferLen;		/* Number of bytes in buffer */
	t_cipherDirection	dir;		/* Encryption or decryption mode */
}	t_desEcbCtx;

/**
 * @brief DES CBC (Cipher Block Chaining) context structure.
 * 
 * Maintains state for DES encryption/decryption in CBC mode.
 * CBC mode XORs each plaintext block with the previous ciphertext block
 * before encryption (or after decryption).
 */
typedef struct s_desCbcCtx
{
	uint64_t		subkeys[16];	/* 16 round subkeys (48 bits each) */
	uint8_t			iv[8];			/* Initialization vector */
	uint8_t			buffer[8];		/* Buffer for partial block */
	size_t			bufferLen;		/* Number of bytes in buffer */
	t_cipherDirection	dir;		/* Encryption or decryption mode */
}	t_desCbcCtx;

/* ---------- Core DES operations ---------- */

/**
 * @brief Generates the 16 round subkeys from a 64-bit DES key.
 *
 * The input key includes parity bits (8 bytes), but only 56 bits are used for subkey generation.
 * The subkeys are generated using the PC1 and PC2 tables and the specified left shifts.
 * 
 * @param key 64-bit DES key (includes parity bits)
 * @param subkeys Output array of 16 subkeys (48 bits each)
 */
void	desGenerateSubkeys(uint64_t key, uint64_t subkeys[16]);

/**
 * @brief DES round function (Feistel function).
 * 
 * Applies expansion, XOR with subkey, S-box substitution, and permutation.
 * The input is a 32-bit half-block (R) and a 48-bit round subkey.
 * 
 * @param R 32-bit right half of block
 * @param subkey 48-bit round subkey
 * @return 32-bit output after Feistel transformation
 */
uint32_t	desFeistel(uint32_t R, uint64_t subkey);

/**
 * @brief Encrypts a single 64-bit block using DES.
 *
 * DES operates on 64-bit blocks and uses the 16 round subkeys generated from the key.
 * The encryption process includes the initial permutation (IP), 16 rounds of Feistel function, and the final permutation (FP).
 * 
 * @param block 64-bit plaintext block
 * @param subkeys 16 round subkeys
 * @return 64-bit ciphertext block
 */
uint64_t	desEncryptBlock(uint64_t block, uint64_t subkeys[16]);

/**
 * @brief Decrypts a single 64-bit block using DES.
 *
 * Decryption is performed by applying the same process as encryption but with the round subkeys in reverse order.
 * The initial and final permutations are the same as in encryption.
 * 
 * @param block 64-bit ciphertext block
 * @param subkeys 16 round subkeys
 * @return 64-bit plaintext block
 */
uint64_t	desDecryptBlock(uint64_t block, uint64_t subkeys[16]);

/* ---------- ECB mode functions ---------- */

/**
 * @brief Initializes DES ECB context with key and direction.
 * 
 * @param ctx Pointer to DES ECB context
 * @param key Encryption key (8 bytes, or fewer padded with zeros)
 * @param keyLen Length of key in bytes (max 8, extra truncated)
 * @param iv Initialization vector (unused in ECB, kept for interface)
 * @param dir Encryption or decryption direction
 */
void	desEcbInit(void					*ctx,
				   const uint8_t		*key,
				   size_t				keyLen,
				   const uint8_t		*iv,
				   t_cipherDirection	dir);

/**
 * @brief Updates DES ECB context with input data.
 * 
 * Processes input data in 8-byte blocks, outputting encrypted/decrypted data.
 * Partial blocks are buffered for next update or final call.
 * 
 * @param ctx Pointer to DES ECB context
 * @param in Input data buffer
 * @param inLen Length of input data
 * @param out Output buffer for processed data
 * @param outLen Number of bytes written to output
 */
void	desEcbUpdate(void			*ctx,
					 const uint8_t	*in,
					 size_t			inLen,
					 uint8_t		*out,
					 size_t			*outLen);

/**
 * @brief Finalizes DES ECB operation, handling padding.
 * 
 * For encryption: applies PKCS#7 padding to the last block.
 * For decryption: verifies and removes padding (padding check done separately).
 * 
 * @param ctx Pointer to DES ECB context
 * @param out Output buffer for final data
 * @param outLen Number of bytes written to output
 */
void	desEcbFinal(void *ctx, uint8_t *out, size_t *outLen);

/**
 * @brief Frees DES ECB context resources.
 * 
 * @param ctx Pointer to DES ECB context
 */
void	desEcbFree(void *ctx);

/* ---------- CBC mode functions ---------- */

/**
 * @brief Initializes DES CBC context with key, IV, and direction.
 * 
 * @param ctx Pointer to DES CBC context
 * @param key Encryption key (8 bytes, or fewer padded with zeros)
 * @param keyLen Length of key in bytes
 * @param iv Initialization vector (8 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction
 */
void	desCbcInit(void *ctx, const uint8_t *key, size_t keyLen,
				   const uint8_t *iv, t_cipherDirection dir);

/**
 * @brief Updates DES CBC context with input data.
 * 
 * Processes input data in 8-byte blocks with cipher block chaining.
 * In encryption: XOR with previous ciphertext block (or IV) before encryption.
 * In decryption: decrypt then XOR with previous ciphertext block (or IV).
 * 
 * @param ctx Pointer to DES CBC context
 * @param in Input data buffer
 * @param inLen Length of input data
 * @param out Output buffer for processed data
 * @param outLen Number of bytes written to output
 */
void	desCbcUpdate(void *ctx, const uint8_t *in, size_t inLen,
					 uint8_t *out, size_t *outLen);

/**
 * @brief Finalizes DES CBC operation, handling padding.
 * 
 * For encryption: applies PKCS#7 padding to the last block.
 * For decryption: verifies and removes padding (padding check done separately).
 * 
 * @param ctx Pointer to DES CBC context
 * @param out Output buffer for final data
 * @param outLen Number of bytes written to output
 */
void	desCbcFinal(void *ctx, uint8_t *out, size_t *outLen);

/**
 * @brief Frees DES CBC context resources.
 * 
 * @param ctx Pointer to DES CBC context
 */
void	desCbcFree(void *ctx);

/* ---------- Padding functions ---------- */

/**
 * @brief Applies PKCS#7 padding to a block.
 * 
 * Fills remaining bytes in block with the padding length.
 * 
 * @param block Data block to pad
 * @param len Current data length in block
 * @param blockSize Total block size (always 8 for DES)
 */
void	desPad(uint8_t *block, size_t len, size_t blockSize);

/**
 * @brief Verifies and removes PKCS#7 padding from a block.
 * 
 * Checks that all padding bytes have the correct value and returns
 * the original data length.
 * 
 * @param block Padded data block
 * @param len Pointer to block size, updated to original data length
 * @param blockSize Total block size (always 8 for DES)
 * @return 0 on success, -1 on invalid padding
 */
int		desUnpad(uint8_t *block, size_t *len, size_t blockSize);

/* ---------- Global cipher structures ---------- */

/**
 * @brief DES ECB cipher structure for dispatch table.
 * 
 * Implements the t_cipher interface for DES ECB mode.
 */
extern const t_cipher	g_desEcbCipher;

/**
 * @brief DES CBC cipher structure for dispatch table.
 * 
 * Implements the t_cipher interface for DES CBC mode.
 */
extern const t_cipher	g_desCbcCipher;

/**
 * @brief DES alias cipher structure (points to CBC mode).
 * 
 * Implements the t_cipher interface for "des" command (alias for des-cbc).
 */
extern const t_cipher	g_desCipher;

#endif /* HAJCRYPT_DES_H */
