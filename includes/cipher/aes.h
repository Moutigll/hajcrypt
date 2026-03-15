#ifndef HAJCRYPT_AES_H
#define HAJCRYPT_AES_H

#include <stddef.h>
#include <stdint.h>

#include "cipher.h"

/* AES block size in bytes */
#define AES_BLOCK_SIZE 16

#define AES_MAX_ROUNDS 14

/* AES key sizes in bytes */
#define AES_KEY_SIZE_128 16
#define AES_KEY_SIZE_192 24
#define AES_KEY_SIZE_256 32

/* Number of rounds per key size */
#define AES_ROUNDS_128 10
#define AES_ROUNDS_192 12
#define AES_ROUNDS_256 14

/**
 * @brief AES ECB (Electronic Codebook) context structure.
 * 
 * Maintains state for AES encryption/decryption in ECB mode.
 * Supports 128, 192, and 256-bit keys.
 */
typedef struct s_aesEcbCtx
{
	uint32_t			roundKeys[60];			/* Expanded key schedule (max for AES-256) */
	uint32_t			nbRounds;				/* Number of rounds (10/12/14) */
	uint8_t				buffer[AES_BLOCK_SIZE] __attribute__((aligned(16)));	/* Buffer for partial block */
	size_t				bufferLen;				/* Number of bytes in buffer */
	t_cipherDirection	dir;					/* Encryption or decryption mode */
}	t_aesEcbCtx;

/**
 * @brief AES CBC (Cipher Block Chaining) context structure.
 * 
 * Maintains state for AES encryption/decryption in CBC mode.
 * Supports 128, 192, and 256-bit keys.
 */
typedef struct s_aesCbcCtx
{
	uint32_t			roundKeys[60];			/* Expanded key schedule (max for AES-256) */
	uint32_t			nbRounds;				/* Number of rounds (10/12/14) */
	uint8_t				iv[AES_BLOCK_SIZE] __attribute__((aligned(16)));		/* Initialization vector */
	uint8_t				buffer[AES_BLOCK_SIZE] __attribute__((aligned(16)));	/* Buffer for partial block */
	size_t				bufferLen;				/* Number of bytes in buffer */
	t_cipherDirection	dir;					/* Encryption or decryption mode */
}	t_aesCbcCtx;

/* ---------- Core AES operations ---------- */

/**
 * @brief Get number of rounds for given key size.
 * 
 * @param keyLen Key length in bytes (16, 24, or 32)
 * @return Number of rounds (10, 12, or 14), or 0 if invalid
 */
uint32_t	aesGetRounds(size_t keyLen);

/**
 * @brief Expand a cipher key into the AES key schedule.
 * 
 * Generates round keys for encryption using the AES key expansion algorithm.
 * 
 * @param key Original cipher key (16, 24, or 32 bytes)
 * @param keyLen Length of key in bytes
 * @param roundKeys Output array for expanded round keys
 * @param nbRounds Number of rounds (for verification)
 * @return 0 on success, -1 on error
 */
uint32_t	aesExpandKey(const uint8_t *key, size_t keyLen, uint32_t roundKeys[60]);

/**
 * @brief Expand a cipher key for decryption (inverse key schedule).
 * 
 * Transforms the encryption round keys into decryption round keys
 * by applying InvMixColumns to all but the first and last round keys.
 * 
 * @param encRoundKeys Encryption round keys
 * @param nbRounds Number of rounds
 * @param decRoundKeys Output array for decryption round keys
 */
void	aesExpandDecryptKeys(const uint32_t *encRoundKeys, uint32_t nbRounds, uint32_t *decRoundKeys);

/**
 * @brief Encrypts a single 128-bit block using AES.
 * 
 * AES operates on 16-byte blocks and uses the expanded key schedule.
 * The encryption process includes AddRoundKey, SubBytes, ShiftRows, and MixColumns.
 * 
 * @param block 16-byte plaintext block
 * @param roundKeys Expanded key schedule
 * @param nbRounds Number of rounds
 */
void	aesEncryptBlock(uint8_t block[AES_BLOCK_SIZE], const uint32_t *roundKeys, uint32_t nbRounds);

/**
 * @brief Decrypts a single 128-bit block using AES.
 * 
 * Decryption uses the inverse operations: InvSubBytes, InvShiftRows, InvMixColumns.
 * 
 * @param block 16-byte ciphertext block
 * @param roundKeys Expanded key schedule (decryption keys)
 * @param nbRounds Number of rounds
 */
void	aesDecryptBlock(uint8_t block[AES_BLOCK_SIZE], const uint32_t *roundKeys, uint32_t nbRounds);

/* ---------- ECB mode functions ---------- */

/**
 * @brief Initializes AES ECB context with key and direction.
 * 
 * @param ctx Pointer to AES ECB context
 * @param key Encryption key (16, 24, or 32 bytes)
 * @param keyLen Length of key in bytes
 * @param iv Initialization vector (unused in ECB, kept for interface)
 * @param dir Encryption or decryption direction
 */
int	aesEcbInit(void					*ctx,
			   const uint8_t		*key,
			   size_t				keyLen,
			   const uint8_t		*iv,
			   t_cipherDirection	dir);

/**
 * @brief Updates AES ECB context with input data.
 * 
 * Processes input data in 16-byte blocks, outputting encrypted/decrypted data.
 * Partial blocks are buffered for next update or final call.
 * 
 * @param ctx Pointer to AES ECB context
 * @param in Input data buffer
 * @param inLen Length of input data
 * @param out Output buffer for processed data
 * @param outLen Number of bytes written to output
 */
void	aesEcbUpdate(void			*ctx,
					 const uint8_t	*in,
					 size_t			inLen,
					 uint8_t		*out,
					 size_t			*outLen);
/**
 * @brief Finalizes AES ECB operation, handling padding.
 * 
 * For encryption: applies PKCS#7 padding to the last block.
 * For decryption: verifies and removes padding.
 * 
 * @param ctx Pointer to AES ECB context
 * @param out Output buffer for final data
 * @param outLen Number of bytes written to output
 */
void	aesEcbFinal(void *ctx, uint8_t *out, size_t *outLen);

/**
 * @brief Frees AES ECB context resources.
 * 
 * @param ctx Pointer to AES ECB context
 */
void	aesEcbFree(void *ctx);

/* ---------- CBC mode functions ---------- */

/**
 * @brief Initializes AES CBC context with key, IV, and direction.
 * 
 * @param ctx Pointer to AES CBC context
 * @param key Encryption key (16, 24, or 32 bytes)
 * @param keyLen Length of key in bytes
 * @param iv Initialization vector (16 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction
 */
int	aesCbcInit(void					*ctx,
			   const uint8_t		*key,
			   size_t				keyLen,
			   const uint8_t		*iv,
			   t_cipherDirection	dir);
/**
 * @brief Updates AES CBC context with input data.
 * 
 * Processes input data in 16-byte blocks with cipher block chaining.
 * 
 * @param ctx Pointer to AES CBC context
 * @param in Input data buffer
 * @param inLen Length of input data
 * @param out Output buffer for processed data
 * @param outLen Number of bytes written to output
 */
void	aesCbcUpdate(void			*ctx,
					 const uint8_t	*in,
					 size_t			inLen,
					 uint8_t		*out,
					 size_t			*outLen);

/**
 * @brief Finalizes AES CBC operation, handling padding.
 * 
 * For encryption: applies PKCS#7 padding to the last block.
 * For decryption: verifies and removes padding.
 * 
 * @param ctx Pointer to AES CBC context
 * @param out Output buffer for final data
 * @param outLen Number of bytes written to output
 */
void	aesCbcFinal(void *ctx, uint8_t *out, size_t *outLen);

/**
 * @brief Frees AES CBC context resources.
 * 
 * @param ctx Pointer to AES CBC context
 */
void	aesCbcFree(void *ctx);

/* ---------- ARM64 optimized functions ---------- */

/**
 * @brief Processes multiple AES blocks using ARM NEON instructions.
 *
 * This function performs AES encryption or decryption on a batch of blocks,
 * leveraging NEON SIMD acceleration for improved performance on supported hardware.
 *
 * @param in         Pointer to the input data buffer containing blocks to process.
 * @param out        Pointer to the output data buffer where processed blocks will be written.
 * @param roundKeys  Pointer to the expanded AES round keys.
 * @param blocks     Number of blocks to process.
 * @param nbRounds   Number of AES rounds (depends on key size).
 * @param encrypt    Set to non-zero for encryption, zero for decryption.
 */
void	aesProcessBlocksNeon(const uint8_t	*in,
							 uint8_t		*out,
							 const uint32_t	*roundKeys,
							 size_t			blocks,
							 int			nbRounds,
							 int			encrypt);
/* ---------- Global cipher structures ---------- */

extern const t_cipher g_aes128EcbCipher;
extern const t_cipher g_aes192EcbCipher;
extern const t_cipher g_aes256EcbCipher;

extern const t_cipher g_aes128CbcCipher;
extern const t_cipher g_aes192CbcCipher;
extern const t_cipher g_aes256CbcCipher;

extern const t_cipher g_aes128Cipher;
extern const t_cipher g_aes192Cipher;
extern const t_cipher g_aes256Cipher;

#endif /* HAJCRYPT_AES_H */
