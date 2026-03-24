#ifndef HAJCRYPT_DES_H
#define HAJCRYPT_DES_H

#include <stddef.h>
#include <stdint.h>

#include "cipher.h"
#include "modes.h"

/**
 * @brief DES ECB (Electronic Codebook) context structure.
 * 
 * Maintains state for DES encryption/decryption in ECB mode.
 * ECB mode processes each block independently.
 */
typedef struct s_desEcbCtx
{
	uint64_t			subkeys[16];	/* 16 round subkeys (48 bits each) */
	uint8_t				buffer[8];		/* Buffer for partial block */
	size_t				bufferLen;		/* Number of bytes in buffer */
	t_cipherDirection	dir;			/* Encryption or decryption mode */
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
	t_cbcGenCtx			cbcCtx;			/* CBC context */
	uint64_t			subkeys[16];	/* 16 round subkeys (48 bits each) */
}	t_desCbcCtx;

/**
 * @brief DES CFB (Cipher Feedback) context structure.
 * 
 * Maintains state for DES encryption/decryption in CFB mode.
 * CFB mode operates as a stream cipher, using the previous ciphertext block for feedback.
 */
typedef struct s_desCfbCtx
{
	t_cfbGenCtx			cfbCtx;			/* CFB context */
	uint64_t			subkeys[16];	/* 16 round subkeys (48 bits each) */
}	t_desCfbCtx;

/**
 * @brief DES OFB (Output Feedback) context structure.
 * 
 * Maintains state for DES encryption/decryption in OFB mode.
 * OFB mode generates keystream blocks independent of plaintext/ciphertext.
 */
typedef struct s_desOfbCtx
{
	t_ofbGenCtx			ofbCtx;			/* OFB context */
	uint64_t			subkeys[16];	/* 16 round subkeys (48 bits each) */
}	t_desOfbCtx;

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
int	desEcbInit(void						*ctx,
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
int	desCbcInit(void					*ctx,
			   const uint8_t		*key,
			   size_t				keyLen,
			   const uint8_t		*iv,
			   t_cipherDirection	dir);

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
void	desCbcUpdate(void			*ctx,
					 const uint8_t	*in,
					 size_t			inLen,
					 uint8_t		*out,
					 size_t			*outLen);

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

/* ---------- CFB mode functions ---------- */

/**
 * @brief Initializes DES CFB context with key, IV, and direction.
 * 
 * CFB mode operates as a stream cipher, so this function may set up additional state.
 * 
 * @param ctx Pointer to DES CFB context
 * @param key Encryption key (8 bytes, or fewer padded with zeros)
 * @param keyLen Length of key in bytes
 * @param iv Initialization vector (8 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction
 */
int	desCfbInit(void					*ctx,
			   const uint8_t		*key,
			   size_t				keyLen,
			   const uint8_t		*iv,
			   t_cipherDirection	dir);

/**
 * @brief Updates DES CFB context with input data.
 * 
 * Processes input data in 8-byte blocks with cipher feedback mode.
 * In encryption: encrypt IV, XOR with plaintext to get ciphertext, then update IV.
 * In decryption: encrypt IV, XOR with ciphertext to get plaintext, then update IV.
 * 
 * @param ctx Pointer to DES CFB context
 * @param in Input data buffer
 * @param inLen Length of input data
 * @param out Output buffer for processed data
 * @param outLen Number of bytes written to output
 */
void	desCfbUpdate(void			*ctx,
					 const uint8_t	*in,
					 size_t			inLen,
					 uint8_t		*out,
					 size_t			*outLen);

/**
 * @brief Finalizes DES CFB operation.
 *
 * CFB mode does not require padding, so this function may be a no-op.
 * 
 * @param ctx Pointer to DES CFB context
 * @param out Output buffer for final data (unused)
 * @param outLen Number of bytes written to output (set to 0)
 */
void	desCfbFinal(void *ctx, uint8_t *out, size_t *outLen);

/**
 * @brief Frees DES CFB context resources.
 * 
 * @param ctx Pointer to DES CFB context
 */
void	desCfbFree(void *ctx);

/**
 * @brief Initializes DES CFB1 context with key, IV, and direction.
 * 
 * CFB1 mode operates on single bits, so this function may set up additional state.
 * 
 * @param ctx Pointer to DES CFB1 context
 * @param key Encryption key (8 bytes, or fewer padded with zeros)
 * @param keyLen Length of key in bytes
 * @param iv Initialization vector (8 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction
 */
int	desCfb1Init(void					*ctx,
				const uint8_t		*key,
				size_t				keyLen,
				const uint8_t		*iv,
				t_cipherDirection	dir);

/**
 * @brief Updates DES CFB1 context with input data.
 * 
 * Processes input data in 8-byte blocks with cipher feedback mode.
 * In encryption: encrypt IV, XOR with plaintext to get ciphertext, then update IV.
 * In decryption: encrypt IV, XOR with ciphertext to get plaintext, then update IV.
 * 
 * @param ctx Pointer to DES CFB1 context
 * @param in Input data buffer
 * @param inLen Length of input data
 * @param out Output buffer for processed data
 * @param outLen Number of bytes written to output
 */
void	desCfb1Update(void			*ctx,
					 const uint8_t	*in,
					 size_t			inLen,
					 uint8_t		*out,
					 size_t			*outLen);

/**
 * @brief Finalizes DES CFB1 operation.
 *
 * CFB1 mode does not require padding, so this function may be a no-op.
 * 
 * @param ctx Pointer to DES CFB1 context
 * @param out Output buffer for final data (unused)
 * @param outLen Number of bytes written to output (set to 0)
 */
void	desCfb1Final(void *ctx, uint8_t *out, size_t *outLen);

/**
 * @brief Initializes DES CFB8 context with key, IV, and direction.
 * 
 * CFB8 mode operates on bytes, so this function may set up additional state.
 * 
 * @param ctx Pointer to DES CFB8 context
 * @param key Encryption key (8 bytes, or fewer padded with zeros)
 * @param keyLen Length of key in bytes
 * @param iv Initialization vector (8 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction
 */
int	desCfb8Init(void					*ctx,
			   const uint8_t			*key,
			   size_t					keyLen,
			   const uint8_t			*iv,
			   t_cipherDirection		dir);

/* ---------- OFB mode functions ---------- */

/**
 * @brief Initializes a DES cipher in OFB (Output Feedback) mode.
 * 
 * @param vctx Pointer to the cipher context structure to be initialized.
 * @param key Pointer to the encryption key buffer.
 * @param keyLen Length of the key in bytes.
 * @param iv Pointer to the initialization vector buffer.
 * @param dir The cipher direction (encrypt or decrypt).
 * 
 * @return On success, returns 0. On error, returns a non-zero error code.
 */
int	desOfbInit(void					*vctx,
			   const uint8_t		*key,
			   size_t				keyLen,
			   const uint8_t		*iv,
			   t_cipherDirection	dir);

/**
 * @brief Frees resources associated with a DES OFB context.
 * 
 * @param vctx Pointer to the DES OFB context to be freed.
 */
void	desOfbFree(void *vctx);

/**
 * @brief Updates the DES OFB context with input data, producing output data.
 * 
 * @param vctx Pointer to the DES OFB context.
 * @param in Pointer to the input data buffer.
 * @param inLen Length of the input data in bytes.
 * @param out Pointer to the output buffer where processed data will be written.
 * @param outLen Pointer to a size_t variable where the number of bytes written to output will be stored.
 */
void	desOfbUpdate(void *vctx, const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen);

/**
 * @brief Finalizes the DES OFB operation, writing any remaining output data.
 * 
 * @param vctx Pointer to the DES OFB context.
 * @param out Pointer to the output buffer where final data will be written.
 * @param outLen Pointer to a size_t variable where the number of bytes written to output will be stored.
 */
void	desOfbFinal(void *vctx, uint8_t *out, size_t *outLen);

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

/**
 * @brief DES CFB cipher structure for dispatch table.
 * 
 * Implements the t_cipher interface for DES CFB mode.
 */
extern const t_cipher	g_desCfbCipher;

/**
 * @brief DES CFB1 cipher structure for dispatch table.
 * 
 * Implements the t_cipher interface for DES CFB1 mode.
 */
extern const t_cipher	g_desCfb1Cipher;

/**
 * @brief DES CFB8 cipher structure for dispatch table.
 * 
 * Implements the t_cipher interface for DES CFB8 mode.
 */
extern const t_cipher	g_desCfb8Cipher;

/**
 * @brief DES OFB cipher structure for dispatch table.
 * 
 * Implements the t_cipher interface for DES OFB mode.
 */
extern const t_cipher	g_desOfbCipher;

#endif /* HAJCRYPT_DES_H */
