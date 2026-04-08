#ifndef HAJCRYPT_BLOWFISH_H
#define HAJCRYPT_BLOWFISH_H

#include <stddef.h>
#include <stdint.h>

#include "cipher.h"
#include "modes.h"

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
 */
typedef struct s_blowfishEcbCtx
{
	uint32_t			P[18];			/* 18 P-array subkeys */
	uint32_t			S[4][256];		/* 4 S-boxes of 256 entries each */
	uint8_t				buffer[8];		/* Buffer for partial block */
	size_t				bufferLen;		/* Number of bytes in buffer */
	t_cipherDirection	dir;			/* Encryption or decryption mode */
}	t_blowfishEcbCtx;

/**
 * @brief Blowfish CBC (Cipher Block Chaining) context structure.
 * 
 * Maintains state for Blowfish encryption/decryption in CBC mode.
 * CBC mode XORs each plaintext block with the previous ciphertext block
 * before encryption (or after decryption).
 */
typedef struct s_blowfishCbcCtx
{
	t_cbcGenCtx			cbcCtx;			/* CBC context */
	uint32_t			P[18];			/* 18 P-array subkeys */
	uint32_t			S[4][256];		/* 4 S-boxes of 256 entries each */
}	t_blowfishCbcCtx;

/**
 * @brief Blowfish CFB (Cipher Feedback) context structure.
 * 
 * Maintains state for Blowfish encryption/decryption in CFB mode.
 * CFB mode operates as a stream cipher, using the previous ciphertext block for feedback.
 */
typedef struct s_blowfishCfbCtx
{
	t_cfbGenCtx			cfbCtx;			/* CFB context */
	uint32_t			P[18];			/* 18 P-array subkeys */
	uint32_t			S[4][256];		/* 4 S-boxes of 256 entries each */
}	t_blowfishCfbCtx;

/**
 * @brief Blowfish OFB (Output Feedback) context structure.
 * 
 * Maintains state for Blowfish encryption/decryption in OFB mode.
 * OFB mode generates keystream blocks independent of plaintext/ciphertext.
 */
typedef struct s_blowfishOfbCtx
{
	t_ofbGenCtx			ofbCtx;			/* OFB context */
	uint32_t			P[18];			/* 18 P-array subkeys */
	uint32_t			S[4][256];		/* 4 S-boxes of 256 entries each */
}	t_blowfishOfbCtx;

/**
 * @brief Blowfish CTR (Counter) context structure.
 * 
 * Maintains state for Blowfish encryption/decryption in CTR mode.
 * CTR mode generates keystream blocks by encrypting a counter value.
 */
typedef struct s_blowfishCtrCtx
{
	t_ctrGenCtx			ctrCtx;			/* CTR context */
	uint32_t			P[18];			/* 18 P-array subkeys */
	uint32_t			S[4][256];		/* 4 S-boxes of 256 entries each */
}	t_blowfishCtrCtx;

/**
 * @brief Blowfish PCBC (Propagating Cipher Block Chaining) context structure.
 * 
 * Maintains state for Blowfish encryption/decryption in PCBC mode.
 * PCBC mode is similar to CBC but propagates changes in both plaintext and ciphertext.
 */
typedef struct s_blowfishPcbcCtx
{
	t_pcbcGenCtx		pcbcCtx;		/* PCBC context */
	uint32_t			P[18];			/* 18 P-array subkeys */
	uint32_t			S[4][256];		/* 4 S-boxes of 256 entries each */
}	t_blowfishPcbcCtx;

/* ---------- Core Blowfish operations ---------- */

/**
 * @brief Initialize the Blowfish state with default values
 * 
 * @param P   P-array (18 elements)
 * @param S   S-boxes (4 arrays of 256 elements each)
 */
void blowfishInitState(uint32_t *P, uint32_t (*S)[256]);

/**
 * @brief Initializes the Blowfish key schedule from a variable-length key.
 *
 * Blowfish accepts keys from 32 to 448 bits (4 to 56 bytes).
 * The key is used to initialize the P-array and S-boxes through the
 * key expansion process defined in the Blowfish specification.
 * 
 * @param P Output array for the initialized P-array (18 entries)
 * @param S Output array for the initialized S-boxes (4 arrays of 256 entries)
 * @param key Input key for initialization
 * @param keyLen Length of the input key in bytes
 */
void	blowfishInitKey(uint32_t *P, uint32_t (*S)[256], const uint8_t *key, size_t keyLen);

/**
 * @brief Encrypts a single 64-bit block using Blowfish.
 *
 * Blowfish operates on 64-bit blocks divided into two 32-bit halves (L and R).
 * The encryption process consists of 16 rounds of Feistel network using the
 * P-array, followed by a final swap and XOR with the last two P-array entries.
 * 
 * @param P P-array subkeys for encryption
 * @param S S-boxes for encryption
 * @param in 64-bit input block to encrypt (8 bytes)
 * @param out 64-bit output block after encryption (8 bytes)
 * @return 64-bit encrypted output block
 */
void	blowfishEncryptBlock(const uint32_t *P, const uint32_t (*S)[256], const uint8_t in[8], uint8_t out[8]);

/**
 * @brief Decrypts a single 64-bit block using Blowfish.
 *
 * Decryption uses the same P-array and S-boxes as encryption, but applies
 * the P-array entries in reverse order. The Feistel network structure makes
 * encryption and decryption symmetric except for key order.
 * 
 * @param P P-array subkeys for decryption
 * @param S S-boxes for decryption
 * @param in 64-bit input block to decrypt (8 bytes)
 * @param out 64-bit output block after decryption (8 bytes)
 * @return 64-bit decrypted output block
 */
void	blowfishDecryptBlock(const uint32_t *P, const uint32_t (*S)[256], const uint8_t in[8], uint8_t out[8]);

/* ---------- ECB mode functions ---------- */

/**
 * @brief Initializes Blowfish ECB context with key and direction.
 * 
 * @param ctx Pointer to Blowfish ECB context
 * @param key Encryption key (4-56 bytes)
 * @param keyLen Length of key in bytes
 * @param iv Initialization vector (unused in ECB, kept for interface)
 * @param dir Encryption or decryption direction
 */
int	blowfishEcbInit(void				*ctx,
					 const uint8_t		*key,
					 size_t				keyLen,
					 const uint8_t		*iv,
					 t_cipherDirection	dir);

/**
 * @brief Updates Blowfish ECB context with input data.
 * 
 * Processes input data in 8-byte blocks, outputting encrypted/decrypted data.
 * Partial blocks are buffered for next update or final call.
 * 
 * @param ctx Pointer to Blowfish ECB context
 * @param in Input data buffer
 * @param inLen Length of input data
 * @param out Output buffer for processed data
 * @param outLen Number of bytes written to output
 */
void	blowfishEcbUpdate(void			*ctx,
						  const uint8_t	*in,
						  size_t		inLen,
						  uint8_t		*out,
						  size_t		*outLen);

/**
 * @brief Finalizes Blowfish ECB operation, handling padding.
 * 
 * @param ctx Pointer to Blowfish ECB context
 * @param out Output buffer for final data
 * @param outLen Number of bytes written to output
 */
void	blowfishEcbFinal(void *ctx, uint8_t *out, size_t *outLen);

/**
 * @brief Frees Blowfish ECB context resources.
 * 
 * @param ctx Pointer to Blowfish ECB context
 */
void	blowfishEcbFree(void *ctx);

/* ---------- CBC mode functions ---------- */

/**
 * @brief Initializes Blowfish CBC context with key, IV, and direction.
 * 
 * @param ctx Pointer to Blowfish CBC context
 * @param key Encryption key (4-56 bytes)
 * @param keyLen Length of key in bytes
 * @param iv Initialization vector (8 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction
 */
int	blowfishCbcInit(void				*ctx,
					 const uint8_t		*key,
					 size_t				keyLen,
					 const uint8_t		*iv,
					 t_cipherDirection	dir);

/**
 * @brief Updates Blowfish CBC context with input data.
 * 
 * Processes input data in 8-byte blocks with cipher block chaining.
 * 
 * @param ctx Pointer to Blowfish CBC context
 * @param in Input data buffer
 * @param inLen Length of input data
 * @param out Output buffer for processed data
 * @param outLen Number of bytes written to output
 */
void	blowfishCbcUpdate(void			*ctx,
						  const uint8_t	*in,
						  size_t		inLen,
						  uint8_t		*out,
						  size_t		*outLen);

/**
 * @brief Finalizes Blowfish CBC operation, handling padding.
 * 
 * @param ctx Pointer to Blowfish CBC context
 * @param out Output buffer for final data
 * @param outLen Number of bytes written to output
 */
void	blowfishCbcFinal(void *ctx, uint8_t *out, size_t *outLen);

/**
 * @brief Frees Blowfish CBC context resources.
 * 
 * @param ctx Pointer to Blowfish CBC context
 */
void	blowfishCbcFree(void *ctx);

/* ---------- CFB mode functions ---------- */

/**
 * @brief Initializes Blowfish CFB context with key, IV, and direction.
 * 
 * @param ctx Pointer to Blowfish CFB context
 * @param key Encryption key (4-56 bytes)
 * @param keyLen Length of key in bytes
 * @param iv Initialization vector (8 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction
 */
int	blowfishCfbInit(void				*ctx,
					 const uint8_t		*key,
					 size_t				keyLen,
					 const uint8_t		*iv,
					 t_cipherDirection	dir);

/**
 * @brief Updates Blowfish CFB context with input data.
 * 
 * @param ctx Pointer to Blowfish CFB context
 * @param in Input data buffer
 * @param inLen Length of input data
 * @param out Output buffer for processed data
 * @param outLen Number of bytes written to output
 */
void	blowfishCfbUpdate(void			*ctx,
						  const uint8_t	*in,
						  size_t		inLen,
						  uint8_t		*out,
						  size_t		*outLen);

/**
 * @brief Finalizes Blowfish CFB operation.
 * 
 * @param ctx Pointer to Blowfish CFB context
 * @param out Output buffer for final data
 * @param outLen Number of bytes written to output
 */
void	blowfishCfbFinal(void *ctx, uint8_t *out, size_t *outLen);

/**
 * @brief Frees Blowfish CFB context resources.
 * 
 * @param ctx Pointer to Blowfish CFB context
 */
void	blowfishCfbFree(void *ctx);

/**
 * @brief Initializes Blowfish CFB1 context with key, IV, and direction.
 * 
 * @param ctx Pointer to Blowfish CFB1 context
 * @param key Encryption key (4-56 bytes)
 * @param keyLen Length of key in bytes
 * @param iv Initialization vector (8 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction
 */
int	blowfishCfb1Init(void				*ctx,
					  const uint8_t		*key,
					  size_t			keyLen,
					  const uint8_t		*iv,
					  t_cipherDirection	dir);

/**
 * @brief Updates Blowfish CFB1 context with input data (bit-oriented).
 * 
 * @param ctx Pointer to Blowfish CFB1 context
 * @param in Input data buffer
 * @param inLen Length of input data in bytes
 * @param out Output buffer for processed data
 * @param outLen Number of bits written to output
 */
void	blowfishCfb1Update(void				*ctx,
						   const uint8_t	*in,
						   size_t			inLen,
						   uint8_t			*out,
						   size_t			*outLen);

/**
 * @brief Finalizes Blowfish CFB1 operation.
 * 
 * @param ctx Pointer to Blowfish CFB1 context
 * @param out Output buffer for final data
 * @param outLen Number of bits written to output
 */
void	blowfishCfb1Final(void *ctx, uint8_t *out, size_t *outLen);

/**
 * @brief Initializes Blowfish CFB8 context with key, IV, and direction.
 * 
 * @param ctx Pointer to Blowfish CFB8 context
 * @param key Encryption key (4-56 bytes)
 * @param keyLen Length of key in bytes
 * @param iv Initialization vector (8 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction
 */
int	blowfishCfb8Init(void				*ctx,
					  const uint8_t		*key,
					  size_t			keyLen,
					  const uint8_t		*iv,
					  t_cipherDirection	dir);

/* ---------- OFB mode functions ---------- */

/**
 * @brief Initializes Blowfish OFB context with key, IV, and direction.
 * 
 * @param ctx Pointer to Blowfish OFB context
 * @param key Encryption key (4-56 bytes)
 * @param keyLen Length of key in bytes
 * @param iv Initialization vector (8 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction
 */
int	blowfishOfbInit(void				*ctx,
					 const uint8_t		*key,
					 size_t				keyLen,
					 const uint8_t		*iv,
					 t_cipherDirection	dir);

/**
 * @brief Updates Blowfish OFB context with input data.
 * 
 * @param ctx Pointer to Blowfish OFB context
 * @param in Input data buffer
 * @param inLen Length of input data
 * @param out Output buffer for processed data
 * @param outLen Number of bytes written to output
 */
void	blowfishOfbUpdate(void			*ctx,
						  const uint8_t	*in,
						  size_t		inLen,
						  uint8_t		*out,
						  size_t		*outLen);

/**
 * @brief Finalizes Blowfish OFB operation.
 * 
 * @param ctx Pointer to Blowfish OFB context
 * @param out Output buffer for final data
 * @param outLen Number of bytes written to output
 */
void	blowfishOfbFinal(void *ctx, uint8_t *out, size_t *outLen);

/**
 * @brief Frees Blowfish OFB context resources.
 * 
 * @param ctx Pointer to Blowfish OFB context
 */
void	blowfishOfbFree(void *ctx);

/* ---------- CTR mode functions ---------- */

/**
 * @brief Initializes Blowfish CTR context with key, IV, and direction.
 * 
 * @param ctx Pointer to Blowfish CTR context
 * @param key Encryption key (4-56 bytes)
 * @param keyLen Length of key in bytes
 * @param iv Initialization vector (8 bytes, used as initial counter)
 * @param dir Encryption or decryption direction
 */
int	blowfishCtrInit(void				*ctx,
					 const uint8_t		*key,
					 size_t				keyLen,
					 const uint8_t		*iv,
					 t_cipherDirection	dir);

/**
 * @brief Updates Blowfish CTR context with input data.
 * 
 * @param ctx Pointer to Blowfish CTR context
 * @param in Input data buffer
 * @param inLen Length of input data
 * @param out Output buffer for processed data
 * @param outLen Number of bytes written to output
 */
void	blowfishCtrUpdate(void			*ctx,
						  const uint8_t	*in,
						  size_t		inLen,
						  uint8_t		*out,
						  size_t		*outLen);

/**
 * @brief Finalizes Blowfish CTR operation.
 * 
 * @param ctx Pointer to Blowfish CTR context
 * @param out Output buffer for final data
 * @param outLen Number of bytes written to output
 */
void	blowfishCtrFinal(void *ctx, uint8_t *out, size_t *outLen);

/**
 * @brief Frees Blowfish CTR context resources.
 * 
 * @param ctx Pointer to Blowfish CTR context
 */
void	blowfishCtrFree(void *ctx);

/* ---------- PCBC mode functions ---------- */

/**
 * @brief Initializes Blowfish PCBC context with key, IV, and direction.
 * 
 * @param ctx Pointer to Blowfish PCBC context
 * @param key Encryption key (4-56 bytes)
 * @param keyLen Length of key in bytes
 * @param iv Initialization vector (8 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction
 */
int	blowfishPcbcInit(void				*ctx,
					  const uint8_t		*key,
					  size_t			keyLen,
					  const uint8_t		*iv,
					  t_cipherDirection	dir);

/**
 * @brief Updates Blowfish PCBC context with input data.
 * 
 * @param ctx Pointer to Blowfish PCBC context
 * @param in Input data buffer
 * @param inLen Length of input data
 * @param out Output buffer for processed data
 * @param outLen Number of bytes written to output
 */
void	blowfishPcbcUpdate(void				*ctx,
						   const uint8_t	*in,
						   size_t			inLen,
						   uint8_t			*out,
						   size_t			*outLen);

/**
 * @brief Finalizes Blowfish PCBC operation, handling padding.
 * 
 * @param ctx Pointer to Blowfish PCBC context
 * @param out Output buffer for final data
 * @param outLen Number of bytes written to output
 */
void	blowfishPcbcFinal(void *ctx, uint8_t *out, size_t *outLen);

/**
 * @brief Frees Blowfish PCBC context resources.
 * 
 * @param ctx Pointer to Blowfish PCBC context
 */
void	blowfishPcbcFree(void *ctx);

/* ---------- Global cipher structures ---------- */

extern const t_cipher	g_blowfishEcbCipher;
extern const t_cipher	g_blowfishCbcCipher;
extern const t_cipher	g_blowfishCipher;
extern const t_cipher	g_blowfishCfbCipher;
extern const t_cipher	g_blowfishCfb1Cipher;
extern const t_cipher	g_blowfishCfb8Cipher;
extern const t_cipher	g_blowfishOfbCipher;
extern const t_cipher	g_blowfishCtrCipher;
extern const t_cipher	g_blowfishPcbcCipher;

#endif /* HAJCRYPT_BLOWFISH_H */
