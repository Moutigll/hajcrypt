#ifndef HAJCRYPT_AES_H
#define HAJCRYPT_AES_H

#include <stddef.h>
#include <stdint.h>

#include "cipher.h"
#include "modes.h"

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

/* GCM tag size in bytes */
#define AES_GCM_TAG_SIZE 16

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
	t_cbcGenCtx			cbcCtx;					/* CBC context */
	uint32_t			roundKeys[60];			/* Expanded key schedule (max for AES-256) */
	uint32_t			nbRounds;				/* Number of rounds (10/12/14) */
}	t_aesCbcCtx;

/**
 * @brief AES CFB (Cipher Feedback) context structure.
 * 
 * Maintains state for AES encryption/decryption in CFB mode.
 * Supports 128, 192, and 256-bit keys.
 */
typedef struct s_aesCfbCtx
{
	t_cfbGenCtx			cfbCtx;					/* CFB context */
	uint32_t			roundKeys[60];			/* Expanded key schedule (max for AES-256) */
	uint32_t			nbRounds;				/* Number of rounds (10/12/14) */
}	t_aesCfbCtx;

/**
 * @brief AES OFB (Output Feedback) context structure.
 * 
 * Maintains state for AES encryption/decryption in OFB mode.
 * Supports 128, 192, and 256-bit keys.
 */
typedef struct s_aesOfbCtx
{
	t_ofbGenCtx			ofbCtx;					/* OFB context */
	uint32_t			roundKeys[60];			/* Expanded key schedule (max for AES-256) */
	uint32_t			nbRounds;				/* Number of rounds (10/12/14) */
}	t_aesOfbCtx;

/**
 * @brief AES CTR (Counter) context structure.
 * 
 * Maintains state for AES encryption/decryption in CTR mode.
 * Supports 128, 192, and 256-bit keys.
 */
typedef struct s_aesCtrCtx {
    t_ctrGenCtx  ctrCtx;
    uint32_t     roundKeys[60];
    uint32_t     nbRounds;
} t_aesCtrCtx;




 typedef struct {
    uint32_t rk[4 * (AES_MAX_ROUNDS + 1)];
} t_aesRoundKeys;

#if defined(__aarch64__)
#include <arm_neon.h>
#endif

/**
 * @brief AES GCM (Galois/Counter Mode) context structure.
 * 
 * Maintains state for AES encryption/decryption in GCM mode, including
 * authentication data and tag generation. Supports 128, 192, and 256-bit keys.
 */
typedef struct {
	t_cipherDirection	dir;
	t_aesRoundKeys		roundKeys;
	int					nr;					/* number of rounds (10,12,14) */
	uint8_t				H[16];				/* hash key (normal order) */
	uint8_t				Hpow[8][16];			/* H^1 .. H^8 (normal order) */
#if defined(__aarch64__)
	uint8_t				Hpow8[8][16] __attribute__((aligned(16))); /* H^1 .. H^8 in bit-reflected order for NEON */
	uint8x16_t			rk_neon[AES_MAX_ROUNDS + 1];	/* Round keys in NEON format (bit-reflected) */
#endif
	uint8_t				J0[16];				/* initial counter */
	uint8_t				counter[16];			/* running counter */
	uint8_t				ghashState[16];		/* current GHASH value */
	uint64_t			aadLen;					/* total length of AAD processed */
	uint64_t			dataLen;
	uint8_t				aadBuffer[16];
	size_t				aadBufferLen;
	uint8_t				dataBuffer[16];
	size_t				dataBufferLen;
} t_aesGcmCtx;

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

/* ---------- CFB mode functions ---------- */

/**
 * @brief Initializes AES CFB context with key, IV, and direction.
 * 
 * @param ctx Pointer to AES CFB context
 * @param key Encryption key (16, 24, or 32 bytes)
 * @param keyLen Length of key in bytes
 * @param iv Initialization vector (16 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction
 */
int	aesCfbInit(void					*ctx,
			   const uint8_t		*key,
			   size_t				keyLen,
			   const uint8_t		*iv,
			   t_cipherDirection	dir);

/**
 * @brief Updates AES CFB context with input data.
 * 
 * Processes input data in 16-byte blocks with cipher feedback mode.
 * 
 * @param ctx Pointer to AES CFB context
 * @param in Input data buffer
 * @param inLen Length of input data
 * @param out Output buffer for processed data
 * @param outLen Number of bytes written to output
 */
void	aesCfbUpdate(void			*ctx,
					 const uint8_t	*in,
					 size_t			inLen,
					 uint8_t		*out,
					 size_t			*outLen);

/**
 * @brief Finalizes AES CFB operation.
 * 
 * CFB mode does not require padding, so this function may be a no-op.
 * 
 * @param ctx Pointer to AES CFB context
 * @param out Output buffer for final data (unused)
 * @param outLen Number of bytes written to output (set to 0)
 */
void	aesCfbFinal(void *ctx, uint8_t *out, size_t *outLen);

/**
 * @brief Frees AES CFB context resources.
 * 
 * @param ctx Pointer to AES CFB context
 */
void	aesCfbFree(void *ctx);

/**
 * @brief Initializes AES CFB1 context with key, IV, and direction.
 * 
 * CFB1 mode operates on single bits, so this function may set up additional state.
 * 
 * @param ctx Pointer to AES CFB1 context
 * @param key Encryption key (16, 24, or 32 bytes)
 * @param keyLen Length of key in bytes
 * @param iv Initialization vector (16 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction
 */
int	aesCfb1Init(void				*ctx,
			   const uint8_t		*key,
			   size_t				keyLen,
			   const uint8_t		*iv,
			   t_cipherDirection	dir);

/**
 * @brief Updates AES CFB1 context with input data.
 * 
 * Processes input data bit by bit, which may require special handling.
 * 
 * @param ctx Pointer to AES CFB1 context
 * @param in Input data buffer (bit-packed)
 * @param inLen Length of input data in bits
 * @param out Output buffer for processed data (bit-packed)
 * @param outLen Number of bits written to output
 */
void	aesCfb1Update(void			*ctx,
					 const uint8_t	*in,
					 size_t			inLen,
					 uint8_t		*out,
					 size_t			*outLen);

/**
 * @brief Finalizes AES CFB1 operation.
 * 
 * CFB1 mode does not require padding, so this function may be a no-op.
 * 
 * @param ctx Pointer to AES CFB1 context
 * @param out Output buffer for final data (unused)
 * @param outLen Number of bits written to output (set to 0)
 */
void	aesCfb1Final(void *ctx, uint8_t *out, size_t *outLen);

/**
 * @brief Initializes AES CFB8 context with key, IV, and direction.
 * 
 * CFB8 mode operates on bytes, so this function may set up additional state.
 * 
 * @param ctx Pointer to AES CFB8 context
 * @param key Encryption key (16, 24, or 32 bytes)
 * @param keyLen Length of key in bytes
 * @param iv Initialization vector (16 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction
 */
int	aesCfb8Init(void				*ctx,
			   const uint8_t		*key,
			   size_t				keyLen,
			   const uint8_t		*iv,
			   t_cipherDirection	dir);

/* --------- OFB mode functions ---------- */

/**
 * @brief Initializes AES OFB context with key, IV, and direction.
 * 
 * @param ctx Pointer to AES OFB context
 * @param key Encryption key (16, 24, or 32 bytes)
 * @param keyLen Length of key in bytes
 * @param iv Initialization vector (16 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction (OFB uses the same process for both)
 */
int	aesOfbInit(void					*vctx,
			   const uint8_t		*key,
			   size_t				keyLen,
			   const uint8_t		*iv,
			   t_cipherDirection	dir);

/**
 * @brief Updates AES OFB context with input data.
 * 
 * Processes input data in 16-byte blocks with output feedback mode.
 * 
 * @param ctx Pointer to AES OFB context
 * @param in Input data buffer
 * @param inLen Length of input data
 * @param out Output buffer for processed data
 * @param outLen Number of bytes written to output
 */
void	aesOfbUpdate(void			*vctx,
					 const uint8_t	*in,
					 size_t			inLen,
					 uint8_t		*out,
					 size_t			*outLen);

/**
 * @brief Finalizes AES OFB operation.
 * 
 * OFB mode does not require padding, so this function is not needed to do anything,
 * but it is included for interface consistency.
 * 
 * @param ctx Pointer to AES OFB context
 * @param out Output buffer for final data (unused)
 * @param outLen Number of bytes written to output (set to 0)
 */
void	aesOfbFinal(void *vctx, uint8_t *out, size_t *outLen);

/**
 * @brief Frees AES OFB context resources.
 * 
 * @param ctx Pointer to AES OFB context
 */
void	aesOfbFree(void *vctx);

/* ---------- CTR mode functions ---------- */

/**
 * @brief Initializes AES CTR context with key, IV, and direction.
 * 
 * @param ctx Pointer to AES CTR context
 * @param key Encryption key (16, 24, or 32 bytes)
 * @param keyLen Length of key in bytes
 * @param iv Initialization vector (16 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction (CTR uses the same process for both)
 */
int	aesCtrInit(void					*vctx,
			   const uint8_t		*key,
			   size_t				keyLen,
			   const uint8_t		*iv,
			   t_cipherDirection	dir);

/**
 * @brief Updates AES CTR context with input data.
 * 
 * Processes input data in 16-byte blocks with counter mode.
 * 
 * @param ctx Pointer to AES CTR context
 * @param in Input data buffer
 * @param inLen Length of input data
 * @param out Output buffer for processed data
 * @param outLen Number of bytes written to output
 */
void	aesCtrUpdate(void			*vctx,
					 const uint8_t	*in,
					 size_t			inLen,
					 uint8_t		*out,
					 size_t			*outLen);

/**
 * @brief Finalizes AES CTR operation.
 * 
 * CTR mode does not require padding, so this function may be a no-op.
 * 
 * @param ctx Pointer to AES CTR context
 * @param out Output buffer for final data (unused)
 * @param outLen Number of bytes written to output (set to 0)
 */
void	aesCtrFinal(void *vctx, uint8_t *out, size_t *outLen);

/**
 * @brief Frees AES CTR context resources.
 * 
 * @param ctx Pointer to AES CTR context
 */
void	aesCtrFree(void *vctx);

/* ---------- GCM mode functions ---------- */

/**
 * @brief Initializes AES GCM context with key, IV, and direction.
 * 
 * @param ctx Pointer to AES GCM context
 * @param key Encryption key (16, 24, or 32 bytes)
 * @param keyLen Length of key in bytes
 * @param iv Initialization vector (16 bytes, NULL for zeros)
 * @param dir Encryption or decryption direction
 */
int	aesGcmInit(void					*vctx,
			   const uint8_t		*key,
			   size_t				keyLen,
			   const uint8_t		*iv,
			   size_t				ivLen,
			   t_cipherDirection	dir);

/**
 * @brief Updates AES GCM context with additional authenticated data (AAD).
 * 
 * AAD is processed for authentication but not encrypted. This function can be called
 * before or after processing plaintext/ciphertext data.
 *
 * @param ctx Pointer to AES GCM context
 * @param aad Additional authenticated data buffer
 * @param aadLen Length of AAD in bytes
 */
void	aesGcmUpdateAAD(void *vctx, const uint8_t *aad, size_t aadLen);

/**
 * @brief Updates AES GCM context with input data and AAD.
 * 
 * @param ctx Pointer to AES GCM context
 * @param in Input data buffer
 * @param inLen Length of input data
 * @param out Output buffer for processed data
 * @param outLen Number of bytes written to output
 */
void	aesGcmUpdate(void			*vctx,
					 const uint8_t	*in,
					 size_t			inLen,
					 uint8_t		*out,
					 size_t			*outLen);

/**
 * @brief Finalizes AES GCM operation, generating the authentication tag.
 * 
 * @param ctx Pointer to AES GCM context
 * @param out Output buffer for authentication tag
 * @param outLen Number of bytes written to output (set to tag size)
 */
void	aesGcmFinal(void *vctx, uint8_t *out, size_t *outLen);

/**
 * @brief Verifies the AES GCM authentication tag during decryption.
 * 
 * @param ctx Pointer to AES GCM context
 * @param tag Expected authentication tag
 * @param tagLen Length of the tag in bytes
 * @return 0 if the tag is valid, -1 if the data has been tampered with
 */
int	aesGcmVerifyTag(void *vctx, const uint8_t *tag, size_t tagLen);

/**
 * @brief Frees AES GCM context resources.
 * 
 * @param ctx Pointer to AES GCM context
 */
void	aesGcmFree(void *vctx);

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

extern const t_cipher g_aes128CfbCipher;
extern const t_cipher g_aes192CfbCipher;
extern const t_cipher g_aes256CfbCipher;

extern const t_cipher g_aes128Cfb8Cipher;
extern const t_cipher g_aes192Cfb8Cipher;
extern const t_cipher g_aes256Cfb8Cipher;

extern const t_cipher g_aes128Cfb1Cipher;
extern const t_cipher g_aes192Cfb1Cipher;
extern const t_cipher g_aes256Cfb1Cipher;

extern const t_cipher g_aes128OfbCipher;
extern const t_cipher g_aes192OfbCipher;
extern const t_cipher g_aes256OfbCipher;

extern const t_cipher g_aes128CtrCipher;
extern const t_cipher g_aes192CtrCipher;
extern const t_cipher g_aes256CtrCipher;

#endif /* HAJCRYPT_AES_H */
