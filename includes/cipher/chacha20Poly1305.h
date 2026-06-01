#ifndef HAJCRYPT_CHACHA20_POLY1305_H
#define HAJCRYPT_CHACHA20_POLY1305_H

#include "cipher.h"

#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
# define CHACHA_USE_NEON
#endif

/* ChaCha20 constants */
#define CHACHA20_BLOCK_SIZE		64	/* ChaCha20 block size in bytes */
#define CHACHA20_KEY_SIZE		32	/* ChaCha20 key size in bytes (256 bits) */
#define CHACHA20_NONCE_SIZE		12	/* ChaCha20 nonce size in bytes (96 bits) - TLS 1.3 standard */
#define CHACHA20_COUNTER_SIZE	4	/* Counter size in bytes (32 bits) */

/* Poly1305 constants */
#define POLY1305_KEY_SIZE	32	/* Poly1305 key size in bytes (r + s) */
#define POLY1305_TAG_SIZE	16	/* Poly1305 authentication tag size in bytes */

/* ChaCha20-Poly1305 AEAD constants */
#define CHACHA20_POLY1305_TAG_SIZE		16  /* AEAD authentication tag size */
#define CHACHA20_POLY1305_BLOCK_SIZE	16  /* Block size for AAD and data processing in Poly1305 */

/* ChaCha20 block matrix indices */
#define CHACHA20_CONSTANT_0	0x61707865	/* "expa" - constant for ChaCha20 state */
#define CHACHA20_CONSTANT_1	0x3320646e	/* "nd 3" - constant for ChaCha20 state */
#define CHACHA20_CONSTANT_2	0x79622d32	/* "2-by" - constant for ChaCha20 state */
#define CHACHA20_CONSTANT_3	0x6b206574	/* "te k" - constant for ChaCha20 state */

/* Poly1305 bit masks (RFC 7539) */
#define POLY1305_R_MASK			UINT64_C(0x0ffffffc0ffffffc)
#define POLY1305_R_MASK_LAST	UINT64_C(0x0ffffffc0ffffffc)

/**
 * @brief ChaCha20 core context structure.
 * 
 * Maintains state for ChaCha20 keystream generation.
 * Used internally by the AEAD implementation.
 */
typedef struct s_chacha20Ctx
{
	uint32_t	state[16];						/* 4x4 matrix state (16 words of 32 bits) */
	uint8_t		keystream[CHACHA20_BLOCK_SIZE];	/* Current keystream block */
	size_t		keystreamPos;					/* Position in current keystream block */
} t_chacha20Ctx;

/**
 * @brief Poly1305 core context structure.
 * 
 * Maintains state for Poly1305 authentication tag generation.
 * Used internally by the AEAD implementation.
 */
typedef struct s_poly1305Ctx
{
	uint32_t	r[5];		/* r value (clamped) in 130-bit representation */
	uint32_t	s[4];		/* s value (key part) */
	uint32_t	h[5];		/* Current hash value (130 bits) */
	uint8_t		buffer[16];	/* Input buffer for partial blocks */
	size_t		bufferLen;	/* Length of data in buffer */
	uint64_t	totalLen;	/* Total length of processed data */
} t_poly1305Ctx;

/**
 * @brief ChaCha20-Poly1305 AEAD context structure.
 * 
 * Maintains state for ChaCha20-Poly1305 authenticated encryption/decryption
 * as specified in RFC 7539 for TLS 1.3 and other protocols.
 */
typedef struct s_chacha20Poly1305Ctx {
	t_cipherDirection	dir;
	t_chacha20Ctx		chachaCtx;
	t_poly1305Ctx		polyCtx;
	uint8_t				polyKey[POLY1305_KEY_SIZE];
	uint8_t				aadBuffer[CHACHA20_POLY1305_BLOCK_SIZE];
	size_t				aadBufferLen;
	uint8_t				dataBuffer[CHACHA20_POLY1305_BLOCK_SIZE];
	size_t				dataBufferLen;
	uint64_t			aadTotalLen;
	uint64_t			dataTotalLen;
	uint8_t				tag[CHACHA20_POLY1305_TAG_SIZE];
	int					tagValid;
} t_chacha20Poly1305Ctx;

/* ---------- Core ChaCha20 operations ---------- */

/**
 * @brief Initializes a ChaCha20 context with key, nonce, and counter.
 * 
 * The initial state is constructed using the 4 constants, the 8 key words,
 * the 3 nonce words, and the counter word as specified in RFC 7539.
 * 
 * @param ctx Pointer to ChaCha20 context
 * @param key 32-byte encryption key
 * @param nonce 12-byte nonce (96 bits) - standard for TLS 1.3
 * @param counter Initial counter value (typically 0)
 */
void	chacha20Init(t_chacha20Ctx	*ctx,
					 const uint8_t	key[CHACHA20_KEY_SIZE],
					 const uint8_t	nonce[CHACHA20_NONCE_SIZE],
					 uint32_t		counter);

/**
 * @brief Generates the next keystream block from ChaCha20.
 * 
 * Processes one block (64 bytes) of keystream by applying the ChaCha20
 * quarter round operations for 20 rounds (10 iterations of column/diagonal rounds).
 * 
 * @param ctx Pointer to ChaCha20 context
 * @param keystream Output buffer for 64-byte keystream block
 */
void	chacha20NextBlock(t_chacha20Ctx *ctx, uint8_t keystream[CHACHA20_BLOCK_SIZE]);

/**
 * @brief Generates keystream of arbitrary length from ChaCha20.
 * 
 * Generates keystream by producing consecutive blocks, updating the counter
 * automatically. The output can be used for XOR-based encryption/decryption.
 * 
 * @param ctx Pointer to ChaCha20 context
 * @param keystream Output buffer for keystream
 * @param len Length of keystream to generate in bytes
 */
void	chacha20GenerateKeystream(t_chacha20Ctx *ctx, uint8_t *keystream, size_t len);

/**
 * @brief Encrypts/decrypts data using ChaCha20 stream cipher.
 * 
 * XORs the input data with the generated keystream. Since ChaCha20 is a
 * stream cipher, encryption and decryption are identical operations.
 * 
 * @param ctx Pointer to ChaCha20 context
 * @param input Input data buffer
 * @param output Output buffer for processed data (can overlap with input)
 * @param len Length of data to process in bytes
 */
void	chacha20Crypt(t_chacha20Ctx *ctx, const uint8_t *input, uint8_t *output, size_t len);

/**
 * @brief Clear the context of ChaCha20 by zeroing sensitive data.
 * 
 * @param ctx Pointer to ChaCha20 context
 */
void	chacha20Free(void *vctx);

/* ---------- Core Poly1305 operations ---------- */

/**
 * @brief Initializes a Poly1305 context with a 32-byte key.
 * 
 * Splits the key into r (clamped) and s values. The r value is clamped
 * by masking specific bits as required by the Poly1305 specification.
 * 
 * @param ctx Pointer to Poly1305 context
 * @param key 32-byte key (first 16 bytes for r, last 16 bytes for s)
 */
void	poly1305Init(t_poly1305Ctx *ctx, const uint8_t key[POLY1305_KEY_SIZE]);

/**
 * @brief Updates Poly1305 context with additional input data.
 * 
 * Processes input data in 16-byte blocks, accumulating the polynomial hash.
 * Partial blocks are buffered for the next update or final call.
 * 
 * @param ctx Pointer to Poly1305 context
 * @param data Input data buffer
 * @param len Length of input data in bytes
 */
void	poly1305Update(t_poly1305Ctx *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finalizes Poly1305 computation and produces authentication tag.
 * 
 * Processes the final block (with padding), adds the s value, and produces
 * the 16-byte authentication tag in little-endian order.
 * 
 * @param ctx Pointer to Poly1305 context
 * @param tag Output buffer for 16-byte authentication tag
 */
void	poly1305Final(t_poly1305Ctx *ctx, uint8_t tag[POLY1305_TAG_SIZE]);

/* ---------- ChaCha20-Poly1305 AEAD operations ---------- */

/**
 * @brief Initializes ChaCha20-Poly1305 context for AEAD operation.
 * 
 * Derives the Poly1305 key from the first ChaCha20 keystream block (counter=0)
 * and initializes both the cipher and authentication contexts.
 * 
 * @param ctx Pointer to ChaCha20-Poly1305 context
 * @param key 32-byte encryption key
 * @param nonce 12-byte nonce (96 bits) - standard for TLS 1.3
 * @param dir Encryption or decryption direction
 * 
 * @return 0 on success, -1 on error (invalid parameters)
 */
int	 chacha20Poly1305Init(void				*ctx,
						  const uint8_t		*key,
						  size_t			keyLen,
						  const uint8_t		*nonce,
						  t_cipherDirection	dir);

/**
 * @brief Processes additional authenticated data (AAD).
 * 
 * AAD is authenticated but not encrypted. This function MUST be called
 * before processing the actual data (plaintext/ciphertext).
 * 
 * @param ctx Pointer to ChaCha20-Poly1305 context
 * @param aad Additional authenticated data buffer
 * @param aadLen Length of AAD in bytes
 */
void	chacha20Poly1305UpdateAAD(void *ctx, const uint8_t *aad, size_t aadLen);

/**
 * @brief Updates ChaCha20-Poly1305 context with input data.
 * 
 * For encryption: XORs plaintext with ChaCha20 keystream (counter starting at 1)
 * and updates Poly1305 with the resulting ciphertext.
 * For decryption: XORs ciphertext with ChaCha20 keystream and updates Poly1305
 * with the ciphertext (before decryption).
 * 
 * @param ctx Pointer to ChaCha20-Poly1305 context
 * @param in Input data buffer (plaintext for encryption, ciphertext for decryption)
 * @param inLen Length of input data in bytes
 * @param out Output buffer for processed data (ciphertext for encryption, plaintext for decryption)
 * @param outLen Number of bytes written to output
 */
void	chacha20Poly1305Update(void *ctx, const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen);

/**
 * @brief Finalizes ChaCha20-Poly1305 operation and outputs authentication tag.
 * 
 * For encryption: computes the authentication tag over AAD and ciphertext,
 * and outputs it. The tag should be appended to the ciphertext.
 * For decryption: computes the expected tag and compares it with the provided tag.
 * 
 * @param ctx Pointer to ChaCha20-Poly1305 context
 * @param out Output buffer for authentication tag (encryption) or NULL (decryption)
 * @param outLen Number of bytes written to output (always 16 if tag output)
 */
void	chacha20Poly1305Final(void *ctx, uint8_t *out, size_t *outLen);

/**
 * @brief Verifies the authentication tag during decryption.
 * 
 * Compares the computed tag with the expected tag using constant-time comparison
 * to prevent timing attacks. Must be called after finalization.
 * 
 * @param ctx Pointer to ChaCha20-Poly1305 context
 * @param tag Expected authentication tag (16 bytes)
 * @param tagLen Length of the tag in bytes (must be 16 for RFC 7539)
 * @return 0 if tag is valid, -1 if verification fails
 */
int	 chacha20Poly1305VerifyTag(void *ctx, const uint8_t *tag, size_t tagLen);

/**
 * @brief Frees ChaCha20-Poly1305 context resources.
 * 
 * Securely zeroes sensitive material in the context.
 * 
 * @param ctx Pointer to ChaCha20-Poly1305 context
 */
void	chacha20Poly1305Free(void *ctx);

/* ---------- Convenience AEAD functions ---------- */

/**
 * @brief One-shot ChaCha20-Poly1305 authenticated encryption.
 * 
 * Encrypts plaintext and authenticates both AAD and ciphertext in a single call.
 * Equivalent to calling init, updateAAD, update, final sequentially.
 * 
 * @param key 32-byte encryption key
 * @param nonce 12-byte nonce (96 bits)
 * @param aad Additional authenticated data (can be NULL if aadLen == 0)
 * @param aadLen Length of AAD in bytes
 * @param plaintext Plaintext data to encrypt
 * @param plaintextLen Length of plaintext in bytes
 * @param ciphertext Output buffer for ciphertext (must be at least plaintextLen bytes)
 * @param tag Output buffer for 16-byte authentication tag
 * @return 0 on success, -1 on error
 */
int	 chacha20Poly1305Seal(const uint8_t	key[CHACHA20_KEY_SIZE],
						  const uint8_t	nonce[CHACHA20_NONCE_SIZE],
						  const uint8_t	*aad,			size_t aadLen,
						  const uint8_t	*plaintext,		size_t plaintextLen,
						  uint8_t		*ciphertext,	uint8_t tag[CHACHA20_POLY1305_TAG_SIZE]);

/**
 * @brief One-shot ChaCha20-Poly1305 authenticated decryption.
 * 
 * Decrypts ciphertext and verifies authentication tag in a single call.
 * Equivalent to calling init, updateAAD, update, final, verifyTag sequentially.
 * 
 * @param key 32-byte encryption key
 * @param nonce 12-byte nonce (96 bits)
 * @param aad Additional authenticated data (must match encryption)
 * @param aadLen Length of AAD in bytes
 * @param ciphertext Ciphertext data to decrypt
 * @param ciphertextLen Length of ciphertext in bytes
 * @param plaintext Output buffer for plaintext (must be at least ciphertextLen bytes)
 * @param tag Authentication tag (16 bytes) from encryption
 * @return 0 on success (tag valid), -1 on error or tag mismatch
 */
int	 chacha20Poly1305Open(const uint8_t		key[CHACHA20_KEY_SIZE],
							 const uint8_t	nonce[CHACHA20_NONCE_SIZE],
							 const uint8_t	*aad,			size_t aadLen,
							 const uint8_t	*ciphertext,	size_t ciphertextLen,
							 uint8_t		*plaintext,		const uint8_t tag[CHACHA20_POLY1305_TAG_SIZE]);

/* ---------- Global cipher structures for dispatch table ---------- */

/**
 * @brief ChaCha20-Poly1305 AEAD cipher structure for dispatch table.
 * 
 * Implements the t_cipher interface for ChaCha20-Poly1305 AEAD mode.
 * This is the primary interface for TLS 1.3 and other protocols.
 */
extern const t_cipher	g_chacha20Cipher;

#endif /* HAJCRYPT_CHACHA20_POLY1305_H */
