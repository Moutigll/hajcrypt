#ifndef BTLS_AEAD_CIPHER_H
# define BTLS_AEAD_CIPHER_H

# include "../../includes/cipher/aes.h"
# include "../../includes/cipher/chacha20Poly1305.h"

/**
 * @brief AEAD cipher type for record protection
 *
 * This enumeration lists the supported AEAD cipher types for TLS 1.3 record
 * protection. AES-128-GCM and AES-256-GCM are mandatory cipher suites as
 * specified in RFC 8446
 */
typedef enum e_tlsCipherType
{
	BTLS_CIPHER_AES_128_GCM,
	BTLS_CIPHER_AES_256_GCM,
	BTLS_CIPHER_CHACHA20_POLY1305
}	t_tlsCipherType;

/**
 * @brief Unified AEAD cipher context
 *
 * This structure abstracts the differences between AES-GCM and
 * ChaCha20-Poly1305, providing a common interface for TLS record
 * protection. The union stores the cipher-specific context while
 * the common fields track metadata and cached key material for
 * potential re-initialization or key updates.
 */
typedef struct s_tlsAeadCipher
{
	t_tlsCipherType		type;
	size_t				keyLen;
	size_t				ivLen;
	size_t				tagLen;
	union
	{
		t_aesGcmCtx				gcm;
		t_chacha20Poly1305Ctx	chacha;
	} ctx;
	t_cipherDirection	dir;
	uint8_t				key[32];
	uint8_t				iv[12];
	size_t				keyLenCache;
	size_t				ivLenCache;
}	t_tlsAeadCipher;

/**
 * @brief Initialize an AEAD cipher context
 *
 * This function initializes the AEAD cipher context for the specified
 * cipher type, key, IV, and direction. The key and IV are cached for
 * potential re-initialization. For AES-GCM, the internal round keys
 * are expanded and the GHASH key H is precomputed. For ChaCha20-Poly1305,
 * the initial block counter is set appropriately.
 *
 * @param ctx		Pointer to the AEAD cipher context
 * @param type		Cipher type (AES-128-GCM, AES-256-GCM, or ChaCha20-Poly1305)
 * @param key		Encryption key
 * @param keyLen	Length of the key (16 for AES-128, 32 for AES-256, 32 for ChaCha20)
 * @param iv		Initialization vector (nonce)
 * @param ivLen		Length of the IV (12 for TLS 1.3)
 * @param dir		Encryption or decryption direction
 * @return			1 on success, 0 on error
 */
int	tlsAeadCipherInit(t_tlsAeadCipher	*ctx,
					  t_tlsCipherType	type,
					  const uint8_t		*key,
					  size_t			keyLen,
					  const uint8_t		*iv,
					  size_t			ivLen,
					  t_cipherDirection	dir);

/**
 * @brief Add additional authenticated data (AAD)
 *
 * This function processes additional authenticated data that will be
 * authenticated but not encrypted. In TLS 1.3, the AAD consists of the
 * record header and the sequence number encoded as described in RFC 8446.
 * This function can be called multiple times to provide AAD in chunks.
 *
 * @param ctx		AEAD cipher context
 * @param aad		Additional authenticated data
 * @param aadLen	Length of AAD in bytes
 */
void	tlsAeadCipherUpdateAAD(t_tlsAeadCipher	*ctx,
							  const uint8_t		*aad,
							  size_t			aadLen);

/**
 * @brief Encrypt or decrypt data
 *
 * For encryption: transforms plaintext into ciphertext.
 * For decryption: transforms ciphertext into plaintext.
 * In both cases, the authentication tag is not processed here but
 * will be handled by tlsAeadCipherFinal(). The output buffer must
 * be large enough to hold the processed data.
 *
 * @param ctx		AEAD cipher context
 * @param in		Input data buffer
 * @param inLen		Length of input data
 * @param out		Output buffer
 * @param outLen	Pointer to output length
 */
void	tlsAeadCipherUpdate(t_tlsAeadCipher	*ctx,
						   const uint8_t	*in,
						   size_t			inLen,
						   uint8_t			*out,
						   size_t			*outLen);

/**
 * @brief Finalize AEAD operation and get/set tag
 *
 * For encryption: finalizes the encryption and outputs the authentication
 * tag computed over the AAD and ciphertext.
 * For decryption: finalizes the decryption and verifies the provided
 * authentication tag. If the tag is invalid, the function returns an
 * error and the decrypted data must not be used.
 *
 * @param ctx		AEAD cipher context
 * @param tag		Tag buffer (input for decryption, output for encryption)
 * @param tagLen	Length of the tag (must be 16 for TLS 1.3)
 * @return			1 on success (tag valid for decryption), 0 on error
 */
int	tlsAeadCipherFinal(t_tlsAeadCipher	*ctx,
					   uint8_t			*tag,
					   size_t			tagLen);

/**
 * @brief One-shot AEAD encryption (Seal)
 *
 * This convenience function combines initialization, AAD processing,
 * encryption, and finalization into a single call. It is suitable for
 * encrypting complete TLS records where all data is available at once.
 * The ciphertext is written to the output buffer and the authentication
 * tag is written to the tag buffer.
 *
 * @param type			Cipher type
 * @param key			Encryption key
 * @param keyLen		Key length
 * @param iv			IV/Nonce
 * @param ivLen			IV length
 * @param aad			Additional authenticated data
 * @param aadLen		AAD length
 * @param plaintext		Plaintext to encrypt
 * @param plaintextLen	Plaintext length
 * @param ciphertext	Output buffer for ciphertext
 * @param tag			Output buffer for authentication tag (16 bytes)
 * @return				1 on success, 0 on error
 */
int	tlsAeadSeal(t_tlsCipherType	type,
				const uint8_t	*key,		size_t	keyLen,
				const uint8_t	*iv,		size_t	ivLen,
				const uint8_t	*aad,		size_t	aadLen,
				const uint8_t	*plaintext,	size_t	plaintextLen,
				uint8_t			*ciphertext,
				uint8_t			*tag);

/**
 * @brief One-shot AEAD decryption (Open)
 *
 * This convenience function combines initialization, AAD processing,
 * decryption, and tag verification into a single call. It is suitable
 * for decrypting complete TLS records. The tag is verified internally
 * during finalization; if verification fails, no plaintext is produced.
 *
 * @param type			Cipher type
 * @param key			Encryption key
 * @param keyLen		Key length
 * @param iv			IV/Nonce
 * @param ivLen			IV length
 * @param aad			Additional authenticated data
 * @param aadLen		AAD length
 * @param ciphertext	Ciphertext to decrypt
 * @param ciphertextLen	Ciphertext length
 * @param plaintext		Output buffer for plaintext
 * @param tag			Authentication tag (16 bytes)
 * @return				1 on success (tag valid), 0 on error
 */
int	tlsAeadOpen(t_tlsCipherType	type,
				const uint8_t	*key,			size_t	keyLen,
				const uint8_t	*iv,			size_t	ivLen,
				const uint8_t	*aad,			size_t	aadLen,
				const uint8_t	*ciphertext,	size_t	ciphertextLen,
				uint8_t			*plaintext,
				const uint8_t	*tag);

/**
 * @brief Free AEAD cipher context (zero sensitive data)
 *
 * This function securely zeros all sensitive material in the AEAD cipher
 * context including keys, IVs, and cipher-specific internal state. After
 * freeing, the context should not be reused without reinitialization.
 *
 * @param ctx	AEAD cipher context
 */
void	tlsAeadCipherFree(t_tlsAeadCipher *ctx);

/**
 * @brief Get cipher parameters
 *
 * This utility function returns the key length, IV length, and tag length
 * for a given cipher type. It is useful for allocating buffers and validating
 * parameters before initializing a cipher context.
 *
 * @param type		Cipher type
 * @param keyLen	Output: key length in bytes
 * @param ivLen		Output: IV length in bytes
 * @param tagLen	Output: tag length in bytes
 * @return			1 on success, 0 on error (invalid type)
 */
int	tlsAeadGetParams(t_tlsCipherType	type,
					 size_t				*keyLen,
					 size_t				*ivLen,
					 size_t				*tagLen);

#endif /* BTLS_AEAD_CIPHER_H */
