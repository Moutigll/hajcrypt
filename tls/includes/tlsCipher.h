#ifndef BTLS_CIPHER_H
# define BTLS_CIPHER_H

# include "../../includes/cipher/cipher.h"
# include "../../includes/cipher/des3.h"
# include "../../includes/cipher/des.h"
# include "../../includes/hash/hmac.h"

# include "constants.h"

/**
 * @brief CBC + HMAC context for non‑AEAD cipher simulation
 *
 * This structure is used to simulate AEAD behavior for legacy CBC+HMAC
 * cipher suites (TLS 1.2 and earlier). It holds a pointer to the
 * underlying CBC cipher context, an HMAC context for message
 * authentication, and a small buffer for padding operations during
 * encryption and decryption. The padding buffer is large enough to
 * accommodate the maximum block size (16 bytes for AES).
 */
typedef struct s_cbcHmacCtx
{
	void		*cbcCtx;	/* Pointer to the underlying CBC cipher context */
	t_hmacCtx	hmac;		/* HMAC context for MAC computation */
	uint8_t		padBuffer[16];	/* Temporary buffer for padding operations */
}	t_cbcHmacCtx;

/**
 * @brief Unified TLS record cipher context
 *
 * This structure provides a uniform interface for all TLS record ciphers,
 * abstracting away the differences between AEAD (AES‑GCM, ChaCha20‑Poly1305)
 * and non‑AEAD (CBC+HMAC, stream) ciphers. The API presented to the
 * record layer is identical regardless of the underlying cipher type.
 *
 * For AEAD ciphers, the gcm or chacha fields are used directly and the
 * MAC key is not required. For CBC+HMAC, the cbcHmac field is used and
 * a separate MAC key is provided; the context handles padding, MAC
 * computation, and verification internally, simulating AEAD behavior.
 */
typedef struct s_tlsCipher
{
	const t_tlsCipherSuite	*suite;		/* Pointer to the cipher suite definition */
	t_cipherDirection		dir;		/* Encryption or decryption direction */
	int						isServer;	/* 1 for server, 0 for client */

	/* Key material (cached for re‑initialization) */
	uint8_t				key[64];	/* Encryption key (max 64 for ChaCha20) */
	uint8_t				iv[16];		/* IV / nonce */
	uint8_t				macKey[64];	/* MAC key (CBC+HMAC only) */
	size_t				macKeyLen;	/* Length of MAC key */
	uint64_t			seqNum;		/* Sequence number for record protection */

	/* Cipher‑specific contexts */
	union {
		t_chacha20Poly1305Ctx	chacha;		/* ChaCha20‑Poly1305 context */
		t_aesGcmCtx				gcm;		/* AES‑GCM context */
		t_cbcHmacCtx			cbcHmac;	/* CBC+HMAC context */
	} ctx;

	/* State flags */
	int					initialized;	/* 1 if context is properly initialised */
	int					aadProcessed;	/* 1 if AAD has been processed */
}	t_tlsCipher;

/**
 * @brief Initialise a record cipher context
 *
 * This function initialises a t_tlsCipher context for either AEAD or
 * CBC+HMAC ciphers. The API is identical regardless of the underlying
 * cipher type. For AEAD ciphers, the macKey and macKeyLen parameters
 * should be NULL and 0 respectively. For CBC+HMAC, both encryption key
 * and MAC key are required.
 *
 * @param ctx		Context to initialise
 * @param suite		Cipher suite definition (contains algorithm metadata)
 * @param key		Encryption key
 * @param keyLen	Length of encryption key
 * @param iv		IV / nonce (implicit for AEAD, explicit for CBC)
 * @param ivLen		Length of IV
 * @param macKey	MAC key (NULL for AEAD ciphers)
 * @param macKeyLen	Length of MAC key (0 for AEAD ciphers)
 * @param dir		Encryption or decryption direction
 * @param isServer	1 for server, 0 for client (affects key derivation order)
 * @return			1 on success, 0 on error
 */
int	tlsCipherInit(t_tlsCipher				*ctx,
				  const t_tlsCipherSuite	*suite,
				  const uint8_t				*key,		size_t	keyLen,
				  const uint8_t				*iv,		size_t	ivLen,
				  const uint8_t				*macKey,	size_t	macKeyLen,
				  t_cipherDirection			dir,
				  int						isServer);

/**
 * @brief Unified "seal" operation (encrypt + authenticate)
 *
 * This function behaves like AEAD Seal for all cipher types. For AEAD
 * ciphers, it performs encryption and tag generation. For CBC+HMAC,
 * it performs encryption, computes the HMAC over the ciphertext and
 * AAD, and appends the MAC as the authentication tag. The API is
 * identical regardless of the underlying cipher.
 *
 * @param ctx			Record cipher context
 * @param aad			Additional authenticated data (may be NULL)
 * @param aadLen		Length of AAD
 * @param plaintext		Plaintext to encrypt
 * @param plaintextLen	Length of plaintext
 * @param ciphertext	Output buffer for ciphertext
 * @param tag			Output buffer for authentication tag (16 bytes)
 * @return				1 on success, 0 on error
 */
int	tlsCipherSeal(t_tlsCipher	*ctx,
				  const uint8_t	*aad,		size_t	aadLen,
				  const uint8_t	*plaintext,	size_t	plaintextLen,
				  uint8_t		*ciphertext,
				  uint8_t		*tag);

/**
 * @brief Unified "open" operation (decrypt + verify)
 *
 * This function behaves like AEAD Open for all cipher types. For AEAD
 * ciphers, it performs decryption and tag verification. For CBC+HMAC,
 * it performs decryption, computes the HMAC over the ciphertext and
 * AAD, and verifies it against the provided tag. The API is identical
 * regardless of the underlying cipher.
 *
 * @param ctx			Record cipher context
 * @param aad			Additional authenticated data (may be NULL)
 * @param aadLen		Length of AAD
 * @param ciphertext	Ciphertext to decrypt
 * @param ciphertextLen	Length of ciphertext
 * @param tag			Authentication tag to verify
 * @param tagLen		Length of tag (must be at least 16 for AEAD)
 * @param plaintext		Output buffer for plaintext
 * @return				1 on success (tag valid), 0 on error
 */
int	tlsCipherOpen(t_tlsCipher	*ctx,
				  const uint8_t	*aad,			size_t	aadLen,
				  const uint8_t	*ciphertext,	size_t	ciphertextLen,
				  const uint8_t	*tag,			size_t	tagLen,
				  uint8_t		*plaintext);

/**
 * @brief Free a record cipher context
 *
 * This function securely zeroes all sensitive material in the context
 * (keys, MAC key, IV, sequence number) and releases any internally
 * allocated resources. After calling tlsCipherFree(), the context must
 * not be reused without reinitialisation.
 *
 * @param ctx	Record cipher context to free
 */
void	tlsCipherFree(t_tlsCipher *ctx);

#endif /* BTLS_CIPHER_H */
