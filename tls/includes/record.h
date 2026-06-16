#ifndef BTLS_RECORD_H
# define BTLS_RECORD_H

# include "../../includes/hash/hash.h"
# include "constants.h"
# include "aeadCipher.h"

/**
 * @brief TLS record header structure
 *
 * This structure represents the 5-byte header of a TLS record as defined in
 * RFC 8446 Appendix B. The content type indicates the protocol message type
 * (handshake, application data, alert, or change_cipher_spec). The legacy
 * version field is set to 0x0303 for TLS 1.2 compatibility, even in TLS 1.3.
 * The length field specifies the size of the fragment that follows.
 *
 * struct {
 *	 uint8 content_type;
 *	 uint16 legacy_version;  // always 0x0303 for TLS 1.2 compat
 *	 uint16 length;
 * } TLSRecordHeader;
 */
typedef struct s_tlsRecordHeader
{
	uint8_t		contentType;
	uint16_t	legacyVersion;
	uint16_t	length;
}	t_tlsRecordHeader;

/**
 * @brief TLS record with protected payload
 *
 * This structure holds a complete TLS record including its header and the
 * fragment payload. The fragment can contain either plaintext or ciphertext
 * depending on whether encryption has been applied. The fragment buffer is
 * dynamically allocated and must be freed using tlsRecordFree().
 */
typedef struct s_tlsRecord
{
	t_tlsRecordHeader	header;
	uint8_t				*fragment;
	size_t				fragmentLen;
}	t_tlsRecord;

/**
 * @brief Context for record protection
 *
 * This structure maintains the cryptographic state for record protection
 * including the AEAD cipher context and separate 64-bit sequence numbers
 * for client and server directions. The sequence numbers are used as part
 * of the nonce for AEAD encryption and increment with each record sent
 * in each direction.
 */
typedef struct s_tlsRecordCtx
{
	t_tlsAeadCipher	aeadCtx;		/* AEAD cipher context (keys, IV, type) */
	uint64_t		seqNumClient;	/* Sequence number for client → server */
	uint64_t		seqNumServer;	/* Sequence number for server → client */
	int				isEncrypt;	
}	t_tlsRecordCtx;

/**
 * @brief Initialize record context with traffic secret
 *
 * This function initializes a record protection context by deriving the
 * encryption key and IV from the provided traffic secret using HKDF.
 * The key and IV lengths are determined by the cipher type (16 or 32 bytes
 * for AES, 32 bytes for ChaCha20 key, 12 bytes IV for all). The sequence
 * numbers are initialized to zero.
 *
 * @param ctx			Record context to initialize
 * @param cipherType	AEAD cipher to use
 * @param secret		Traffic secret (clientHandshakeTrafficSecret, etc.)
 * @param secretLen		Length of the secret
 * @param hash			Hash algorithm for HKDF
 * @return				1 on success, 0 on error
 */
int	tlsRecordCtxInit(t_tlsRecordCtx		*ctx,
					 t_tlsCipherType	cipherType,
					 const uint8_t		*secret,
					 size_t				secretLen,
					 const t_hash		*hash,
					 int				isEncrypt);

/**
 * @brief Free record context (zero sensitive data)
 *
 * This function securely zeros all sensitive material in the record context
 * including keys, IVs, and sequence numbers. After freeing, the context
 * should not be reused without reinitialization.
 *
 * @param ctx	Record context to free
 */
void	tlsRecordCtxFree(t_tlsRecordCtx *ctx);

/**
 * @brief Encrypt a TLS record
 *
 * This function encrypts a plaintext TLS record using the AEAD cipher
 * configured in the context. It constructs the additional authenticated
 * data (AAD) from the record header and sequence number, then encrypts
 * the fragment using the appropriate key and nonce based on the direction.
 * The encrypted record includes the authentication tag appended to the
 * ciphertext. The sequence number is incremented after successful encryption.
 *
 * @param ctx			Record context (contains keys and seq number)
 * @param record		Record to encrypt (plaintext fragment)
 * @param isClient		1 if client sending, 0 if server sending
 * @param output		Output buffer for encrypted record
 * @param outputLen		Pointer to output length
 * @return				1 on success, 0 on error
 */
int	tlsRecordEncrypt(t_tlsRecordCtx	*ctx,
					 const uint8_t	*fragment,	size_t	fragmentLen,
					 uint8_t		innerType,
					 int			isClient,
					 uint8_t		*output,	size_t	*outputLen);

/**
 * @brief Decrypt a TLS record
 *
 * This function decrypts an encrypted TLS record using the AEAD cipher
 * configured in the context. It reconstructs the AAD from the record header
 * and sequence number, then decrypts and verifies the authentication tag.
 * If tag verification fails, the function returns an error and the output
 * data must not be used. The sequence number is incremented after successful
 * decryption.
 *
 * @param ctx			Record context (contains keys and seq number)
 * @param ciphertext	Encrypted record data (including header)
 * @param ciphertextLen	Length of ciphertext
 * @param isClient		1 if client receiving, 0 if server receiving
 * @param output		Output buffer for decrypted plaintext
 * @param outputLen		Pointer to output length
 * @return				1 on success, 0 on error (including tag mismatch)
 */
int	tlsRecordDecrypt(t_tlsRecordCtx	*ctx,
					 const uint8_t	*ciphertext,	size_t	ciphertextLen,
					 int			isClient,
					 uint8_t		*fragment,		size_t	*fragmentLen,
					 uint8_t		*innerType);

/**
 * @brief Build a plaintext record from data
 *
 * This function constructs a plaintext TLS record from raw payload data.
 * It sets the content type, legacy version (0x0303), and length fields
 * in the header. A fragment buffer is allocated to hold the provided data.
 * The resulting record is ready for encryption or further processing.
 *
 * @param contentType	Content type (handshake, app data, etc.)
 * @param data			Payload data
 * @param dataLen		Payload length
 * @param record		Output record structure
 * @return				1 on success, 0 on error
 */
int	tlsRecordBuild(uint8_t			contentType,
				   const uint8_t	*data,
				   size_t			dataLen,
				   t_tlsRecord		*record);

/**
 * @brief Free record resources
 *
 * This function releases the fragment buffer allocated for a TLS record
 * and securely zeros it before freeing. The fragment pointer is set to NULL
 * to prevent double free attempts. The header structure is left untouched.
 *
 * @param record	Record to free
 */
void	tlsRecordFree(t_tlsRecord *record);

/**
 * @brief Reset sequence numbers (for key update)
 *
 * This function resets both client and server sequence numbers to zero.
 * It is used when performing a key update operation as specified in
 * RFC 8446 Section 6.1. After a key update, new sequence numbers start
 * from zero for the new encryption keys.
 *
 * @param ctx	Record context
 */
void	tlsRecordResetSeqNum(t_tlsRecordCtx *ctx);

#endif /* BTLS_RECORD_H */
