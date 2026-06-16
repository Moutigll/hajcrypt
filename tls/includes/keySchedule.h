#ifndef BTLS_KEY_SCHEDULE_H
# define BTLS_KEY_SCHEDULE_H

# include "../../includes/hash/hmac.h"

#define BTLS13_PSK_ENABLED	1	/* Set to 1 to enable PSK support, 0 to disable */

/**
 * @brief Structure containing all derived secrets for a TLS 1.3 connection
 *
 * This structure holds all the cryptographic secrets derived during a TLS 1.3
 * handshake according to RFC 8446. The array sizes are fixed at 64 bytes to
 * accommodate both SHA-256 (32 bytes) and SHA-384 (48 bytes) output sizes,
 * with extra space for potential future hash algorithms. The handshake secret
 * is derived from the ECDHE shared secret, then used to generate traffic
 * secrets for handshake and application data encryption.
 */
typedef struct s_tls13Secrets
{
	/* Base secrets */
	uint8_t			earlySecret[64];					/* Eventual Pre-Shared Key (PSK) to re-establish the connection faster, or zeros if not used */
	uint8_t			handshakeSecret[64];				/* Derived from the shared secret of the key exchange (ECDHE/FFDHE) */
	uint8_t			masterSecret[64];					/* Derived from the handshake secret after the handshake completes */

	/* Traffic secrets */
	uint8_t			clientEarlyTrafficSecret[64];		/* Used to derive keys for encrypting client's early data (0-RTT) */
	uint8_t			clientHandshakeTrafficSecret[64];	/* Used to derive keys for encrypting client's handshake messages */
	uint8_t			serverHandshakeTrafficSecret[64];	/* Used to derive keys for encrypting server's handshake messages */
	uint8_t			clientAppTrafficSecret[64];			/* Used to derive keys for encrypting client's application messages */
	uint8_t			serverAppTrafficSecret[64];			/* Used to derive keys for encrypting server's application messages */
	
	/* Export Secrets */
	uint8_t			exporterMasterSecret[64];			/* Used to derive keys for the exporter function */
	uint8_t			resumptionMasterSecret[64];			/* Used to derive keys for resuming sessions */

	/* Binder secrets (for PSK authentication) */
	uint8_t			externalBinderKey[64];				/* Derived from the external PSK for use in the binder */
	uint8_t			resumptionBinderKey[64];			/* Derived from the resumption PSK for use in the binder */

	const t_hash	*hash;								/* Pointer to the hash algorithm used */
	int				pskEnabled;							/* Flag indicating whether PSK is used (1 if PSK is used, 0 otherwise) */
}	t_tls13Secrets;

/**
 * @brief Structure for encryption keys derived from a traffic secret
 *
 * This structure holds the actual encryption key and initialization vector
 * derived from a traffic secret using HKDF. The key length varies depending
 * on the cipher suite (16 bytes for AES-128, 32 bytes for AES-256), while
 * the IV is always 12 bytes for AEAD ciphers used in TLS 1.3.
 */
typedef struct s_tls13TrafficKeys
{
	uint8_t	key[32];	/* Encryption key (max 32 for AES-256) */
	uint8_t	iv[12];		/* IV (12 bytes for AEAD) */
	size_t	keyLen;		/* Actual key length (16 or 32) */
	size_t	ivLen;		/* Actual IV length (12) */
}	t_tls13TrafficKeys;

/**
 * @brief Derive-Secret(secret, label, context)
 *
 * Implements the formula: HKDF-Expand-Label(secret, label, context, hashLen)
 * This is the core derivation function used throughout TLS 1.3 key schedule.
 *
 * @param secret		Input secret
 * @param secretLen		Length of the secret
 * @param label			Label (e.g., "handshake", "c hs traffic")
 * @param context		Context (hash of messages)
 * @param contextLen	Length of the context
 * @param output		Output buffer
 * @param outputLen		Desired length (typically hashLen)
 * @param hash			Hash algorithm to use
 * @return				1 on success, 0 on error
 */
int	tls13DeriveSecret(const uint8_t	*secret,	size_t	secretLen,
					  const char	*label,
					  const uint8_t	*context,	size_t	contextLen,
					  uint8_t		*output,	size_t	outputLen,
					  const t_hash	*hash);

/**
 * @brief Initializes the secrets structure with default parameters
 *
 * This function must be called before any other key schedule operations.
 * It sets the hash algorithm to be used for all subsequent HKDF operations
 * and zeros out all secret buffers for security.
 *
 * @param secrets	Structure to initialize
 * @param hash		Hash algorithm to use (g_sha256Hash or g_sha384Hash)
 */
void	tls13KeyScheduleInit(t_tls13Secrets *secrets, const t_hash *hash);

/**
 * @brief Derives handshakeSecret from the shared secret (ECDHE/FFDHE)
 *
 * This function performs the first HKDF-Extract operation using the shared
 * secret from the key exchange as IKM and the hash algorithm's zero string
 * as salt. The output is stored as the handshake secret.
 *
 * @param secrets		Secrets structure (already initialized)
 * @param psk			Optional PSK for early secret (can be NULL if not used)
 * @param pskLen		Length of the PSK (0 if not used)
 * @param sharedSecret	Shared secret from key exchange
 * @param sharedLen		Length of the shared secret
 * @return				1 on success, 0 on error
 */
int	tls13KeyScheduleExtractHandshake(t_tls13Secrets	*secrets,
									 const uint8_t	*psk,			size_t pskLen,
									 const uint8_t	*sharedSecret,	size_t sharedLen);

/**
 * @brief Derives handshake traffic secrets
 *
 * Must be called after receiving/sending hello messages. This function derives
 * both client and server handshake traffic secrets using HKDF-Expand-Label
 * with the labels "c hs traffic" and "s hs traffic".
 *
 * @param secrets		Secrets structure
 * @param handshakeHash	Hash of all handshake messages so far
 * @param hashLen		Length of the hash
 * @return				1 on success, 0 on error
 */
int	tls13KeyScheduleDeriveHandshakeSecrets(t_tls13Secrets	*secrets,
											const uint8_t	*handshakeHash,
											size_t			hashLen);

/**
 * @brief Derives application traffic secrets
 *
 * This function derives client and server application traffic secrets from
 * the master secret using the labels "c ap traffic" and "s ap traffic".
 * These secrets are used to encrypt application data after the handshake
 * completes.
 *
 * @param secrets		Secrets structure
 * @param handshakeHash	Final handshake hash (for derive_context)
 * @param hashLen		Length of the hash
 * @return				1 on success, 0 on error
 */
int	tls13KeyScheduleDeriveAppSecrets(t_tls13Secrets	*secrets,
									  const uint8_t		*handshakeHash,
									  size_t			hashLen);

/**
 * @brief Derives actual encryption keys from a traffic secret
 *
 * This function expands a traffic secret into an encryption key and IV
 * using HKDF-Expand-Label with the labels "key" and "iv". The key length
 * is determined by the cipher suite (AES-128 uses 16 bytes, AES-256 uses
 * 32 bytes). The IV is always 12 bytes for TLS 1.3 AEAD ciphers.
 *
 * @param keys			Output structure for keys
 * @param secret		Traffic secret (e.g., clientHandshakeTrafficSecret)
 * @param secretLen		Length of the secret
 * @param hash			Hash algorithm to use
 * @param cipherKeyLen	Cipher key length (16 for AES-128, 32 for AES-256)
 * @return				1 on success, 0 on error
 */
int	tls13DeriveTrafficKeys(t_tls13TrafficKeys	*keys,
						   const uint8_t		*secret,
						   size_t				secretLen,
						   const t_hash			*hash,
						   size_t				cipherKeyLen);



/**
 * @brief Prints the secrets (debug)
 *
 * This function is intended for debugging purposes only. It prints all
 * secrets stored in the t_tls13Secrets structure in hexadecimal format.
 * Should not be used in production code.
 *
 * @param secrets	Secrets structure
 */
void	tls13PrintSecrets(const t_tls13Secrets *secrets);

#endif /* BTLS_KEY_SCHEDULE_H */
