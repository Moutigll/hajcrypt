#ifndef HAJCRYPT_ECDSA_H
# define HAJCRYPT_ECDSA_H

# include "ecdh.h"
# include "pkey.h"

/**
 * @brief Structure representing an ECDSA key pair
 *
 * This type alias reuses the ECDH context structure because ECDSA uses
 * the same curve parameters and key format as ECDH. The private key is
 * a big integer in the range [1, n-1], and the public key is a point
 * on the curve (X, Y coordinates).
 */
typedef t_ecdhCtx t_ecdsaKey;

extern const t_pkeyDef g_ecdsaPkeyDef;

/**
 * @brief Generate an ECDSA key pair on a given curve
 *
 * This function generates a random private key in the range [1, n-1]
 * (where n is the order of the base point) and computes the corresponding
 * public key point by scalar multiplication of the base point with the
 * private key. The results are stored in the key structure.
 *
 * @param key	Pointer to the ECDSA key structure (t_ecdhCtx)
 * @param curve	Curve identifier (ECDH_GROUP_SECP256R1, etc.)
 * @return		1 on success, 0 on error
 */
int	ecdsaGenerateKey(t_ecdsaKey *key, int curve);

/**
 * @brief Free an ECDSA key
 *
 * This function securely zeroises and frees all resources associated
 * with the ECDSA key (private key, public coordinates, curve parameters).
 * After this call, the key structure must not be reused unless reinitialised.
 *
 * @param key	Pointer to the ECDSA key structure
 */
void	ecdsaFreeKey(t_ecdsaKey *key);

/**
 * @brief Sign a digest using ECDSA
 *
 * This function computes an ECDSA signature (r, s) over the provided
 * digest. The signature is encoded as a DER-encoded SEQUENCE of two
 * INTEGERs (r and s). The digest should already be hashed using the
 * appropriate algorithm for the curve size. For ECDSA, only
 * PKEY_PADDING_NONE is supported.
 *
 * @param digest		Pre-computed hash of the message
 * @param digestLen		Length of the digest
 * @param digestAlgo	Algorithm used to produce the digest (may be NULL)
 * @param key			Private key
 * @param sig			Output buffer for the signature
 * @param sigLen		[in] Buffer size, [out] Signature length
 * @param padding		Padding scheme (only PKEY_PADDING_NONE for ECDSA)
 * @return				1 on success, 0 on error
 */
int	ecdsaSign(const uint8_t		*digest,	size_t	digestLen,
			  const t_algoId	*digestAlgo,
			  const void		*key,
			  uint8_t			*sig,		size_t	*sigLen,
			  t_pkeyPadding		padding);

/**
 * @brief Verify an ECDSA signature
 *
 * This function verifies an ECDSA signature (r, s) encoded as a DER
 * SEQUENCE of two INTEGERs. It recomputes the expected signature using
 * the public key and the provided digest, and returns whether the
 * signature is valid.
 *
 * @param digest		Pre-computed hash of the message
 * @param digestLen		Length of the digest
 * @param digestAlgo	Algorithm used (may be NULL)
 * @param key			Public key
 * @param sig			Signature to verify (DER-encoded SEQUENCE)
 * @param sigLen		Length of the signature
 * @param padding		Padding scheme
 * @return				1 if valid, 0 otherwise
 */
int	ecdsaVerify(const uint8_t	*digest,	size_t	digestLen,
				const t_algoId	*digestAlgo,
				const void		*key,
				const uint8_t	*sig,		size_t	sigLen,
				t_pkeyPadding	padding);

/**
 * @brief Check the consistency of an ECDSA key
 *
 * This function verifies that the public key point lies on the curve
 * and that the private key (if present) is in the correct range.
 * It also checks that the public key correctly derives from the
 * private key if both are present.
 *
 * @param key	Pointer to the ECDSA key structure
 * @return		1 if consistent, 0 otherwise
 */
int	ecdsaCheckKey(const t_ecdsaKey *key);

/**
 * @brief Print an ECDSA key
 *
 * This debug function prints the curve parameters, public key
 * coordinates (X, Y), and optionally the private key. The output
 * format is human-readable hexadecimal.
 *
 * @param key			Pointer to the ECDSA key structure
 * @param showPrivate	If non-zero, prints the private key
 */
void	ecdsaPrintKey(const t_ecdsaKey *key, int showPrivate);

/**
 * @brief Get the size of the curve order in bytes
 *
 * This function returns the size in bytes of the curve order n.
 * This value determines the maximum size of the r and s components
 * of an ECDSA signature.
 *
 * @param key	Pointer to the ECDSA key structure
 * @return		Size in bytes
 */
size_t	ecdsaKeySizeBytes(const void *key);

/**
 * @brief Maximum size of an ECDSA signature
 *
 * This function returns the maximum possible size of a DER-encoded
 * ECDSA signature (r, s) for the given key. This value can be used
 * to allocate a buffer large enough for any signature.
 *
 * @param key	Pointer to the ECDSA key structure
 * @return		Maximum signature length in bytes
 */
size_t	ecdsaMaxSignatureLen(const void *key);

/**
 * @brief Set public key from X and Y coordinates (bytes)
 *
 * This function initialises an ECDSA key structure with a public key
 * provided as raw X and Y coordinate bytes in big-endian order.
 * The curve parameters are loaded based on the curve identifier.
 *
 * @param key		ECDSA key structure
 * @param curveId	Curve identifier
 * @param pubX		X coordinate bytes (big-endian)
 * @param pubXLen	Length of X coordinate
 * @param pubY		Y coordinate bytes (big-endian)
 * @param pubYLen	Length of Y coordinate
 * @return			1 on success, 0 on error
 */
int	ecdsaSetPublicKey(t_ecdsaKey	*key,	int		curveId,
					  const uint8_t	*pubX,	size_t	pubXLen,
					  const uint8_t	*pubY,	size_t	pubYLen);

/**
 * @brief Set private key from bytes
 *
 * This function initialises an ECDSA key structure with a private key
 * provided as raw bytes in big-endian order. The public key is computed
 * from the private key by scalar multiplication of the base point.
 *
 * @param key		ECDSA key structure
 * @param curveId	Curve identifier
 * @param priv		Private key bytes (big-endian)
 * @param privLen	Length of private key
 * @return			1 on success, 0 on error
 */
int	ecdsaSetPrivateKey(t_ecdsaKey *key, int curveId, const uint8_t *priv, size_t privLen);

#endif /* HAJCRYPT_ECDSA_H */
