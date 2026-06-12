#ifndef HAJCRYPT_PKEY_H
# define HAJCRYPT_PKEY_H

# include "../x509/oid.h"
# include "bigint.h"

/* Forward declarations */
typedef struct s_pkeyDef	t_pkeyDef;
typedef struct s_pkey		t_pkey;

typedef enum t_pkeyType
{
	PKEY_TYPE_UNDEFINED = 0,
	PKEY_TYPE_RSA,
	PKEY_TYPE_DSA,
	PKEY_TYPE_ECDSA,
	PKEY_TYPE_MAX,
}	t_pkeyType;

/**
 * @enum t_pkeyPadding
 * @brief Identifies the padding / encoding scheme used for an operation.
 *
 */
typedef enum {
	PKEY_PADDING_NONE      = 0,  /* No padding (raw operation).  */
	PKEY_PADDING_PKCS1V15  = 1,  /* PKCS#1 v1.5 padding (RSA, DSA). */
	PKEY_PADDING_PSS       = 2,  /* RSA-PSS probabilistic signature. */
	PKEY_PADDING_OAEP      = 3,  /* OAEP encryption padding. */
}	t_pkeyPadding;

/**
 * @brief Bit-flags describing which operations an algorithm supports.
 *
 * These are stored in the @ref t_pkeyDef::caps field so that generic code
 * can query whether encryption or signing is available before calling
 * the corresponding function.
 */
typedef enum {
	PKEY_CAP_ENCRYPT       = (1 << 0),  /* Asymmetric encryption. */
	PKEY_CAP_SIGN          = (1 << 1),  /* Digital signature. */
	PKEY_CAP_KEY_EXCHANGE  = (1 << 2),  /* Key exchange (DH, ECDH). */
	PKEY_CAP_KEY_ENCIPHER  = (1 << 3),  /* Key encipherment (RSA). */
}	t_pkeyCap;

/**
 * @struct s_pkeyDef
 * @brief Virtual table describing a complete asymmetric key algorithm.
 *
 * One instance of this structure exists per supported algorithm (RSA, DSA,
 * EC, …). It contains:
 *   - Identity metadata (OID, human-readable name).
 *   - Capability flags (encrypt, sign, key-exchange).
 *   - PEM encoding / decoding callbacks.
 *   - Key generation, validation, and destruction callbacks.
 *   - Cryptographic operation callbacks.
 */
struct s_pkeyDef
{
	/* ----- Identity ----- */
	const t_pkeyType	type;	/* PKEY_TYPE_RSA, PKEY_TYPE_DSA, … */
	const t_algoId		oid;	/* Algorithm OID (e.g., 1.2.840.113549.1.1.1 for RSA */
	const char			*name;	/* Human-readable name ("RSA", "DSA", "EC", …). */
	size_t				keyLen;	/* sizeof() the concrete key structure. */
	unsigned int		caps;	/* Bitmask of @ref t_pkeyCap values. */
	size_t				defaultBits; /* Default key size if not specified. */

	/* ----- PEM serialization ----- */
	const char	*tradPubLabel;		/* "RSA PUBLIC KEY", "DSA PUBLIC KEY", … */
	const char	*tradPrivLabel;		/* "RSA PRIVATE KEY", "DSA PRIVATE KEY", … */

	/**
	 * @brief Encode AlgorithmIdentifier parameters.
	 *
	 * @param key    Pointer to the concrete key structure.
	 * @param outLen Output: length of the returned DER buffer.
	 * @return Heap-allocated DER-encoded parameters, or NULL.
	 *
	 * @note RSA has no parameters → returns NULL.
	 *       DSA returns SEQUENCE { p, q, g }.
	 */
	uint8_t	*(*encodeAlgoParams)(const void *key, size_t *outLen);

	/**
	 * @brief Encode a public key in PKCS#1 / traditional DER format.
	 *
	 * RSA : SEQUENCE { n, e }
	 * DSA : SEQUENCE { p, q, g, y }
	 *
	 * @param key    Pointer to the concrete key structure.
	 * @param outLen Output: length of the returned DER buffer.
	 * @return Heap-allocated DER buffer, or NULL on failure.
	 */
	uint8_t	*(*encodePubKeyPkcs1)(const void *key, size_t *outLen);

	/**
	 * @brief Encode a public key payload for SubjectPublicKeyInfo (SPKI).
	 *
	 * This is the content placed inside the BIT STRING of the SPKI.
	 * RSA : SEQUENCE { n, e }     (same as PKCS#1)
	 * DSA : INTEGER y             (different from PKCS#1)
	 *
	 * @param key    Pointer to the concrete key structure.
	 * @param outLen Output: length of the returned DER buffer.
	 * @return Heap-allocated DER buffer, or NULL on failure.
	 */
	uint8_t	*(*encodePubKeySpki)(const void *key, size_t *outLen);

	/**
	 * @brief Encode a private key in PKCS#1 / traditional DER format.
	 *
	 * RSA : SEQUENCE { version, n, e, d, p, q, dp, dq, qinv }
	 * DSA : SEQUENCE { version, p, q, g, y, x }
	 *
	 * @param key    Pointer to the concrete key structure.
	 * @param outLen Output: length of the returned DER buffer.
	 * @return Heap-allocated DER buffer, or NULL on failure.
	 */
	uint8_t	*(*encodePrivKeyPkcs1)(const void *key, size_t *outLen);

	/**
	 * @brief Encode a private key payload for PKCS#8 (OCTET STRING content).
	 *
	 * RSA : SEQUENCE { version, n, e, d, p, q, dp, dq, qinv }  (same as PKCS#1)
	 * DSA : INTEGER x                                           (different from PKCS#1)
	 *
	 * @param key    Pointer to the concrete key structure.
	 * @param outLen Output: length of the returned DER buffer.
	 * @return Heap-allocated DER buffer, or NULL on failure.
	 */
	uint8_t	*(*encodePrivKeyPkcs8)(const void *key, size_t *outLen);

	/**
	 * @brief Parse a DER-encoded public key payload.
	 *
	 * Receives the raw public key bytes, either from a traditional PEM block
	 * (PKCS#1) or from the BIT STRING of a SubjectPublicKeyInfo (SPKI).
	 * The function detects the format automatically.
	 *
	 * @param der  DER-encoded public key data.
	 * @param len  Length of @p der.
	 * @param algoParams  Algorithm parameters (if any).
	 * @param algoParamsLen  Length of @p algoParams.
	 * @param key  Pre-allocated buffer of size keyLen to fill.
	 * @return 1 on success, 0 on failure.
	 */
	int		(*decodePubKey)(const uint8_t *der, size_t len, const uint8_t *algoParams, size_t algoParamsLen, void *key);

	/**
	 * @brief Parse a DER-encoded private key payload.
	 *
	 * Receives the raw private key bytes, either from a traditional PEM block
	 * (PKCS#1) or from the OCTET STRING of a PrivateKeyInfo (PKCS#8).
	 * The function detects the format automatically.
	 *
	 * @param der  DER-encoded private key data.
	 * @param len  Length of @p der.
	 * @param algoParams  Algorithm parameters (if any).
	 * @param algoParamsLen  Length of @p algoParams.
	 * @param key  Pre-allocated buffer of size keyLen to fill.
	 * @return 1 on success, 0 on failure.
	 */
	int		(*decodePrivKey)(const uint8_t *der, size_t len, const uint8_t *algoParams, size_t algoParamsLen, void *key);

	/* ----- Key generation ----- */

	/**
	 * @brief Generate a fresh key pair.
	 *
	 * @param key   Pre-allocated buffer of size keyLen.
	 * @param bits  Requested key size (modulus bits for RSA/DSA, curve id
	 *              for EC, …).
	 * @return 1 on success, 0 on failure.
	 */
	int		(*generate)(void *key, int bits);

	/**
	 * @brief Release all resources owned by a key.
	 *
	 * @param key  Pointer to the concrete key structure.
	 */
	void	(*freeKey)(void *key);

	/**
	 * @brief Check whether the given key size is valid for this algorithm.
	 *
	 * @param bits  Requested key size.
	 * @return 1 if the size is acceptable, 0 otherwise.
	 *
	 */
	int		(*validateBits)(int bits);

	/* ----- Cryptographic operations ----- */

	/**
	 * @brief Asymmetric encryption.
	 *
	 * @param input      Plaintext to encrypt.
	 * @param inputLen   Length of @p input in bytes.
	 * @param key        Pointer to the concrete public key structure.
	 * @param output     Buffer for ciphertext (caller-allocated).
	 * @param outputLen  [in]  Size of @p output buffer.
	 *                   [out] Number of bytes written.
	 * @param padding    Padding scheme to apply.
	 * @return 1 on success, 0 on failure.
	 *
	 * @note Only available when @ref caps includes PKEY_CAP_ENCRYPT.
	 */
	int		(*encrypt)(const uint8_t	*input,		size_t	inputLen,
					   const void		*key,
					   uint8_t			*output,	size_t	*outputLen,
					   t_pkeyPadding	padding);

	/**
	 * @brief Asymmetric decryption.
	 *
	 * @param input      Ciphertext to decrypt.
	 * @param inputLen   Length of @p input in bytes.
	 * @param key        Pointer to the concrete private key structure.
	 * @param output     Buffer for plaintext (caller-allocated).
	 * @param outputLen  [in]  Size of @p output buffer.
	 *                   [out] Number of bytes written.
	 * @param padding    Padding scheme to remove.
	 * @return 1 on success, 0 on failure.
	 *
	 * @note Only available when @ref caps includes PKEY_CAP_ENCRYPT.
	 */
	int		(*decrypt)(const uint8_t	*input,		size_t	inputLen,
					   const void		*key,
					   uint8_t			*output,	size_t	*outputLen,
					   t_pkeyPadding	padding);

	/**
	 * @brief Sign a message digest.
	 *
	 * @param digest      Pre-computed hash of the message.
	 * @param digestLen   Length of @p digest in bytes.
	 * @param digestAlgo  Algorithm used to produce @p digest (may be NULL).
	 * @param key         Pointer to the concrete private key structure.
	 * @param sig         Buffer for the signature (caller-allocated).
	 * @param sigLen      [in]  Size of @p sig buffer.
	 *                    [out] Number of bytes written.
	 * @param padding     Padding / encoding scheme.
	 * @return 1 on success, 0 on failure.
	 *
	 * @note Only available when @ref caps includes PKEY_CAP_SIGN.
	 * @note @p digestAlgo is embedded in PKCS#1 v1.5 signatures but is
	 *       only used for length validation with DSA.
	 */
	int		(*sign)(const uint8_t	*digest,	size_t	digestLen,
					const t_algoId *digestAlgo,
					const void		*key,
					uint8_t			*sig,		size_t	*sigLen,
					t_pkeyPadding	padding);

	/**
	 * @brief Verify a digital signature.
	 *
	 * @param digest      Pre-computed hash of the message.
	 * @param digestLen   Length of @p digest in bytes.
	 * @param digestAlgo  Algorithm used to produce @p digest (may be NULL).
	 * @param key         Pointer to the concrete public key structure.
	 * @param sig         Signature to verify.
	 * @param sigLen      Length of @p sig in bytes.
	 * @param padding     Padding / encoding scheme.
	 * @return 1 if the signature is valid, 0 otherwise.
	 *
	 * @note Only available when @ref caps includes PKEY_CAP_SIGN.
	 */
	int		(*verify)(const uint8_t		*digest,	size_t	digestLen,
					  const t_algoId	*digestAlgo,
					  const void		*key,
					  const uint8_t		*sig,		size_t	sigLen,
					  t_pkeyPadding		padding);

	/* ----- Utility functions ----- */

	/**
	 * @brief Maximum size of a signature produced by this algorithm.
	 *
	 * @param key  Pointer to the concrete key structure.
	 * @return Maximum number of bytes a signature may occupy.
	 */
	size_t	(*maxSignatureLen)(const void *key);

	/**
	 * @brief Size of the modulus / order in bytes.
	 *
	 * @param key  Pointer to the concrete key structure.
	 * @return Length in bytes used for I2OSP / OS2IP.
	 */
	size_t	(*keySizeBytes)(const void *key);

	/**
	 * @brief Perform internal consistency checks on a key pair.
	 *
	 * @param key  Pointer to the concrete key structure.
	 * @return 1 if the key is consistent, 0 otherwise.
	 */
	int		(*checkKey)(const void *key);

	/**
	 * @brief Print key components for debugging.
	 *
	 * @param key          Pointer to the concrete key structure.
	 * @param showPrivate  If non-zero, private components are also printed.
	 */
	void	(*printKey)(const void *key, int showPrivate);
};



/**
 * @struct s_pkey
 * @brief Opaque handle for any asymmetric key type.
 *
 * This structure pairs a concrete key with its virtual method table,
 * enabling fully generic code paths.
 */
struct s_pkey
{
	const t_pkeyDef	*def;	/* Algorithm definition (v-table). */
	void			*key;	/* Pointer to concrete key (t_rsaKey*, t_dsaKey*, …). */
};




/* =========================================================================
 *           Generic API
 * ========================================================================= */

/**
 * @brief Allocate and generate a new key pair.
 *
 * @param pkey  On success, filled with the v-table pointer and a heap-
 *              allocated concrete key.
 * @param bits  Requested key size.
 * @return 1 on success, 0 on failure.
 *
 * @note The caller must later call pkeyFree() to release the key.
 */
int		pkeyGenerate(t_pkey *pkey, int bits);

/**
 * @brief Release all resources owned by a key handle.
 *
 * If the key was generated by pkeyGenerate(), this also frees the
 * heap-allocated concrete key structure. After this call the @p pkey
 * structure is zeroed.
 *
 * @param pkey  Key handle to release.
 */
void	pkeyFree(t_pkey *pkey);



/**
 * @brief Serialize a public or private key to a PEM string.
 *
 * @param key             Initialised key handle.
 * @param isPrivate       Non-zero to output a private key, zero for public.
 * @param useTraditional  Non-zero to use the traditional label
 *                        (e.g., "RSA PRIVATE KEY") instead of PKCS#8.
 * @param password        Optional passphrase for encryption (may be NULL).
 * @param cipher          Optional cipher to use (may be NULL).
 * @return Heap-allocated NUL-terminated PEM string, or NULL on failure.
 */
char	*pkeyToPem(t_pkey *key, int isPrivate, int useTraditional, const char *password, const void *cipher);

/**
 * @brief Parse a PEM-encoded key.
 *
 * Supports unencrypted and encrypted (PKCS#8) private keys, as well as
 * traditional algorithm-specific PEM labels.
 *
 * @param pem        NUL-terminated PEM string.
 * @param pkey       On success, filled with the v-table pointer and a
 *                   heap-allocated concrete key.
 * @param isPrivate  Non-zero if a private key is expected, zero for public.
 * @param password   Passphrase for decryption (may be NULL).
 * @return 1 on success, 0 on failure, 2 if a password is required but
 *         was not supplied.
 */
int		pkeyFromPem(const char *pem, t_pkey *pkey, int isPrivate, const char *password);



/**
 * @brief Encrypt data with a public key.
 *
 * @param pkey      Initialised key handle (must support encryption).
 * @param input     Plaintext buffer.
 * @param inputLen  Length of @p input in bytes.
 * @param output    Ciphertext buffer (caller-allocated).
 * @param outputLen [in] Size of @p output. [out] Bytes written.
 * @param padding   Padding scheme.
 * @return 1 on success, 0 on failure.
 */
int		pkeyEncrypt(const t_pkey	*pkey,
					const uint8_t	*input,		size_t	inputLen,
					uint8_t			*output,	size_t	*outputLen,
					t_pkeyPadding	padding);

/**
 * @brief Decrypt data with a private key.
 *
 * @param pkey      Initialised key handle (must support encryption).
 * @param input     Ciphertext buffer.
 * @param inputLen  Length of @p input in bytes.
 * @param output    Plaintext buffer (caller-allocated).
 * @param outputLen [in] Size of @p output. [out] Bytes written.
 * @param padding   Padding scheme.
 * @return 1 on success, 0 on failure.
 */
int		pkeyDecrypt(const t_pkey	*pkey,
					const uint8_t	*input,		size_t	inputLen,
					uint8_t			*output,	size_t	*outputLen,
					t_pkeyPadding	padding);

/**
 * @brief Sign a message digest.
 *
 * @param pkey       Initialised key handle (private key, must support sign).
 * @param digest     Pre-computed digest of the message.
 * @param digestLen  Length of @p digest in bytes.
 * @param digestAlgo Hash algorithm used to produce the digest (may be NULL).
 * @param sig        Signature buffer (caller-allocated).
 * @param sigLen     [in] Size of @p sig. [out] Bytes written.
 * @param padding    Padding / encoding scheme.
 * @return 1 on success, 0 on failure.
 */
int		pkeySign(const t_pkey	*pkey,
				 const uint8_t	*digest,	size_t	digestLen,
				 const t_algoId	*digestAlgo,
				 uint8_t		*sig,		size_t	*sigLen,
				 t_pkeyPadding	padding);

/**
 * @brief Verify a digital signature.
 *
 * @param pkey       Initialised key handle (public key, must support sign).
 * @param digest     Pre-computed digest of the message.
 * @param digestLen  Length of @p digest in bytes.
 * @param digestAlgo Hash algorithm used to produce the digest (may be NULL).
 * @param sig        Signature buffer.
 * @param sigLen     Length of @p sig in bytes.
 * @param padding    Padding / encoding scheme.
 * @return 1 if the signature is valid, 0 otherwise.
 */
int		pkeyVerify(const t_pkey		*pkey,
				   const uint8_t	*digest,	size_t	digestLen,
				   const t_algoId	*digestAlgo,
				   const uint8_t	*sig,		size_t	sigLen,
				   t_pkeyPadding	padding);


/* ==================================================
					Internal utils
   ================================================== */

void printComponent(const char *name, const t_bigInt *num);

#endif /* HAJCRYPT_PKEY_H */
