#ifndef HAJCRYPT_RSA_H
# define HAJCRYPT_RSA_H

#include "../cipher/cipher.h"
#include "../hajcrypt.h"
#include "pkey.h"
#include "bigint.h"

#define RSA_MIN_BITS 512
#define RSA_MAX_BITS 16384

typedef struct s_rsaKey {
	t_bigInt	*n;		/* modulus */
	t_bigInt	*e;		/* public exponent */
	t_bigInt	*d;		/* private exponent */
	t_bigInt	*p;		/* prime 1 */
	t_bigInt	*q;		/* prime 2 */
	t_bigInt	*dp;	/* d mod (p-1) */
	t_bigInt	*dq;	/* d mod (q-1) */
	t_bigInt	*qinv;	/* q^-1 mod p */
	int			bits;	/* key size in bits */
}	t_rsaKey;

extern const t_pkeyDef g_rsaPkeyDef;


/**
 * @brief Generate an RSA key pair of the specified bit length.
 *
 * @param key Pointer to the RSA key structure to initialize.
 * @param bits The desired bit length of the RSA key.
 * @param e_val The public exponent value.
 *
 * @return 1 if the key is generated successfully, 0 on failure.
 */
int			rsaGenerateKey(t_rsaKey *key, size_t bits, uint64_t e_val);

/**
 * @brief Free the memory allocated for an RSA key structure.
 *
 * @param key Pointer to the RSA key structure to free.
 */
void		rsaFreeKey(t_rsaKey *key);

/**
 * @brief Convert an RSA key to PEM format.
 *
 * @param key Pointer to the RSA key structure to convert.
 * @param isPrivate Set to 1 if the key is a private key, 0 for public key.
 * @param useTraditional If set to 1, use traditional PEM format (PKCS#1) for private keys.
 *					   For public keys, this parameter is ignored and PKCS#8 format is always used.
 * @param password Optional password for encrypting the private key. Ignored for public keys.
 * @param cipher Optional cipher to use for encrypting the private key. Ignored for public keys.
 *
 * @return A newly allocated string containing the PEM-encoded key, or NULL on failure.
 */
char		*rsaKeyToPem(t_rsaKey		*key,
						 int			isPrivate,
						 int			useTraditional,
						 const char		*password,
						 const t_cipher	*cipher);

/**
 * @brief Parse a PEM-formatted string to extract an RSA key.
 *
 * @param pem The PEM-formatted string containing the RSA key.
 * @param key Pointer to the RSA key structure to populate with the parsed key components.
 * @param isPrivate Set to 1 if the PEM contains a private key, 0 for public key.
 * @param password Optional password for decrypting the private key. Ignored for public keys.
 *
 * @return 0 on failure, 1 on success, 2 if a password is needed
 */
int			rsaKeyFromPem(const char *pem, t_rsaKey *key, int isPrivate, const char *password);



/**
 * @brief Print the components of an RSA key in a human-readable format.
 *
 * @param key Pointer to the RSA key structure to print.
 * @param showPrivate Set to 1 to include private key components in the output, 0 to show only public components.
 */
void		rsaPrintKey(t_rsaKey *key, int showPrivate);

/**
 * @brief Check the consistency of an RSA key by verifying that e*d ≡ 1 (mod lcm(p-1, q-1)).
 *
 * @param key Pointer to the RSA key structure to check.
 * @param primalityRounds The number of rounds for the Miller-Rabin primality test.
 * @return 1 if the key is consistent, 0 if it is not.
 */
int			rsaCheckKey(t_rsaKey *key, int primalityRounds);


/**
 * @brief Encrypt data using the specified padding
 *
 * @param input The input data to encrypt.
 * @param inputLen The length of the input data.
 * @param key The RSA key to use for encryption.
 * @param output The buffer to store the encrypted data.
 * @param outputLen The length of the output buffer.
 *
 * @return 1 if encryption is successful, 0 on failure.
 */
int			rsaEncrypt(const uint8_t	*input,		size_t	inputLen,
					   const void		*key,
					   uint8_t			*output,	size_t	*outputLen,
					   t_pkeyPadding	padding);

/**
 * @brief Decrypt data using the specified padding
 *
 * @param input The input data to decrypt.
 * @param inputLen The length of the input data.
 * @param key The RSA key to use for decryption.
 * @param output The buffer to store the decrypted data.
 * @param outputLen The length of the output buffer.
 *
 * @return 1 if decryption is successful, 0 on failure.
 */
int			rsaDecrypt(const uint8_t	*input,		size_t	inputLen,
					   const void		*key,
					   uint8_t			*output,	size_t	*outputLen,
					   t_pkeyPadding	padding);

/**
 * @brief Sign a digest using the specified padding
 *
 * @param digest The input digest to sign.
 * @param digestLen The length of the input digest.
 * @param digestAlgo The algorithm identifier for the digest.
 * @param key The RSA key to use for signing.
 * @param sig The buffer to store the signature.
 * @param sigLen The length of the signature buffer.
 * @return 1 if signing is successful, 0 on failure.
 */
int			rsaSign(const uint8_t	*digest,	size_t	digestLen,
					 const t_algoId	*digestAlgo,
					 const void		*key,
					 uint8_t		*sig,		size_t	*sigLen,
					 t_pkeyPadding	padding);

/**
 * @brief Verify a signature using the specified padding
 * @param digest The input digest that was signed.
 * @param digestLen The length of the input digest.
 * @param digestAlgo The algorithm identifier for the digest.
 * @param key The RSA key to use for verification.
 * @param sig The signature to verify.
 * @param sigLen The length of the signature.
 * @param padding The padding scheme used for signing.
 * @return 1 if the signature is valid, 0 on failure.
 */
int			rsaVerify(const uint8_t	*digest,	size_t	digestLen,
					 const t_algoId	*digestAlgo,
					 const void		*key,
					 const uint8_t	*sig,		size_t	sigLen,
					 t_pkeyPadding	padding);

/* ------------------------- Padding ------------------------- */

/**
 * @brief Apply PKCS#1 v1.5 padding for encryption.
 * @param input The input data to pad.
 * @param inputLen The length of the input data.
 * @param key The RSA key.
 * @param padded The buffer to store the padded data.
 * @param paddedLen The length of the padded buffer.
 * @return 1 if padding is successful, 0 on failure.
 */
int rsaPkcs1v15PadEncrypt(const uint8_t		*input,		size_t	inputLen,
						  const t_rsaKey	*key,
						  uint8_t			*padded,	size_t	paddedLen);


/**
 * @brief Remove PKCS#1 v1.5 type 2 padding from encrypted data
 * @param padded Padded ciphertext
 * @param paddedLen Length of padded data
 * @param output Buffer for recovered plaintext
 * @param outputLen Pointer to store plaintext length
 * @return 1 on success, 0 on failure
 */
int rsaPkcs1v15UnpadEncrypt(const uint8_t	*padded,	size_t	paddedLen,
							uint8_t			*output,	size_t	*outputLen);

/**
 * @brief Apply PKCS#1 v1.5 padding for signing.
 * @param digest The digest to pad.
 * @param digestLen The length of the digest.
 * @param digestAlgoOid The algorithm identifier for the digest.
 * @param key The RSA key.
 * @param padded The buffer to store the padded data.
 * @param paddedLen The length of the padded buffer.
 * @return 1 if padding is successful, 0 on failure.
 */
int	rsaPkcs1v15PadSign(const uint8_t	*digest,		size_t	digestLen,
					   const t_algoId	*digestAlgoOid,
					   const t_rsaKey	*key,
					   uint8_t			*padded,		size_t	paddedLen);

/**
 * @brief Remove PKCS#1 v1.5 type 1 padding from signed data
 * @param padded Padded signature
 * @param paddedLen Length of padded data
 * @param digestOut Buffer for recovered digest
 * @param digestLen Pointer to store digest length
 * @param expectedAlgoOid Expected algorithm identifier
 * @return 1 on success, 0 on failure
 */
int	rsaPkcs1v15UnpadSign(const uint8_t			*padded,		size_t	paddedLen,
							  uint8_t			*digestOut,		size_t	*digestLen,
							  const t_algoId	*expectedAlgoOid);


/**
 * @brief Apply PSS padding for signing.
 * @param digest The digest to pad.
 * @param digestLen The length of the digest.
 * @param digestAlgoOid The algorithm identifier for the digest.
 * @param key The RSA key.
 * @param padded The buffer to store the padded data.
 * @param paddedLen The length of the padded buffer.
 * @return 1 if padding is successful, 0 on failure.
 */
int	rsaPssPadSign(const uint8_t		*digest,		size_t	digestLen,
				  const t_algoId	*digestAlgoOid,
				  const t_rsaKey	*key,
				  uint8_t			*padded,		size_t	paddedLen);

/**
 * @brief Verify and remove PSS padding from signed data
 * @param padded Padded signature
 * @param paddedLen Length of padded data
 * @param expectedDigest Expected digest value
 * @param expectedDigestLen Length of expected digest
 * @param expectedAlgoOid Expected algorithm identifier
 * @return 1 if padding is valid and digest matches, 0 on failure
 */
int	rsaPssUnpadSign(const uint8_t	*padded,			size_t	paddedLen,
					const uint8_t	*expectedDigest,	size_t	expectedDigestLen,
					const t_algoId	*expectedAlgoOid);

/**
 * @brief Apply OAEP padding for encryption.
 * @param input The input data to pad.
 * @param inputLen The length of the input data.
 * @param key The RSA key.
 * @param padded The buffer to store the padded data.
 * @param paddedLen The length of the padded buffer.
 * @return 1 if padding is successful, 0 on failure.
 */
int	rsaOaepPadEncrypt(const uint8_t		*input,		size_t	inputLen,
					  const t_rsaKey	*key,
					  uint8_t			*padded,	size_t	paddedLen);

/**
 * @brief Remove OAEP padding from encrypted data
 * @param padded Padded ciphertext
 * @param paddedLen Length of padded data
 * @param output Buffer for recovered plaintext
 * @param outputLen Pointer to store plaintext length
 * @return 1 on success, 0 on failure
 */
int	rsaOaepUnpadEncrypt(const uint8_t	*padded,	size_t	paddedLen,
						uint8_t			*output,	size_t	*outputLen);

static inline size_t	rsaModulusBytes(const t_rsaKey *key)
{
	return ((key->bits + 7) / 8);
}

#endif
