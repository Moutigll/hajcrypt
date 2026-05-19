#ifndef HAJCRYPT_DSA_H
# define HAJCRYPT_DSA_H

#include "../hajcrypt.h"
#include "bigint.h"
#include "../cipher/cipher.h"

#define DSA_OID_LEN 7	/* 1.2.840.10040.4.1 (id-dsa) */

/**
 * @brief Structure representing a DSA key (Digital Signature Algorithm).
 *
 * Contains the domain parameters (p, q, g), the public key (y = g^x mod p),
 * the private key (x), and the key size.
 */
typedef struct s_dsaKey {
	t_bigInt	*p;		/* large prime (public parameter) */
	t_bigInt	*q;		/* subgroup prime divisor of p-1 (public parameter) */
	t_bigInt	*g;		/* generator of the subgroup of order q */
	t_bigInt	*pub;	/* public key y = g^x mod p */
	t_bigInt	*priv;	/* private key x (0 < x < q) */
	int			bits;	/* size of p in bits */
}	t_dsaKey;

/**
 * @brief Generate a complete DSA key (parameters and key pair).
 *
 * @param key Pointer to the DSA key structure to initialize.
 * @param bits Desired size of p in bits (e.g., 1024, 2048).
 *
 * @return 1 if generation succeeds, 0 on failure.
 */
int			dsaGenerateKey(t_dsaKey *key, size_t bits);

/**
 * @brief Free the memory allocated for a DSA key.
 *
 * @param key Pointer to the DSA key structure to free.
 */
void		dsaFreeKey(t_dsaKey *key);



/**
 * @brief Encode a DSA key (public or private) into PEM format.
 *
 * Public keys are always encoded as SubjectPublicKeyInfo (PKCS#8).
 * Private keys are encoded as PrivateKeyInfo (PKCS#8).
 *
 * @param key Pointer to the DSA key structure.
 * @param isPrivate Set to 1 for a private key, 0 for a public key.
 * @param password Optional password for encrypting the private key.
 *                 Ignored for public keys.
 * @param cipher Optional cipher for encryption. Ignored for public keys.
 *
 * @return A newly allocated string containing the PEM-encoded key,
 *         or NULL on failure.
 */
char		*dsaKeyToPem(t_dsaKey *key, int isPrivate,
				 const char *password, const t_cipher *cipher);

/**
 * @brief Parse a PEM-formatted string and extract a DSA key.
 *
 * @param pem The PEM-formatted string.
 * @param key Pointer to the DSA key structure to populate.
 * @param isPrivate Set to 1 if the PEM contains a private key, 0 for a public key.
 * @param password Optional password for decrypting an encrypted private key.
 *                 Ignored for public keys.
 *
 * @return 1 if parsing is successful, 0 on failure (e.g., invalid format,
 *         decryption error).
 */
int			dsaKeyFromPem(const char *pem, t_dsaKey *key,
					  int isPrivate, const char *password);

/**
 * @brief Print the components of a DSA key in a human-readable format.
 *
 * @param key Pointer to the DSA key structure to print.
 * @param showPrivate Set to 1 to include private components, 0 for public only.
 */
void		dsaPrintKey(t_dsaKey *key, int showPrivate);

/**
 * @brief Check the consistency of a DSA key.
 *
 * Verifies:
 * - g^q mod p == 1
 * - g != 1
 * - y == g^x mod p
 * - 0 < x < q
 *
 * @param key Pointer to the DSA key structure to check.
 *
 * @return 1 if the key is consistent, 0 otherwise.
 */
int			dsaCheckKey(t_dsaKey *key);



/**
 * @brief Sign a digest using the DSA private key.
 *
 * The resulting signature is a DER-encoded SEQUENCE of two INTEGERs (r, s).
 * The caller must provide a buffer large enough to hold the signature
 * (maximum size is roughly 2 * (q's byte length) + overhead).
 *
 * @param digest Digest to sign.
 * @param digestLen Length of the digest.
 * @param key DSA key containing domain parameters and the private key.
 * @param sig Buffer where the signature will be stored (allocated by the caller).
 * @param sigLen Pointer to receive the actual length of the signature.
 *
 * @return 1 on success, 0 on failure.
 */
int			dsaSign(const uint8_t *digest, size_t digestLen,
					const t_dsaKey *key,
					uint8_t *sig, size_t *sigLen);

/**
 * @brief Verify a DSA signature against a digest.
 *
 * The signature must be a DER-encoded SEQUENCE containing two INTEGERs (r, s).
 *
 * @param digest Digest of the message.
 * @param digestLen Length of the digest.
 * @param key DSA key containing domain parameters and the public key.
 * @param sig Pointer to the signature data.
 * @param sigLen Length of the signature data.
 *
 * @return 1 if the signature is valid, 0 otherwise.
 */
int			dsaVerify(const uint8_t *digest, size_t digestLen,
					  const t_dsaKey *key,
					  const uint8_t *sig, size_t sigLen);

#endif
