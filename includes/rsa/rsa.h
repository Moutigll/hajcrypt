#ifndef HAJCRYPT_RSA_H
# define HAJCRYPT_RSA_H

# include "bigint.h"
#include "../cipher/cipher.h"

#define RSA_OID_LEN 9

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

/**
 * @brief Encode an RSA key (public or private) into PEM format.
 *
 * @param key Pointer to the RSA key structure to encode.
 * @param isPrivate Set to 1 if the key is a private key, 0 for public key.
 * @param useTraditional If set to 1, use traditional PEM format (PKCS#1) for private keys.
 *                       For public keys, this parameter is ignored and PKCS#8 format is always used.
 * @param password Optional password for encrypting the private key. Ignored for public keys.
 * @param cipher Optional cipher to use for encrypting the private key. Ignored for public keys.
 *
 * @return A newly allocated string containing the PEM-encoded key, or NULL on failure.
 */
int			rsaIsPrimeMillerRabin(t_bigInt *n, int rounds);

/**
 * @brief Generate a prime number of the specified bit length using the Miller-Rabin primality test.
 *
 * @param bits The desired bit length of the prime number.
 * @param certainty The number of Miller-Rabin rounds to perform for primality testing. Higher values increase confidence.
 *
 * @return A pointer to a newly allocated t_bigInt containing the generated prime number, or NULL on failure.
 */
t_bigInt	*rsaGeneratePrime(int bits, double certainty);



/**
 * @brief Generate an RSA key pair of the specified bit length.
 *
 * @param key Pointer to the RSA key structure to initialize.
 * @param bits The desired bit length of the RSA key.
 * @param e_val The public exponent value.
 */
void		rsaGenerateKey(t_rsaKey *key, size_t bits, uint64_t e_val);

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
 *                       For public keys, this parameter is ignored and PKCS#8 format is always used.
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
 * @return 1 if parsing is successful, 0 on failure (e.g., invalid format, decryption failure).
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
 * @return 1 if the key is consistent, 0 if it is not.
 */
int			rsaCheckKey(t_rsaKey *key);

#endif
