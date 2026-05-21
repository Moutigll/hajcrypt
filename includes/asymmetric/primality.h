#ifndef HAJCRYPT_PRIME_H
# define HAJCRYPT_PRIME_H

#include "bigint.h"

/**
 * @brief Encode an RSA key (public or private) into PEM format.
 *
 * @param key Pointer to the RSA key structure to encode.
 * @param isPrivate Set to 1 if the key is a private key, 0 for public key.
 * @param useTraditional If set to 1, use traditional PEM format (PKCS#1) for private keys.
 *					   For public keys, this parameter is ignored and PKCS#8 format is always used.
 * @param password Optional password for encrypting the private key. Ignored for public keys.
 * @param cipher Optional cipher to use for encrypting the private key. Ignored for public keys.
 *
 * @return A newly allocated string containing the PEM-encoded key, or NULL on failure.
 */
int			hcIsPrimeMillerRabin(t_bigInt *n, int rounds);

/**
 * @brief Generate a prime number of the specified bit length using the Miller-Rabin primality test.
 *
 * @param bits The desired bit length of the prime number.
 * @param certainty The number of Miller-Rabin rounds to perform for primality testing. Higher values increase confidence.
 *
 * @return A pointer to a newly allocated t_bigInt containing the generated prime number, or NULL on failure.
 */
t_bigInt	*hcGeneratePrime(int bits, double certainty);

#endif /* HAJCRYPT_PRIME_H */
