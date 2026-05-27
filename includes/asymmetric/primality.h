#ifndef HAJCRYPT_PRIME_H
# define HAJCRYPT_PRIME_H

#include "bigint.h"

/**
 * @brief Tests whether a big integer is probably prime using the Miller-Rabin algorithm.
 *
 * @param n      The integer to test for primality.
 * @param rounds The number of Miller-Rabin rounds to perform.
 *
 * @return Non-zero if the value is probably prime, or 0 if it is composite.
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
