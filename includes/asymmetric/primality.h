#ifndef HAJCRYPT_PRIME_H
# define HAJCRYPT_PRIME_H

#include "bigint.h"

const static uint64_t g_smallPrimes[] = {
		2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
		31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
		73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
		127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
		179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
		233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
		283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
		353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
		419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
		467, 479, 487, 491, 499, 503, 509, 521, 523, 541
	};

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
