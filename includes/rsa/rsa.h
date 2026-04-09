#ifndef HAJCRYPT_RSA_H
#define HAJCRYPT_RSA_H

#include <stdint.h>
#include <stddef.h>

/* RSA Key structure for 64-bit keys (for now) */
typedef struct s_rsaKey {
	uint64_t	n;		/* modulus */
	uint64_t	e;		/* public exponent */
	uint64_t	d;		/* private exponent */
	uint64_t	p;		/* prime 1 */
	uint64_t	q;		/* prime 2 */
	uint64_t	dp;		/* d mod (p-1) - for CRT */
	uint64_t	dq;		/* d mod (q-1) - for CRT */
	uint64_t	qinv;	/* q^-1 mod p - for CRT */
	int			bits;	/* key size in bits */
} t_rsaKey;

/* RSA key components for PEM encoding */
typedef struct s_rsaPemComponents {
	uint8_t	*modulus;
	uint8_t	*publicExponent;
	uint8_t	*privateExponent;
	uint8_t	*prime1;
	uint8_t	*prime2;
	uint8_t	*exponent1;
	uint8_t	*exponent2;
	uint8_t	*coefficient;
	size_t	modulusLen;
	size_t	pubExpLen;
	size_t	privExpLen;
	size_t	prime1Len;
	size_t	prime2Len;
	size_t	exp1Len;
	size_t	exp2Len;
	size_t	coeffLen;
} t_rsaPemComponents;

/* Function for modular arithmetic */

/**
 * @brief Computes the modular product of two 64-bit unsigned integers.
 *
 * Calculates `(a * b) % m` for `uint64_t` operands, intended for RSA arithmetic
 * where modular multiplication is frequently required.
 *
 * @param a First multiplicand.
 * @param b Second multiplicand.
 * @param m Modulus.
 * @return The value of `(a * b) % m`.
 *
 * @note `m` must be non-zero.
 */
uint64_t	rsaMulMod(uint64_t a, uint64_t b, uint64_t m);


/**
 * @brief Computes modular exponentiation.
 *
 * Calculates \f$(base^{exp}) \bmod mod\f$ using an efficient exponentiation
 * by squaring algorithm.
 *
 * @param base The base value.
 * @param exp The exponent value.
 * @param mod The modulus value.
 * @return The result of \f$(base^{exp}) \bmod mod\f$.
 */
uint64_t	rsaModExp(uint64_t base, uint64_t exp, uint64_t mod);

/**
 * @brief Computes the modular inverse of a number.
 *
 * Finds an integer \f$x\f$ such that \f$(a \cdot x) \bmod m = 1\f$ using
 * the Extended Euclidean Algorithm. If no such integer exists (i.e., if
 * `a` and `m` are not coprime), the function returns 0.
 *
 * @param a The number to find the inverse of.
 * @param m The modulus.
 * @return The modular inverse of `a` modulo `m`, or 0 if it does not exist.
 */
uint64_t	rsaModInverse(uint64_t a, uint64_t m);

/**
 * @brief Computes the greatest common divisor (GCD) of two numbers.
 *
 * Uses the Euclidean Algorithm to compute the GCD of `a` and `b`.
 *
 * @param a First number.
 * @param b Second number.
 * @return The greatest common divisor of `a` and `b`.
 */
uint64_t	rsaGcd(uint64_t a, uint64_t b);

/**
 * @brief Checks if a number is odd.
 *
 * @param n The number to check.
 * @return 1 if `n` is odd, 0 otherwise.
 */
int			rsaIsOdd(uint64_t n);

int			rsaIsPrimeMillerRabin(uint64_t n, int rounds);

/* Prime generation */
uint64_t	rsaGeneratePrime(int bits, double certainty);

/* Key generation */
void		rsaGenerateKey(t_rsaKey *key, int bits, uint64_t e);
void		rsaFreeKey(t_rsaKey *key);

/* PEM encoding/decoding */
char		*rsaKeyToPem(t_rsaKey *key, int is_private);
int			rsaKeyFromPem(const char *pem, t_rsaKey *key, int is_private);
void		rsaPemComponentsFree(t_rsaPemComponents *comp);

/* Utility */
void		rsaPrintKey(t_rsaKey *key, int show_private);
int			rsaCheckKey(t_rsaKey *key);
void		rsaGetModulus(t_rsaKey *key, uint8_t **mod, size_t *len);

#endif /* HAJCRYPT_RSA_H */
