#ifndef HAJCRYPT_RSA_H
# define HAJCRYPT_RSA_H

# include "bigint.h"

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

int			rsaIsPrimeMillerRabin(t_bigInt *n, int rounds);
t_bigInt	*rsaGeneratePrime(int bits, double certainty);

void		rsaGenerateKey(t_rsaKey *key, size_t bits, uint64_t e_val);
void		rsaFreeKey(t_rsaKey *key);

char		*rsaKeyToPem(t_rsaKey *key, int isPrivate);
int			rsaKeyFromPem(const char *pem, t_rsaKey *key, int isPrivate);

void		rsaPrintKey(t_rsaKey *key, int showPrivate);
int			rsaCheckKey(t_rsaKey *key);

#endif
