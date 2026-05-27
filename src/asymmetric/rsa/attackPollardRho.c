
#include "../../../includes/asymmetric/bigint.h"
#include "../../../includes/asymmetric/primality.h"
#include "../../../includes/asymmetric/rsa.h"

static inline int bigIntIsOne(const t_bigInt *n)
{
	return (n->numWords == 1 && n->words[0] == 1);
}

static int bigIntAddMod(t_bigInt *out, const t_bigInt *a, const t_bigInt *b, const t_bigInt *m)
{
	t_bigInt *tmp = bigIntNew(m->numWords);
	if (!tmp)
		return (0);
	if (!bigIntAdd(tmp, a, b) || !bigIntMod(out, tmp, m)) {
		bigIntFree(tmp);
		return (0);
	}
	bigIntFree(tmp);
	return (1);
}

/**
 * @brief One iteration of Pollard's Rho: x = (x*x + c) mod n.
 */
static int pollardStep(t_bigInt *x, const t_bigInt *c, const t_bigInt *n)
{
	t_bigInt *square = bigIntNew(n->numWords * 2);
	if (!square)
		return (0);
	if (!bigIntMulMod(square, x, x, n)) {
		bigIntFree(square);
		return (0);
	}
	if (!bigIntAddMod(x, square, c, n)) {
		bigIntFree(square);
		return (0);
	}
	bigIntFree(square);
	return (1);
}

/**
 * @brief Pollard's Rho factorisation algorithm.
 *
 * Returns a non‑trivial factor of n (p or q) using Floyd's cycle detection.
 * The function may fail for certain c; it restarts with a new c if d == n.
 *
 * @param n The composite modulus (odd, > 1)
 * @return Newly allocated factor, or NULL on failure.
 */
static t_bigInt *bigIntPollardRho(t_bigInt *n)
{
	t_bigInt	*x = bigIntFromUint64(2);
	t_bigInt	*y = bigIntFromUint64(2);
	t_bigInt	*c = bigIntFromUint64(1);
	t_bigInt	*d = bigIntFromUint64(1);
	t_bigInt	*diff = bigIntNew(n->numWords);
	t_bigInt	*one = bigIntFromUint64(1);
	t_bigInt	*two = bigIntFromUint64(2);

	if (!x || !y || !c || !d || !diff || !one || !two)
		goto failure;

	while (bigIntIsOne(d)) {
		/* x = f(x) */
		if (!pollardStep(x, c, n))
			goto failure;
		/* y = f(f(y)) */
		if (!pollardStep(y, c, n))
			goto failure;
		if (!pollardStep(y, c, n))
			goto failure;
		/* diff = |x - y| */
		if (bigIntCmp(x, y) >= 0)
			bigIntSub(diff, x, y);
		else
			bigIntSub(diff, y, x);
		/* d = gcd(diff, n) */
		if (!bigIntGcd(d, diff, n))
			goto failure;
		/* If d == n, restart with a new constant c */
		if (bigIntCmp(d, n) == 0) {
			bigIntCopy(x, two);
			bigIntCopy(y, two);
			if (!bigIntAdd(c, c, one))
				goto failure;
			bigIntCopy(d, one);
		}
	}

	bigIntFree(x); bigIntFree(y); bigIntFree(c);
	bigIntFree(diff); bigIntFree(one); bigIntFree(two);
	
	return (d);
failure:
	bigIntFree(x);  bigIntFree(y);  bigIntFree(c);  bigIntFree(d);
	bigIntFree(diff);  bigIntFree(one);  bigIntFree(two);
	
	return (NULL);
}

/**
 * @brief Attempts to factor n by trial division using a fixed list of small primes.
 *
 * @param n The modulus.
 * @param p Output factor (if found) - caller must free.
 * @param q Output co‑factor - caller must free.
 * @return 1 if a factor was found, 0 otherwise.
 */
static int trialDivideSmall(t_bigInt *n, t_bigInt **p, t_bigInt **q)
{
	const size_t	numPrimes = sizeof(g_smallPrimes) / sizeof(g_smallPrimes[0]);
	t_bigInt		*rem = bigIntNew(1);
	t_bigInt		*prime = NULL;

	for (size_t i = 0; i < numPrimes; ++i) {
		prime = bigIntFromUint64(g_smallPrimes[i]);
		if (!prime) {
			bigIntFree(rem);
			return (0);
		}
		if (!bigIntMod(rem, n, prime)) {
			bigIntFree(prime);
			bigIntFree(rem);
			return (0);
		}
		if (bigIntIsZero(rem)) {
			/* divisor found */
			*p = prime;
			*q = bigIntNew(n->numWords);
			if (!*q || !bigIntDiv(*q, NULL, n, prime)) {
				bigIntFree(prime);
				bigIntFree(*q);
				bigIntFree(rem);
				return (0);
			}
			bigIntFree(rem);
			return (1);
		}
		bigIntFree(prime);
	}
	bigIntFree(rem);
	return (0);
}

/**
 * @brief Factorises a small RSA modulus n into p and q (p ≤ q).
 *
 * @param n The modulus (should be ≤ 128 bits for practical performance)
 * @param p Output factor (heap allocated)
 * @param q Output factor (heap allocated)
 * @return 1 on success, 0 on failure.
 */
static int factorizeBigInt(t_bigInt *n, t_bigInt **p, t_bigInt **q)
{
	if (!n || bigIntIsZero(n) || bigIntIsOne(n))
		return (0);

	/* Even modulus */
	if (bigIntIsEven(n)) {
		*p = bigIntFromUint64(2);
		if (!*p) return (0);
		*q = bigIntNew(n->numWords);
		if (!*q || !bigIntDiv(*q, NULL, n, *p)) {
			bigIntFree(*p);
			return (0);
		}
		return (1);
	}

	/* Trial division by small primes */
	if (trialDivideSmall(n, p, q))
		return (1);

	/* Pollard's Rho */
	t_bigInt *factor = bigIntPollardRho(n);
	if (!factor) return (0);

	*p = factor;
	*q = bigIntNew(n->numWords);
	if (!*q || !bigIntDiv(*q, NULL, n, *p)) {
		bigIntFree(*p);
		bigIntFree(*q);
		return (0);
	}

	/* Ensure p <= q */
	if (bigIntCmp(*p, *q) > 0) {
		t_bigInt *tmp = *p;
		*p = *q;
		*q = tmp;
	}
	return (1);
}

/**
 * @brief Reconstructs a full RSA private key from p, q and e.
 *
 * Computes n, φ(n), d, dp, dq, qinv.
 *
 * @param privkey Target structure (must be zeroed by caller)
 * @param p Prime factor
 * @param q Prime factor
 * @param e Public exponent
 * @return 1 on success, 0 on failure.
 */
static int reconstructPrivateKey(t_rsaKey	*privkey,
								 const		t_bigInt *p,
								 const		t_bigInt *q,
								 const		t_bigInt *e)
{
	t_bigInt *one = bigIntFromUint64(1);
	if (!one) return (0);

	/* n = p * q */
	privkey->n = bigIntNew(p->numWords + q->numWords);
	if (!privkey->n) { bigIntFree(one); return (0); }
	bigIntMul(privkey->n, p, q);

	/* p-1, q-1 */
	t_bigInt *pMinus1 = bigIntDup(p);
	t_bigInt *qMinus1 = bigIntDup(q);
	if (!pMinus1 || !qMinus1) {
		bigIntFree(one); return (0);
	}
	bigIntSub(pMinus1, pMinus1, one);
	bigIntSub(qMinus1, qMinus1, one);

	/* φ(n) = (p-1)*(q-1) */
	t_bigInt *phi = bigIntNew(pMinus1->numWords + qMinus1->numWords);
	if (!phi) {
		bigIntFree(one); bigIntFree(pMinus1); bigIntFree(qMinus1);
		return (0);
	}
	bigIntMul(phi, pMinus1, qMinus1);

	/* d = e⁻¹ mod φ(n) */
	privkey->d = bigIntNew(phi->numWords);
	if (!privkey->d) goto cleanup;
	if (!bigIntModInverse(privkey->d, e, phi)) goto cleanup;

	/* dp = d mod (p-1) */
	privkey->dp = bigIntNew(pMinus1->numWords);
	if (!privkey->dp) goto cleanup;
	bigIntMod(privkey->dp, privkey->d, pMinus1);

	/* dq = d mod (q-1) */
	privkey->dq = bigIntNew(qMinus1->numWords);
	if (!privkey->dq) goto cleanup;
	bigIntMod(privkey->dq, privkey->d, qMinus1);

	/* qinv = q⁻¹ mod p */
	privkey->qinv = bigIntNew(p->numWords);
	if (!privkey->qinv) goto cleanup;
	if (!bigIntModInverse(privkey->qinv, q, p)) goto cleanup;

	/* Store p, q, e */
	privkey->p = bigIntDup(p);
	privkey->q = bigIntDup(q);
	privkey->e = bigIntDup(e);
	if (!privkey->p || !privkey->q || !privkey->e) goto cleanup;

	privkey->bits = (int)bigIntBitLength(privkey->n);

	bigIntFree(one);
	bigIntFree(pMinus1);
	bigIntFree(qMinus1);
	bigIntFree(phi);
	return (1);

cleanup:
	bigIntFree(privkey->n); privkey->n = NULL;
	bigIntFree(privkey->d); privkey->d = NULL;
	bigIntFree(privkey->dp); privkey->dp = NULL;
	bigIntFree(privkey->dq); privkey->dq = NULL;
	bigIntFree(privkey->qinv); privkey->qinv = NULL;
	bigIntFree(privkey->p); privkey->p = NULL;
	bigIntFree(privkey->q); privkey->q = NULL;
	bigIntFree(privkey->e); privkey->e = NULL;
	bigIntFree(one);
	bigIntFree(pMinus1);
	bigIntFree(qMinus1);
	bigIntFree(phi);
	return (0);
}

int rsaAttackBreakPrivkey(const t_rsaKey *pubkey, t_rsaKey *privkey)
{
	if (!pubkey || !privkey || !pubkey->n || !pubkey->e)
		return (0);

	t_bigInt *p = NULL, *q = NULL;
	if (!factorizeBigInt(pubkey->n, &p, &q))
		return (0);

	int ret = reconstructPrivateKey(privkey, p, q, pubkey->e);
	bigIntFree(p);
	bigIntFree(q);
	return (ret);
}
