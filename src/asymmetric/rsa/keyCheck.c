#include "../../../hajlib/include/hprintf.h" /* IWYU pragma: keep */

#include "../../../includes/asymmetric/rsa.h"

static int checkCRTComponents(const t_rsaKey *key)
{
	t_bigInt	*one = NULL, *pm1 = NULL, *qm1 = NULL;
	t_bigInt	*dp = NULL, *dq = NULL, *temp = NULL;
	int			ok = 1;

	if (!key->dp || !key->dq || !key->qinv)
		return (1);

	one = bigIntFromUint64(1);
	if (!one) return (0);

	pm1 = bigIntDup(key->p);
	qm1 = bigIntDup(key->q);
	if (!pm1 || !qm1) { ok = 0; goto cleanup; }
	bigIntSub(pm1, pm1, one);
	bigIntSub(qm1, qm1, one);

	dp = bigIntNew(key->d->numWords);
	dq = bigIntNew(key->d->numWords);
	if (!dp || !dq) { ok = 0; goto cleanup; }

	bigIntMod(dp, key->d, pm1);
	if (bigIntCmp(dp, key->dp) != 0) {
		HAJCRYPT_DPRINT("RSA check failed: dp != d mod (p-1)\n");
		ok = 0;
		goto cleanup;
	}

	bigIntMod(dq, key->d, qm1);
	if (bigIntCmp(dq, key->dq) != 0) {
		HAJCRYPT_DPRINT("RSA check failed: dq != d mod (q-1)\n");
		ok = 0;
		goto cleanup;
	}

	temp = bigIntNew(key->q->numWords + key->p->numWords);
	if (!temp) { ok = 0; goto cleanup; }
	bigIntMul(temp, key->qinv, key->q);
	bigIntMod(temp, temp, key->p);
	if (bigIntCmp(temp, one) != 0) {
		HAJCRYPT_DPRINT("RSA check failed: qinv * q mod p != 1\n");
		ok = 0;
	}

cleanup:
	bigIntFree(one);
	bigIntFree(pm1);
	bigIntFree(qm1);
	bigIntFree(dp);
	bigIntFree(dq);
	bigIntFree(temp);
	return (ok);
}

static int checkPrimality(const t_rsaKey *key, int rounds)
{
	if (!key->p || !key->q)
		return (1);

	if (!rsaIsPrimeMillerRabin(key->p, rounds)) {
		HAJCRYPT_DPRINT("RSA check failed: p is not prime\n");
		return (0);
	}
	if (!rsaIsPrimeMillerRabin(key->q, rounds)) {
		HAJCRYPT_DPRINT("RSA check failed: q is not prime\n");
		return (0);
	}
	return (1);
}


static int checkPublicExponent(const t_rsaKey *key)
{
	t_bigInt	*one = NULL, *two = NULL;
	int			ok = 1;

	one = bigIntFromUint64(1);
	two = bigIntFromUint64(2);
	if (!one || !two) {
		bigIntFree(one);
		bigIntFree(two);
		return (0);
	}

	if (bigIntIsEven(key->e)) {
		HAJCRYPT_DPRINT("RSA check failed: e is even\n");
		ok = 0;
	} else if (bigIntCmp(key->e, one) <= 0) {
		HAJCRYPT_DPRINT("RSA check failed: e <= 1\n");
		ok = 0;
	} else if (bigIntCmp(key->e, key->n) >= 0) {
		HAJCRYPT_DPRINT("RSA check failed: e >= n\n");
		ok = 0;
	} else if (bigIntBitLength(key->e) > 64) {
		HAJCRYPT_DPRINT("RSA check warning: e is very large (%d bits)\n", bigIntBitLength(key->e));
	}

	bigIntFree(one);
	bigIntFree(two);
	return (ok);
}


/**
 * @brief Validates RSA key security against Fermat's factorization attack
 * 
 * This function checks that the two prime factors (p and q) of an RSA modulus
 * are sufficiently distant from each other. If p and q are too close in value,
 * an attacker can use Fermat's factorization method to efficiently factor the
 * modulus and recover the private key.
 * 
 * Fermat's attack exploits the mathematical property that if p ≈ q, then both
 * are close to √n. The attacker can iterate from √n to find values of x and y
 * where n = x² - y² = (x-y)(x+y), quickly recovering p and q without factoring.
 * 
 * The minimum acceptable distance is set to (bits(n)/2) - 100 bits to ensure
 * p and q are sufficiently separated.
 * 
 * @param key Pointer to the RSA key structure containing primes p, q and modulus n
 * 
 * @return 1 if the key passes the Fermat distance check (p and q are sufficiently far apart)
 *         0 if the key fails the check (p and q are too close, potential vulnerability)
 *         1 if memory allocation fails
 * 
 * @note Prints debug warnings if the check fails, indicating the actual and
 *       minimum required bit lengths of |p-q|
 */
static int checkFermatDistance(const t_rsaKey *key)
{
	t_bigInt	*diff;
	int			bits, minBits, result = 1;

	bits = bigIntBitLength(key->n);
	minBits = (bits / 2) - 100;
	if (minBits < 1)
		minBits = 1;

	diff = bigIntNew(key->p->numWords);
	if (!diff)
		return (1);

	if (bigIntCmp(key->p, key->q) >= 0)
		bigIntSub(diff, key->p, key->q);
	else
		bigIntSub(diff, key->q, key->p);
	bigIntAbs(diff);

	if (bigIntBitLength(diff) < (size_t)minBits) {
		HAJCRYPT_DPRINT("RSA check warning: p and q are too close\n");
		HAJCRYPT_DPRINT("  |p-q| is %d bits, should be at least %d bits\n",
			bigIntBitLength(diff), minBits);
		HAJCRYPT_DPRINT("  Key may be vulnerable to Fermat's attack\n");
		result = 0;
	}

	bigIntFree(diff);
	return (result);
}

/**
 * @brief Checks if an RSA key is vulnerable to Wiener's attack
 * 
 * Wiener's attack is a cryptanalytic attack against RSA that exploits the
 * relationship between the public exponent (e) and private exponent (d).
 * If d is too small (specifically d < n^0.25), an attacker can recover the
 * private exponent through continued fraction approximation of e/n, completely
 * compromising the RSA encryption. This would allow an attacker to decrypt
 * all messages and forge signatures.
 * 
 * @param key Pointer to the RSA key structure to validate. Must contain
 *            initialized n (modulus) and d (private exponent) values.
 * 
 * @return 1 if the key passes the Wiener attack check (d is sufficiently large
 *           or d is not set), 0 if the key is potentially vulnerable
 *           (d < n^0.25)
 * 
 * @note Allocates temporary big integers for sqrt computations which are
 *       freed before returning. Returns 1 on allocation failure as a safe default.
 */
static int checkWienerAttack(const t_rsaKey *key)
{
	t_bigInt *nSqrt = NULL, *nSqrtSqrt = NULL;
	int		result = 1;

	if (!key->d)
		return (1);

	nSqrt = bigIntNew(key->n->numWords);
	nSqrtSqrt = bigIntNew(key->n->numWords / 2 + 2);  /* allocation plus serrée */
	if (!nSqrt || !nSqrtSqrt) {
		bigIntFree(nSqrt);
		bigIntFree(nSqrtSqrt);
		return (1);
	}

	bigIntSqrtNewton(nSqrt, key->n);
	bigIntSqrtNewton(nSqrtSqrt, nSqrt);

	if (bigIntCmp(key->d, nSqrtSqrt) < 0) {
		HAJCRYPT_DPRINT("RSA check warning: d is too small\n");
		HAJCRYPT_DPRINT("  d < n^0.25, key may be vulnerable to Wiener's attack\n");
		result = 0;
	}

	bigIntFree(nSqrt);
	bigIntFree(nSqrtSqrt);
	return (result);
}


/**
 * @brief Checks if an RSA key is vulnerable to Pollard's p-1 attack
 *
 * This function detects if the factors p and q of an RSA key are vulnerable to
 * Pollard's p-1 factorization attack. The attack exploits RSA keys where p-1 or q-1
 * have only small prime factors (smooth numbers). By repeatedly exponentiating with
 * small primes, an attacker can compute gcd(g^(p-1) - 1, n) to factor n without
 * needing the private key.
 *
 * The vulnerability is detected by checking if p-1 or q-1 can be significantly
 * reduced by dividing out small primes (< 1000). If after removing small prime
 * factors, the remaining value has fewer than 200 bits, the key is considered
 * vulnerable.
 *
 * @param key Pointer to the RSA key structure containing factors p and q
 *
 * @return 1 if the key is secure (not vulnerable)
 *         0 if the key is vulnerable to Pollard's p-1 attack
 *         1 if key is NULL, missing factors, or memory allocation fails
 *
 * @note Allocates temporary big integer structures; caller is not responsible
 *       for freeing them as they are managed internally
 */
static int checkPollardPm1Attack(const t_rsaKey *key)
{
	t_bigInt	*one = NULL, *pm1 = NULL, *qm1 = NULL, *rem = NULL;
	int			vulnerable = 0;
	const int	smoothness_limit = 1000;

	if (!key->p || !key->q)
		return (1);

	one = bigIntFromUint64(1);
	pm1 = bigIntDup(key->p);
	qm1 = bigIntDup(key->q);
	rem = bigIntNew(10);
	if (!one || !pm1 || !qm1 || !rem) {
		bigIntFree(one); bigIntFree(pm1);
		bigIntFree(qm1); bigIntFree(rem);
		return (1);
	}
	bigIntSub(pm1, pm1, one);
	bigIntSub(qm1, qm1, one);

	for (uint64_t prime = 2; prime < (uint64_t)smoothness_limit; prime += 1 + (prime > 2)) {
		int isPrime = 1;
		for (uint64_t d = 2; d * d <= prime; d++) {
			if (prime % d == 0) { isPrime = 0; break; }
		}
		if (!isPrime) continue;

		t_bigInt *small = bigIntFromUint64(prime);
		if (!small) continue;

		bigIntMod(rem, pm1, small);
		if (bigIntIsZero(rem)) {
			t_bigInt *quot = bigIntNew(pm1->numWords);
			if (quot) {
				bigIntDiv(quot, NULL, pm1, small);
				bigIntCopy(pm1, quot);
				bigIntFree(quot);
			}
			if (bigIntBitLength(pm1) < 200) vulnerable = 1;
		}

		bigIntMod(rem, qm1, small);
		if (bigIntIsZero(rem)) {
			t_bigInt *quot = bigIntNew(qm1->numWords);
			if (quot) {
				bigIntDiv(quot, NULL, qm1, small);
				bigIntCopy(qm1, quot);
				bigIntFree(quot);
			}
			if (bigIntBitLength(qm1) < 200) vulnerable = 1;
		}

		bigIntFree(small);
	
		if (vulnerable) break;
	}

	if (vulnerable)
		HAJCRYPT_DPRINT("RSA check warning: p-1 or q-1 may be too smooth "
			"(Pollard's p-1 attack)\n");

	bigIntFree(one); bigIntFree(pm1);
	bigIntFree(qm1); bigIntFree(rem);
	return (!vulnerable);
}


/**
 * @brief Validates that the RSA modulus n is not divisible by small prime factors.
 * 
 * This function checks whether the RSA modulus (n) has any small prime factors
 * (2 through 100). A secure RSA key should have n = p*q where both p and q are
 * large primes. If n is divisible by small primes, it indicates a weakness in
 * key generation.
 * 
 * Security Consideration:
 * If this check were omitted or disabled, an attacker could potentially:
 * - Recognize if n has small prime factors through trial division
 * - Factor n more easily using techniques like Pollard's p-1 algorithm
 * - Compromise the entire RSA cryptosystem by recovering the private key
 * - Forge signatures or decrypt ciphertexts without authorization
 * 
 * @param key Pointer to the RSA key structure containing the modulus to validate
 * 
 * @return 1 if the check passes (n has no small prime divisors)
 *         0 if the check fails (n is divisible by a small prime other than 2)
 *         1 on memory allocation failure for intermediate calculations
 * 
 * @note The function tests all primes from 2 to 100 using trial division
 * @note Memory is properly freed on all return paths
 */
static int checkNPrimeFactors(const t_rsaKey *key)
{
	t_bigInt *rem = bigIntNew(10);
	if (!rem) return (1);

	for (uint64_t prime = 2; prime <= 100; prime += 1 + (prime > 2)) {
		t_bigInt *small = bigIntFromUint64(prime);
		if (!small) continue;
		bigIntMod(rem, key->n, small);
		if (bigIntIsZero(rem) && prime != 2) {
			HAJCRYPT_DPRINT("RSA check failed: n is divisible by %llu\n",
				(unsigned long long)prime);
			bigIntFree(small);
			bigIntFree(rem);
			return (0);
		}
		bigIntFree(small);
	}
	bigIntFree(rem);
	return (1);
}

static int checkKeyConsistency(const t_rsaKey *key)
{
	t_bigInt *one = NULL, *pm1 = NULL, *qm1 = NULL;
	t_bigInt *lambda = NULL, *ed = NULL, *temp = NULL, *pq = NULL, *gcd = NULL;
	int ok = 1;

	/* n = p * q */
	pq = bigIntNew(key->p->numWords + key->q->numWords);
	if (!pq) return (0);
	bigIntMul(pq, key->p, key->q);
	if (bigIntCmp(key->n, pq) != 0) {
		HAJCRYPT_DPRINT("RSA check failed: n != p * q\n");
		ok = 0;
		goto cleanup;
	}

	one = bigIntFromUint64(1);
	pm1 = bigIntDup(key->p);
	qm1 = bigIntDup(key->q);
	if (!one || !pm1 || !qm1) { ok = 0; goto cleanup; }
	bigIntSub(pm1, pm1, one);
	bigIntSub(qm1, qm1, one);

	/* λ(n) = lcm(p-1, q-1) */
	lambda = bigIntNew(pm1->numWords + qm1->numWords);
	gcd = bigIntNew(pm1->numWords);
	if (!lambda || !gcd) { ok = 0; goto cleanup; }
	bigIntMul(lambda, pm1, qm1);
	bigIntGcd(gcd, pm1, qm1);
	if (!bigIntIsZero(gcd)) {
		/* lambda = lambda / gcd */
		t_bigInt *quot = bigIntNew(lambda->numWords);
		if (quot) {
			bigIntDiv(quot, NULL, lambda, gcd);
			bigIntCopy(lambda, quot);
			bigIntFree(quot);
		}
}

	/* e*d mod λ(n) doit être 1 */
	ed = bigIntNew(key->e->numWords + key->d->numWords);
	temp = bigIntNew(ed ? ed->numWords : 1);
	if (!ed || !temp) { ok = 0; goto cleanup; }

	bigIntMul(ed, key->e, key->d);
	bigIntMod(temp, ed, lambda);
	if (bigIntCmp(temp, one) != 0) {
		HAJCRYPT_DPRINT("RSA check failed: e*d mod λ(n) != 1\n");
		ok = 0;
	}

cleanup:
	bigIntFree(pq);   bigIntFree(one);
	bigIntFree(pm1);  bigIntFree(qm1);
	bigIntFree(lambda); bigIntFree(ed);
	bigIntFree(temp); bigIntFree(gcd);
	return (ok);
}

static int checkPublicKey(const t_rsaKey *key)
{
	t_bigInt *one = bigIntFromUint64(1);
	if (!one) return (0);

	if (bigIntCmp(key->n, one) <= 0 || bigIntCmp(key->e, one) <= 0) {
		HAJCRYPT_DPRINT("RSA check failed: n or e is invalid\n");
		bigIntFree(one);
		return (0);
	}
	bigIntFree(one);

	if (!checkPublicExponent(key))
		return (0);
	if (!checkNPrimeFactors(key))
		return (0);
	return (1);
}

#define PRINT_FAILED HAJCRYPT_DPRINT(P_RED "Failed\n" P_RESET)
#define PRINT_PASSED HAJCRYPT_DPRINT(P_GREEN "Passed\n" P_RESET);
static int checkPrivateKey(const t_rsaKey *key, int primalityRounds)
{

	HAJCRYPT_DPRINT("Check public exponent... ");
	if (!checkPublicExponent(key))
		return (PRINT_FAILED, 0);
	PRINT_PASSED
	HAJCRYPT_DPRINT("Check Fermat distance... ");
	if (!checkFermatDistance(key))
		return (PRINT_FAILED, 0);
	PRINT_PASSED
	HAJCRYPT_DPRINT("Check Wiener attack... ");
	if (!checkWienerAttack(key))
		return (PRINT_FAILED, 0);
	PRINT_PASSED
	HAJCRYPT_DPRINT("Check Pollard's p-1 attack... ");
	if (!checkPollardPm1Attack(key))
		return (PRINT_FAILED, 0);
	PRINT_PASSED
	HAJCRYPT_DPRINT("Check primality... ");
	if (!checkPrimality(key, primalityRounds))
		return (PRINT_FAILED, 0);
	PRINT_PASSED
	HAJCRYPT_DPRINT("Check N prime factors... ");
	if (!checkNPrimeFactors(key))
		return (PRINT_FAILED, 0);
	PRINT_PASSED
	HAJCRYPT_DPRINT("Check key consistency... ");
	if (!checkKeyConsistency(key))
		return (PRINT_FAILED, 0);
	PRINT_PASSED
	HAJCRYPT_DPRINT("Check CRT components... ");
	if (!checkCRTComponents(key))
		return (PRINT_FAILED, 0);
	PRINT_PASSED

	return (1);
}

int rsaCheckKey(t_rsaKey *key, int primalityRounds)
{
	int bits;

	if (!key || !key->n || !key->e)
		return (0);

	if (primalityRounds <= 0) {
		bits = bigIntBitLength(key->n);
		if (bits >= 1536)	   primalityRounds = 4;
		else if (bits >= 1280)  primalityRounds = 5;
		else if (bits >= 1024)  primalityRounds = 6;
		else if (bits >= 800)   primalityRounds = 7;
		else if (bits >= 512)   primalityRounds = 8;
		else					primalityRounds = 10;
	}

	if (!key->d || !key->p || !key->q)
		return (checkPublicKey(key));
	return (checkPrivateKey(key, primalityRounds));
}
