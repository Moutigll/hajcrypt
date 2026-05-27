#include "../../hajlib/include/hmath.h"
#include "../../hajlib/include/hprintf.h" /* IWYU pragma: keep */
#include "../../includes/hajcrypt.h"

#include "../../includes/asymmetric/primality.h"

static int isPrimeSmall(const t_bigInt *n)
{
	if (n->used == 1) {
		uint64_t val = n->words[0];
		for (size_t i = 0; i < sizeof(g_smallPrimes)/sizeof(g_smallPrimes[0]); i++) {
			if (val == g_smallPrimes[i]) return (1);
			if (val % g_smallPrimes[i] == 0) return (0);
		}
		return (1);
	}
	t_bigInt *p = bigIntNew(1);
	t_bigInt *rem = bigIntNew(1);
	if (!p || !rem) { bigIntFree(p); bigIntFree(rem); return (0); }
	int result = 1;
	for (size_t i = 0; i < sizeof(g_smallPrimes)/sizeof(g_smallPrimes[0]); i++) {
		p->words[0] = g_smallPrimes[i]; p->used = 1;
		bigIntMod(rem, n, p);
		if (bigIntIsZero(rem) && bigIntCmp(n, p) != 0) { result = 0; break; }
	}
	bigIntFree(p); bigIntFree(rem);
	return (result);
}

int hcIsPrimeMillerRabin(t_bigInt *n, int rounds)
{
	t_bigInt	*d, *a, *x, *nMinus1, *one, *two;
	int			s = 0, result = 1;
	
	one = bigIntFromUint64(1);
	two = bigIntFromUint64(2);
	
	if (bigIntCmp(n, two) < 0) { result = 0; goto end; }
	if (bigIntCmp(n, two) == 0) { result = 1; goto end; }
	
	/* Check small primes first to quickly eliminate common composites */
	if (!isPrimeSmall(n)) { result = 0; goto end; }
	
	/* Check if n is even */
	if (bigIntIsEven(n)) { result = 0; goto end; }
	
	nMinus1 = bigIntDup(n);
	bigIntSub(nMinus1, nMinus1, one);
	d = bigIntDup(nMinus1);
	
	/* Write n-1 = d * 2^s with d odd */
	while (bigIntIsEven(d)) {
		bigIntShr(d);
		s++;
	}
	
	a = bigIntNew(n->numWords);
	x = bigIntNew(n->numWords);
	
	for (int i = 0; i < rounds; i++) {
		/* Choose a between 2 and n-2 */
		do {
			bigIntRandom(a, bigIntBitLength(n));
			bigIntMod(a, a, n);
		} while (bigIntCmp(a, two) < 0 || bigIntCmp(a, nMinus1) >= 0);
		
		/* Calculate x = a^d mod n */
		bigIntModExp(x, a, d, n);
		
		if (bigIntCmp(x, one) == 0 || bigIntCmp(x, nMinus1) == 0)
			continue;
		
		int composite = 1;
		for (int j = 0; j < s - 1; j++) {
			bigIntMulMod(x, x, x, n);
			if (bigIntCmp(x, nMinus1) == 0) {
				composite = 0;
				break;
			}
			if (bigIntCmp(x, one) == 0) {
				composite = 1;
				break;
			}
		}
		
		if (composite) {
			result = 0;
			break;
		}
	}
	
	bigIntFree(d);
	bigIntFree(a);
	bigIntFree(x);
	bigIntFree(nMinus1);
	
end:
	bigIntFree(one);
	bigIntFree(two);
	return (result);
}

t_bigInt *hcGeneratePrime(int bits, double certainty)
{
	t_bigInt	*candidate;
	int			rounds;
	int			count = 0;

	rounds = (certainty <= 0.0) ? 5 : (int)(-ft_log2(1.0 - certainty)) + 1;
	if (rounds < 5) rounds = 5;
	if (rounds > 12) rounds = 12;
	
	candidate = bigIntNew((bits + 63) / 64);
	if (!candidate) return (NULL);
	
	while (1) {
		bigIntRandom(candidate, bits);
		
		if (hcIsPrimeMillerRabin(candidate, rounds)) {
			HAJCRYPT_DPRINT("++++++++++++\n");
			return (candidate);
		}
		
		if (count % 192 == 0)
			HAJCRYPT_DPRINT("\n");
		++count;
		if (count % 3 == 0)
			HAJCRYPT_DPRINT(".");
	}
}
