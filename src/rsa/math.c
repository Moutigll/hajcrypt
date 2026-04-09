#include "../../includes/rsa/rsa.h"

uint64_t rsaMulMod(uint64_t a, uint64_t b, uint64_t m)
{
	uint64_t result = 0;
	
	a %= m;
	while (b > 0)
	{
		if (b & 1)
		{
			result += a;
			if (result >= m)
				result -= m;
		}
		a <<= 1;
		if (a >= m)
			a -= m;
		b >>= 1;
	}
	return (result);
}

uint64_t rsaModExp(uint64_t base, uint64_t exp, uint64_t mod)
{
	uint64_t result = 1;
	
	if (mod == 1)
		return (0);
	
	base %= mod;
	while (exp > 0)
	{
		if (exp & 1)
			result = rsaMulMod(result, base, mod);
		base = rsaMulMod(base, base, mod);
		exp >>= 1;
	}
	return (result);
}

uint64_t rsaModInverse(uint64_t a, uint64_t m)
{
	int64_t	t, newt;
	int64_t	r, newr;
	int64_t	quotient, tmp;
	
	if (m == 1)
		return (0);
	
	t = 0;
	newt = 1;
	r = (int64_t)m;
	newr = (int64_t)a;
	
	while (newr != 0)
	{
		quotient = r / newr;
		tmp = newt;
		newt = t - quotient * newt;
		t = tmp;
		tmp = newr;
		newr = r - quotient * newr;
		r = tmp;
	}
	
	if (r > 1)
		return (0);  /* Pas d'inverse */
	if (t < 0)
		t += m;
	
	return (uint64_t)t;
}

uint64_t rsaGcd(uint64_t a, uint64_t b)
{
	uint64_t temp;
	
	while (b != 0)
	{
		temp = b;
		b = a % b;
		a = temp;
	}
	return (a);
}

int rsaIsOdd(uint64_t n)
{
	return (n & 1);
}
