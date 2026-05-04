#include <stdlib.h>

#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"

#include "../../includes/rsa/rsa.h"

void	rsaGenerateKey(t_rsaKey *key, size_t bits, uint64_t e_val)
{
	t_bigInt	*pm1;
	t_bigInt	*qm1;
	t_bigInt	*phi;
	t_bigInt	*one;

	ft_bzero(key, sizeof(t_rsaKey));
	key->e = bigIntFromUint64(e_val);
	one = bigIntFromUint64(1);

	while (1) {
		key->p = rsaGeneratePrime(bits / 2, 0.999999);
		key->q = rsaGeneratePrime(bits - (bits / 2), 0.999999);

		if (bigIntCmp(key->p, key->q) == 0) {
			rsaFreeKey(key);
			continue;
		}

		key->n = bigIntNew(key->p->numWords + key->q->numWords);
		bigIntMul(key->n, key->p, key->q);

		/* Phi(n) = (p-1)(q-1) */
		pm1 = bigIntDup(key->p); bigIntSub(pm1, pm1, one);
		qm1 = bigIntDup(key->q); bigIntSub(qm1, qm1, one);
		phi = bigIntNew(pm1->numWords + qm1->numWords);
		bigIntMul(phi, pm1, qm1);

		/* d = e^-1 mod phi(n) */
		key->d = bigIntNew(phi->numWords);
		if (bigIntModInverse(key->d, key->e, phi) && !bigIntIsZero(key->d)) {
			key->dp = bigIntNew(key->p->numWords);
			key->dq = bigIntNew(key->q->numWords);
			key->qinv = bigIntNew(key->p->numWords);
			bigIntMod(key->dp, key->d, pm1);
			bigIntMod(key->dq, key->d, qm1);
			/* qInv = q^-1 mod p */
			bigIntModInverse(key->qinv, key->q, key->p);

			bigIntFree(pm1); bigIntFree(qm1); bigIntFree(phi); bigIntFree(one);
			key->bits = bits;
			return;
		}

		rsaFreeKey(key); 
		bigIntFree(pm1); bigIntFree(qm1); bigIntFree(phi);
	}
}

void	rsaFreeKey(t_rsaKey *key)
{
	if (!key) return;
	bigIntFree(key->n);
	bigIntFree(key->e);
	bigIntFree(key->d);
	bigIntFree(key->p);
	bigIntFree(key->q);
	bigIntFree(key->dp);
	bigIntFree(key->dq);
	bigIntFree(key->qinv);
	ft_bzero(key, sizeof(t_rsaKey));
}

static void printComponent(const char *name, const t_bigInt *num)
{
	char	*hex;
	char	*paddedHex = NULL;
	size_t   len;
	size_t   i;

	if (!num) return;
	hex = bigIntToHex(num);
	if (!hex) return;
	len = ft_strlen(hex);

	/* If the most significant hex digit is >= 8, prepend a '00' to indicate it's positive */
	if (len > 0 && ((hex[0] >= '8' && hex[0] <= '9') ||
					(hex[0] >= 'a' && hex[0] <= 'f')))
	{
		paddedHex = malloc(len + 3);
		if (paddedHex) {
			ft_strlcpy(paddedHex, "00", len + 3);
			ft_strlcpy(paddedHex + 2, hex, len + 1);
			free(hex);
			hex = paddedHex;
			len += 2;
		}
	}

	ft_printf("%s:\n    ", name);
	for (i = 0; i < len; i += 2) {
		if (i > 0 && (i / 2) % 15 == 0)
			ft_printf("\n    ");
		ft_printf("%c%c", hex[i], hex[i+1]);
		if (i + 2 < len)
			ft_printf(":");
	}
	ft_printf("\n");
	free(hex);
}

void	rsaPrintKey(t_rsaKey *key, int showPrivate)
{
	if (!key || !key->n || !key->e)
	{
		ft_printf("Invalid key\n");
		return;
	}
	ft_printf("%s-Key: (%d bit", showPrivate ? "Private" : "Public", key->bits);
	if (showPrivate)
		ft_printf(", %d primes", key->p && key->q ? 2 : 0);
	ft_printf(")\n");
	if (showPrivate)
	{
		printComponent("modulus", key->n);
		ft_printf("publicExponent: %s (0x%s)\n", bigIntToDec(key->e), bigIntToHex(key->e));
		printComponent("privateExponent", key->d);
		printComponent("prime1", key->p);
		printComponent("prime2", key->q);
		printComponent("exponent1", key->dp);
		printComponent("exponent2", key->dq);
		printComponent("coefficient", key->qinv);
	} else {
		printComponent("Modulus", key->n);
		ft_printf("Exponent: %s (0x%s)\n", bigIntToDec(key->e), bigIntToHex(key->e));
	}
}

/* ------------------------------- Check key ------------------------------- */

static int	checkPublicKey(const t_rsaKey *key)
{
	t_bigInt	*one;
	int			result;

	one = bigIntFromUint64(1);
	result = (bigIntCmp(key->n, one) > 0 && bigIntCmp(key->e, one) > 0);
	bigIntFree(one);
	return (result);
}

static int	checkPrivateKey(const t_rsaKey *key)
{
	t_bigInt	*pm1;
	t_bigInt	*qm1;
	t_bigInt	*phi;
	t_bigInt	*ed;
	t_bigInt	*temp;
	t_bigInt	*pq;
	t_bigInt	*one;
	int			ok;

	ok		= 1;
	pm1		= NULL;
	qm1		= NULL;
	phi		= NULL;
	ed		= NULL;
	temp	= NULL;
	pq		= NULL;
	one		= bigIntFromUint64(1);
	pq		= bigIntNew(key->p->numWords + key->q->numWords);
	bigIntMul(pq, key->p, key->q);
	if (bigIntCmp(key->n, pq) != 0)
	{
		ft_dprintf(STDERR_FILENO, "RSA check failed: n != p * q\n");
		ok = 0;
		goto cleanup;
	}
	pm1 = bigIntDup(key->p);
	bigIntSub(pm1, pm1, one);
	qm1 = bigIntDup(key->q);
	bigIntSub(qm1, qm1, one);
	phi = bigIntNew(pm1->numWords + qm1->numWords);
	bigIntMul(phi, pm1, qm1);
	ed = bigIntNew(key->e->numWords + key->d->numWords);
	bigIntMul(ed, key->e, key->d);
	temp = bigIntNew(ed->numWords);
	bigIntMod(temp, ed, phi);
	if (bigIntCmp(temp, one) != 0)
	{
		ft_dprintf(STDERR_FILENO, "RSA check failed: e*d mod (p-1)(q-1) != 1\n");
		ok = 0;
	}
cleanup:
	bigIntFree(pq);
	bigIntFree(pm1);
	bigIntFree(qm1);
	bigIntFree(phi);
	bigIntFree(ed);
	bigIntFree(temp);
	bigIntFree(one);
	return (ok);
}

int	rsaCheckKey(t_rsaKey *key)
{
	if (!key || !key->n || !key->e)
		return (0);
	if (!key->d || !key->p || !key->q)
		return (checkPublicKey(key));
	return (checkPrivateKey(key));
}
