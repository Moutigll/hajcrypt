#include <stdlib.h>

#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"

#include "../../includes/rsa/rsa.h"

int	rsaGenerateKey(t_rsaKey *key, size_t bits, uint64_t e_val)
{
	t_bigInt	*pm1;
	t_bigInt	*qm1;
	t_bigInt	*phi;
	t_bigInt	*one;

	ft_bzero(key, sizeof(t_rsaKey));
	key->e = bigIntFromUint64(e_val);
	one = bigIntFromUint64(1);
	if (!key->e || !one) {
		HAJCRYPT_DPRINT("Failed to allocate big integers\n");
		return (0);
	}

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
			return (1);
		}

		rsaFreeKey(key); 
		bigIntFree(pm1); bigIntFree(qm1); bigIntFree(phi);
	}
	return (0);
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
		if (hex[i + 1])
			ft_printf("%c%c", hex[i], hex[i+1]);
		else
			ft_printf("%c", hex[i]);
		if (i + 2 < len)
			ft_printf(":");
	}
	ft_printf("\n");
	free(hex);
}

void	rsaPrintKey(t_rsaKey *key, int showPrivate)
{
	char	*expDec;
	char	*expHex;

	if (!key || !key->n || !key->e)
	{
		ft_printf("Invalid key\n");
		return;
	}
	ft_printf("%s-Key: (%d bit", showPrivate ? "Private" : "Public", key->bits);
	if (showPrivate)
		ft_printf(", %d primes", key->p && key->q ? 2 : 0);
	ft_printf(")\n");
	expDec = bigIntToDec(key->e);
	expHex = bigIntToHex(key->e);
	if (showPrivate)
	{
		printComponent("modulus", key->n);
		ft_printf("publicExponent: %s (0x%s)\n", expDec, expHex);
		printComponent("privateExponent", key->d);
		printComponent("prime1", key->p);
		printComponent("prime2", key->q);
		printComponent("exponent1", key->dp);
		printComponent("exponent2", key->dq);
		printComponent("coefficient", key->qinv);
	} else {
		printComponent("Modulus", key->n);
		ft_printf("Exponent: %s (0x%s)\n", expDec, expHex);
	}
	free(expDec);
	free(expHex);
}
