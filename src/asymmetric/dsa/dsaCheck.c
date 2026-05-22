#include "../../../hajlib/include/hprintf.h" /* IWYU pragma: keep */

#include "../../../includes/asymmetric/dsa.h"


/**
 * @brief dsaCheckKey - Validate DSA parameters and (optionally) key pair consistency.
 *
 * This function performs a sequence of mathematical checks to ensure that the
 * DSA domain parameters (p, q, g) are consistent, and if a private/public key
 * pair is provided, that it matches the parameters.
 *
 * Logic of checks:
 * 1) Parameter presence:
 *    Ensures key and required parameters p, q, g are non-NULL. Without these,
 *    validation cannot proceed.
 *
 * 2) q divides (p - 1):
 *    DSA requires q | (p - 1). The function computes pm1 = p - 1 and verifies
 *    pm1 mod q == 0. Failure indicates invalid domain parameters.
 *
 * 3) g^q mod p == 1:
 *    The generator g must be of order q in the multiplicative group modulo p.
 *    This is enforced by checking g^q ≡ 1 (mod p). If not, g is invalid.
 *
 * 4) g != 1:
 *    A generator equal to 1 is trivial and invalid. The function explicitly
 *    rejects this case even if the previous condition might pass.
 *
 * 5) Private/Public key pair consistency (only if both exist):
 *    - The private key x must satisfy 0 < x < q (not zero, strictly less than q).
 *    - The public key y must satisfy y = g^x mod p. The function computes the
 *      expected y and compares it against the provided public key.
 *
 * @param key Pointer to the DSA key structure to validate.
 * @return 1 if all checks pass, 0 otherwise.
 */
int	dsaCheckKey(t_dsaKey *key)
{
	t_bigInt	*pm1, *one, *tmp, *expectedY;
	int			ret;

	if (!key || !key->p || !key->q || !key->g)
		return (0);

	ret = 1;
	one = bigIntFromUint64(1);
	pm1 = bigIntDup(key->p);
	tmp = bigIntNew(key->p->numWords);
	expectedY = bigIntNew(key->p->numWords);
	if (!one || !pm1 || !tmp || !expectedY)
	{
		bigIntFree(one); bigIntFree(pm1);
		bigIntFree(tmp); bigIntFree(expectedY);
		return (0);
	}

	/* 1. q divise p-1 ? */
	bigIntSub(pm1, pm1, one);
	bigIntMod(tmp, pm1, key->q);
	if (!bigIntIsZero(tmp))
	{
		HAJCRYPT_DPRINT("dsaCheck: q does not divide p-1\n");
		ret = 0;
		goto cleanup;
	}

	/* 2. g^q mod p == 1 ? */
	bigIntModExp(tmp, key->g, key->q, key->p);
	if (bigIntCmp(tmp, one) != 0)
	{
		HAJCRYPT_DPRINT("dsaCheck: g^q mod p != 1\n");
		ret = 0;
		goto cleanup;
	}

	/* 3. g != 1 */
	if (bigIntCmp(key->g, one) == 0)
	{
		HAJCRYPT_DPRINT("dsaCheck: g == 1 (invalid generator)\n");
		ret = 0;
		goto cleanup;
	}

	/* 4. Verify key pair consistency */
	if (key->priv && key->pub)
	{
		/* 0 < x < q */
		if (bigIntIsZero(key->priv)
			|| bigIntCmp(key->priv, key->q) >= 0)
		{
			HAJCRYPT_DPRINT("dsaCheck: x out of range\n");
			ret = 0;
			goto cleanup;
		}

		/* y == g^x mod p */
		bigIntModExp(expectedY, key->g, key->priv, key->p);
		if (bigIntCmp(key->pub, expectedY) != 0)
		{
			HAJCRYPT_DPRINT("dsaCheck: y != g^x mod p\n");
			ret = 0;
			goto cleanup;
		}
	}

cleanup:
	bigIntFree(one);
	bigIntFree(pm1);
	bigIntFree(tmp);
	bigIntFree(expectedY);
	return (ret);
}
