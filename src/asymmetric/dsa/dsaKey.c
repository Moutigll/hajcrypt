#include "../../../hajlib/include/hmemory.h"
#include "../../../hajlib/include/hprintf.h" /* IWYU pragma: keep */
#include "../../../includes/asymmetric/primality.h"

#include "../../../includes/asymmetric/dsa.h"

/**
 * @brief Select the q-bit length based on the p-bit length (FIPS 186-4).
 *
 * @param pBits Desired bit length of p.
 * @return Recommended bit length for q.
 */
static int	chooseQSize(int pBits)
{
	if (pBits <= 1024)
		return (160);
	return (256);
}

/**
 * @brief Generate a random prime q of the requested size.
 *
 * @param qBits Desired bit length of q.
 * @return Pointer to the new prime, or NULL on failure.
 */
static t_bigInt	*generateQ(int qBits)
{
	return (hcGeneratePrime(qBits, 0.999999));
}

/**
 * @brief Generate a prime modulus p for DSA such that q divides p-1.
 *
 * Constructs p = k * q + 1 with a random k until p is prime and has
 * exactly the requested bit length.
 *
 * @param q     Prime divisor (order of the subgroup).
 * @param pBits Desired bit length of p.
 * @return Pointer to the new prime p, or NULL on failure.
 */
static t_bigInt	*generateP(t_bigInt *q, int pBits)
{
	t_bigInt	*p;
	t_bigInt	*k;
	t_bigInt	*tmp;
	t_bigInt	*one;
	int			qBits;
	int			kBits;

	qBits = (int)bigIntBitLength(q);
	kBits = pBits - qBits;
	if (kBits < 64)
		kBits = 64;
	one = bigIntFromUint64(1);
	k = bigIntNew((size_t)(kBits + 63) / 64);
	p = bigIntNew((size_t)(pBits + 63) / 64 + 1);
	tmp = bigIntNew((size_t)(pBits + 63) / 64 + 2);
	if (!one || !k || !p || !tmp)
	{
		bigIntFree(one);
		bigIntFree(k);
		bigIntFree(p);
		bigIntFree(tmp);
		return (NULL);
	}
	HAJCRYPT_DPRINT("Finding a prime p of size %d bits...", pBits);
	int attempts = 0;
	while (1)
	{
		bigIntRandom(k, kBits);
		k->words[0] &= ~1ULL; /* force k even → p = k*q + 1 is odd */
		bigIntMul(tmp, k, q);
		bigIntAdd(p, tmp, one);
		if (bigIntBitLength(p) != (size_t)pBits)
			continue;
		if (hcIsPrimeMillerRabin(p, 8))
		{
			ft_dprintf(STDERR_FILENO, "++++++++++++\n");
			break;
		}
		if (attempts % 192 == 0)
			HAJCRYPT_DPRINT("\n");
		++attempts;
		if (attempts % 3 == 0)
			HAJCRYPT_DPRINT(".");
			
	}
	bigIntFree(k);
	bigIntFree(tmp);
	bigIntFree(one);
	return (p);
}

/**
 * @brief Generate the DSA generator g of the subgroup of order q modulo p.
 *
 * Computes g = h^((p-1)/q) mod p for a random h with 1 < h < p-1.
 *
 * @param p Prime modulus.
 * @param q Prime subgroup order.
 * @return Pointer to the generator g, or NULL on failure.
 */
static t_bigInt	*generateG(t_bigInt *p, t_bigInt *q)
{
	t_bigInt	*g;
	t_bigInt	*h;
	t_bigInt	*exp;
	t_bigInt	*pm1;
	t_bigInt	*one;
	int			pBits;

	pBits = (int)bigIntBitLength(p);
	one = bigIntFromUint64(1);
	pm1 = bigIntDup(p);
	if (!one || !pm1)
	{
		bigIntFree(one);
		bigIntFree(pm1);
		return (NULL);
	}
	bigIntSub(pm1, pm1, one);
	exp = bigIntNew(pm1->numWords);
	bigIntDiv(exp, NULL, pm1, q);
	g = bigIntNew(p->numWords);
	h = bigIntNew(p->numWords);
	if (!exp || !g || !h)
	{
		bigIntFree(one);
		bigIntFree(pm1);
		bigIntFree(exp);
		bigIntFree(g);
		bigIntFree(h);
		return (NULL);
	}
	while (1)
	{
		do
		{
			bigIntRandom(h, pBits);
			bigIntMod(h, h, p);
		} while (bigIntCmp(h, one) <= 0 || bigIntCmp(h, pm1) >= 0);
		bigIntModExp(g, h, exp, p);
		if (bigIntCmp(g, one) != 0)
			break;
	}
	bigIntFree(h);
	bigIntFree(exp);
	bigIntFree(pm1);
	bigIntFree(one);
	return (g);
}

/**
 * @brief Generate a complete DSA key pair.
 *
 * Generates domain parameters (p, q, g), private key x, and public key y.
 *
 * @param key  Pointer to the key structure to fill.
 * @param bits Desired size of p in bits (1024, 2048 or 3072).
 * @return 1 on success, 0 on failure.
 */
int	dsaGenerateKey(t_dsaKey *key, size_t bits)
{
	int	qBits;

	if (!key || bits < 512)
		return (0);
	ft_bzero(key, sizeof(t_dsaKey));
	key->bits = bits;
	qBits = chooseQSize((int)bits);
	key->q = generateQ(qBits);
	if (!key->q)
		return (0);
	key->p = generateP(key->q, (int)bits);
	if (!key->p)
	{
		bigIntFree(key->q);
		return (0);
	}
	key->g = generateG(key->p, key->q);
	if (!key->g)
	{
		bigIntFree(key->p);
		bigIntFree(key->q);
		return (0);
	}
	key->priv = bigIntNew(key->q->numWords);
	if (!key->priv)
	{
		dsaFreeKey(key);
		return (0);
	}
	do
	{
		bigIntRandom(key->priv, qBits);
	} while (bigIntIsZero(key->priv) || bigIntCmp(key->priv, key->q) >= 0);
	key->pub = bigIntNew(key->p->numWords);
	if (!key->pub)
	{
		dsaFreeKey(key);
		return (0);
	}
	bigIntModExp(key->pub, key->g, key->priv, key->p);
	return (1);
}

void	dsaFreeKey(t_dsaKey *key)
{
	if (!key)
		return;
	bigIntFree(key->p);
	bigIntFree(key->q);
	bigIntFree(key->g);
	bigIntFree(key->pub);
	bigIntFree(key->priv);
	ft_bzero(key, sizeof(t_dsaKey));
}

void	dsaPrintKey(t_dsaKey *key, int showPrivate)
{
	if (!key || !key->p || !key->q || !key->g || !key->pub)
	{
		if (!key)
			ft_dprintf(STDERR_FILENO, "Missing DSA key\n");
		if (!key->p)
			ft_dprintf(STDERR_FILENO, "Missing DSA key parameter 'p'\n");
		if (!key->q)
			ft_dprintf(STDERR_FILENO, "Missing DSA key parameter 'q'\n");
		if (!key->g)
			ft_dprintf(STDERR_FILENO, "Missing DSA key parameter 'g'\n");
		if (!key->pub)
			ft_dprintf(STDERR_FILENO, "Missing DSA key parameter 'pub'\n");
		ft_printf("Invalid DSA key\n");
		return;
	}
	if (showPrivate)
	{
		ft_printf("Private-Key: (%d bit)\n", key->bits);
		printComponent("priv", key->priv);
		ft_printf("pub: \n");
		printComponent("", key->pub);
	}
	else
	{
		ft_printf("Public-Key: (%d bit)\n", key->bits);
		ft_printf("pub: \n");
		printComponent("", key->pub);
	}
	printComponent("P", key->p);
	printComponent("Q", key->q);
	printComponent("G", key->g);
}
