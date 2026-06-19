#include <stdlib.h>

#include "../../../hajlib/include/hprintf.h" /* IWYU pragma: keep */
#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/asymmetric/pkey.h"
#include "../../../includes/asymmetric/rsa.h"


typedef struct s_crtPool
{
	void		*raw;

	t_bigInt	*c;
	t_bigInt	*cp;
	t_bigInt	*cq;
	t_bigInt	*rp;
	t_bigInt	*rq;
	t_bigInt	*rpE;
	t_bigInt	*rqE;
	t_bigInt	*m1;
	t_bigInt	*m2;
	t_bigInt	*h;
	t_bigInt	*m;
	t_bigInt	*tmp;
	t_bigInt	*fcheck;
} t_crtPool;


static int crtPoolAlloc(t_crtPool *pool, const uint8_t *data, size_t dataLen, const t_rsaKey *key)
{
	size_t pW = key->p->numWords;
	size_t qW = key->q->numWords;
	size_t nW = key->n->numWords;

	pool->c		= bigIntFromBytes(data, dataLen);
	pool->cp	= bigIntNew(pW + 1);
	pool->cq	= bigIntNew(qW + 1);
	pool->rp	= bigIntNew(pW);
	pool->rq	= bigIntNew(qW);
	pool->rpE	= bigIntNew(pW + 1);
	pool->rqE	= bigIntNew(qW + 1);
	pool->m1	= bigIntNew(pW + 1);
	pool->m2	= bigIntNew(qW + 1);
	pool->h		= bigIntNew(pW + 1);
	pool->m		= bigIntNew(nW + 2);
	pool->tmp	= bigIntNew(nW * 2 + 2);   /* double-taille, pas d'overflow */
	pool->fcheck	= bigIntNew(nW + 1);

	return (pool->c && pool->cp && pool->cq && pool->rp && pool->rq &&
			pool->rpE && pool->rqE && pool->m1 && pool->m2 &&
			pool->h && pool->m && pool->tmp && pool->fcheck);
}


static void crtPoolFree(t_crtPool *pool)
{
	if (pool->c)	bigIntZero(pool->c);
	if (pool->cp)	bigIntZero(pool->cp);
	if (pool->cq)	bigIntZero(pool->cq);
	if (pool->rp)	bigIntZero(pool->rp);
	if (pool->rq)	bigIntZero(pool->rq);
	if (pool->m1)	bigIntZero(pool->m1);
	if (pool->m2)	bigIntZero(pool->m2);
	if (pool->m)	bigIntZero(pool->m);
	if (pool->tmp)	bigIntZero(pool->tmp);

	bigIntFree(pool->c);		bigIntFree(pool->cp);  bigIntFree(pool->cq);
	bigIntFree(pool->rp);	bigIntFree(pool->rq);
	bigIntFree(pool->rpE);	bigIntFree(pool->rqE);
	bigIntFree(pool->m1);	bigIntFree(pool->m2);
	bigIntFree(pool->h);		bigIntFree(pool->m);
	bigIntFree(pool->tmp);	bigIntFree(pool->fcheck);
}

static void generatePrimeBlindfactor(t_bigInt *rb, t_bigInt *rbE, const t_bigInt *pr, const t_bigInt *e)
{
	do {
		bigIntRandom(rb, bigIntBitLength(pr));
		bigIntMod(rb, rb, pr);
	} while (bigIntIsZero(rb));

	bigIntModExp(rbE, rb, e, pr);
}

int bigIntCmpConstTime(const t_bigInt *a, const t_bigInt *b)
{
	size_t i;
	size_t maxWords = (a->numWords > b->numWords) ? a->numWords : b->numWords;
	uint32_t diff = 0;

	for (i = 0; i < maxWords; i++)
	{
		uint32_t aw = (i < a->numWords) ? a->words[i] : 0;
		uint32_t bw = (i < b->numWords) ? b->words[i] : 0;
		diff |= aw ^ bw;
	}
	return (diff == 0) ? 1 : 0;
}

static int rsaPrivateOp(const uint8_t *data,   size_t dataLen, const t_rsaKey *key, uint8_t *out, size_t *outLen)
{
	t_crtPool   pool;
	size_t	  k;
	int		 res = 0;

	ft_memset(&pool, 0, sizeof(pool));
	if (!crtPoolAlloc(&pool, data, dataLen, key))
		goto exit;

	bigIntMod(pool.cp, pool.c, key->p);
	bigIntMod(pool.cq, pool.c, key->q);

	generatePrimeBlindfactor(pool.rp, pool.rpE, key->p, key->e);
	bigIntMul(pool.tmp, pool.cp, pool.rpE);
	bigIntMod(pool.cp, pool.tmp, key->p);	  /* cp = c * rp^e mod p */

	generatePrimeBlindfactor(pool.rq, pool.rqE, key->q, key->e);
	bigIntMul(pool.tmp, pool.cq, pool.rqE);
	bigIntMod(pool.cq, pool.tmp, key->q);	  /* cq = c * rq^e mod q */

	if (!bigIntModExpConstTime(pool.m1, pool.cp, key->dp, key->p))
		goto exit;
	if (!bigIntModExpConstTime(pool.m2, pool.cq, key->dq, key->q))
		goto exit;

	/* m1 = m1 * rp^(-1) mod p */
	if (!bigIntModInverse(pool.rp, pool.rp, key->p))
		goto exit;
	bigIntMul(pool.tmp, pool.m1, pool.rp);
	bigIntMod(pool.m1, pool.tmp, key->p);

	/* m2 = m2 * rq^(-1) mod q */
	if (!bigIntModInverse(pool.rq, pool.rq, key->q))
		goto exit;
	bigIntMul(pool.tmp, pool.m2, pool.rq);
	bigIntMod(pool.m2, pool.tmp, key->q);

	/*
	 * h = qinv * (m1 - m2 mod p) mod p
	 *
	 * m1 ∈ [0, p-1], m2 ∈ [0, q-1].
	 * On réduit m2 mod p d'abord ; si m1 < (m2 mod p), on ajoute p
	 * pour éviter un underflow dans la soustraction.
	 */
	bigIntMod(pool.h, pool.m2, key->p);			/* h = m2 mod p		 */
	if (bigIntCmp(pool.m1, pool.h) < 0)
		bigIntAdd(pool.m1, pool.m1, key->p);		/* m1 += p */
	bigIntSub(pool.h, pool.m1, pool.h);			 /* h = m1 - (m2 mod p)  */
	bigIntMul(pool.tmp, key->qinv, pool.h);
	bigIntMod(pool.h, pool.tmp, key->p);			/* h = qinv*(m1-m2) mod p*/

	bigIntMul(pool.tmp, key->q, pool.h);			/* tmp = q * h		  */
	bigIntAdd(pool.m, pool.m2, pool.tmp);		   /* m   = m2 + q*h	   */

	k		= rsaModulusBytes(key);
	*outLen	= bigIntToBytes(pool.m, out, k);
	res		= 1;

exit:
	crtPoolFree(&pool);
	return (res);
}

static inline int rsaPublicOp(const uint8_t *data, size_t dataLen, const t_rsaKey *key, uint8_t *out, size_t *outLen)
{
	t_bigInt	*m;
	t_bigInt	*c;
	size_t		k;

	m = bigIntFromBytes(data, dataLen);
	c = bigIntNew(key->n->numWords + 1);
	if (!m || !c)
	{
		bigIntFree(m);
		bigIntFree(c);
		return (0);
	}
	bigIntModExp(c, m, key->e, key->n);
	k	   = rsaModulusBytes(key);
	*outLen = bigIntToBytes(c, out, k);
	bigIntFree(m);
	bigIntFree(c);
	return (1);
}


int	rsaEncrypt(const uint8_t	*input,		size_t	inputLen,
			   const void		*key,
			   uint8_t			*output,	size_t	*outputLen,
			   t_pkeyPadding	padding)
{
	const t_rsaKey	*rsa = (const t_rsaKey *)key;
	size_t			k   = rsaModulusBytes(rsa);

	if (padding == PKEY_PADDING_NONE)
	{
		uint8_t *paddedInput;
		int	  opOk;

		HAJCRYPT_DPRINT(P_ORANGE "Warning: encrypting without padding\n" P_RESET);
		if (inputLen > k)
		{
			HAJCRYPT_DPRINT(P_RED "rsaEncrypt: message too long (%zu > %zu)\n"
							P_RESET, inputLen, k);
			return (0);
		}
		if (inputLen == k)
			return rsaPublicOp(input, inputLen, rsa, output, outputLen);

		paddedInput = calloc(1, k);
		if (!paddedInput)
			return (0);
		ft_memcpy(paddedInput + (k - inputLen), input, inputLen);
		opOk = rsaPublicOp(paddedInput, k, rsa, output, outputLen);
		free(paddedInput);
		return (opOk);
	}

	{
		uint8_t *padded = malloc(k);
		int	  padOk  = 0;
		int	  opOk;

		if (!padded)
			return (0);

		if (padding == PKEY_PADDING_PKCS1V15)
			padOk = rsaPkcs1v15PadEncrypt(input, inputLen, rsa, padded, k);
		else if (padding == PKEY_PADDING_OAEP)
			padOk = rsaOaepPadEncrypt(input, inputLen, rsa, padded, k);
		else
		{
			HAJCRYPT_DPRINT("rsaEncrypt: unsupported padding %d\n", padding);
			free(padded);
			return (0);
		}
		if (!padOk) { free(padded); return (0); }
		opOk = rsaPublicOp(padded, k, rsa, output, outputLen);
		free(padded);
		return (opOk);
	}
}


int rsaDecrypt(const uint8_t	*input,		size_t	inputLen,
			   const void		*key,
			   uint8_t			*output,	size_t	*outputLen,
			   t_pkeyPadding	padding)
{
	const t_rsaKey	*rsa = (const t_rsaKey *)key;
	size_t			k   = rsaModulusBytes(rsa);
	uint8_t			*padded;
	size_t			paddedLen;
	int				unpadOk;

	if (inputLen != k)
		return (0);
	padded = malloc(k);
	if (!padded)
		return (0);

	if (!rsaPrivateOp(input, k, rsa, padded, &paddedLen))
	{
		free(padded);
		return (0);
	}

	unpadOk = 0;
	if (padding == PKEY_PADDING_NONE)
	{
		size_t start = 0;

		HAJCRYPT_DPRINT(P_ORANGE "Warning: decrypting without padding\n" P_RESET);
		while (start < paddedLen && padded[start] == 0)
			start++;
		*outputLen = paddedLen - start;
		if (*outputLen)
			ft_memcpy(output, padded + start, *outputLen);
		unpadOk = 1;
	}
	else if (padding == PKEY_PADDING_PKCS1V15)
		unpadOk = rsaPkcs1v15UnpadEncrypt(padded, paddedLen, output, outputLen);
	else if (padding == PKEY_PADDING_OAEP)
		unpadOk = rsaOaepUnpadEncrypt(padded, paddedLen, output, outputLen);
	else
		HAJCRYPT_DPRINT("rsaDecrypt: unsupported padding %d\n", padding);

	ft_bzero(padded, k);
	free(padded);
	return (unpadOk ? 1 : 0);
}

int	rsaSign(const uint8_t	*digest,	size_t	digestLen,
			const t_algoId	*digestAlgo,
			const void		*key,
			uint8_t			*sig,		size_t	*sigLen,
			t_pkeyPadding	padding)
{
	const t_rsaKey	*rsa = (const t_rsaKey *)key;
	size_t			k   = rsaModulusBytes(rsa);
	uint8_t			*padded;
	int				padOk = 0;
	int				opOk;

	padded = malloc(k);
	if (!padded)
		return (0);

	if (padding == PKEY_PADDING_PKCS1V15)
		padOk = rsaPkcs1v15PadSign(digest, digestLen, digestAlgo, rsa, padded, k);
	else if (padding == PKEY_PADDING_PSS)
		padOk = rsaPssPadSign(digest, digestLen, digestAlgo, rsa, padded, k);
	else
	{
		HAJCRYPT_DPRINT("rsaSign: unsupported padding %d\n", padding);
		free(padded);
		return (0);
	}
	if (!padOk) { free(padded); return (0); }

	/* OPT-13 : CRT + blinding per-prime + fault check via dispatcher */
	opOk = rsaPrivateOp(padded, k, rsa, sig, sigLen);
	ft_bzero(padded, k);
	free(padded);
	return (opOk);
}


int rsaVerify(const uint8_t		*digest,	size_t digestLen,
			  const t_algoId	*digestAlgo,
			  const void		*key,
			  const uint8_t		*sig,		size_t sigLen,
			  t_pkeyPadding		padding)
{
	const t_rsaKey	*rsa = (const t_rsaKey *)key;
	size_t			k   = rsaModulusBytes(rsa);
	uint8_t			*padded;
	size_t			paddedLen;
	int				ret = 0;

	if (sigLen != k)
		return (0);
	padded = malloc(k);
	if (!padded)
		return (0);
	if (!rsaPublicOp(sig, sigLen, rsa, padded, &paddedLen))
	{
		free(padded);
		return (0);
	}

	if (padding == PKEY_PADDING_PKCS1V15)
	{
		uint8_t recoveredDigest[64];
		size_t  recoveredLen;
		uint8_t diff = 0;
		size_t  i;

		if (rsaPkcs1v15UnpadSign(padded, paddedLen,
				recoveredDigest, &recoveredLen, digestAlgo))
		{
			if (recoveredLen == digestLen)
			{
				for (i = 0; i < digestLen; i++)
					diff |= recoveredDigest[i] ^ digest[i];
			}
			else
				diff = 1;
			ret = (diff == 0) ? 1 : 0;
		}
	}
	else if (padding == PKEY_PADDING_PSS)
	{
		if (rsaPssUnpadSign(padded, paddedLen, digest, digestLen, digestAlgo))
			ret = 1;
	}
	else
		HAJCRYPT_DPRINT("rsaVerify: unsupported padding %d\n", padding);

	free(padded);
	return (ret);
}
