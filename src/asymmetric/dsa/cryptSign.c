#include <stdlib.h>
#include <unistd.h>

#include "../../../hajlib/include/hmemory.h"
#include "../../../hajlib/include/hprintf.h" /* IWYU pragma: keep */
#include "../../../includes/asymmetric/pkey.h"
#include "../../../includes/asymmetric/dsa.h"
#include "../../../includes/x509/asn1.h"

int	dsaSignPkcs15(const uint8_t		*digest,	size_t	digestLen,
				  const t_dsaKey	*key,
				  uint8_t			*sig,		size_t	*sigLen)
{
	t_bigInt	*k = NULL, *kinv = NULL, *r = NULL, *s = NULL, *h = NULL, *tmp1 = NULL, *tmp2 = NULL;
	uint8_t		*rDer = NULL;
	uint8_t		*sDer = NULL;
	uint8_t		*seqDer = NULL;
	size_t		rDerLen;
	size_t		sDerLen;
	size_t		seqLen;
	int			ret = 0;

	if (!digest || !key || !key->priv || !sig || !sigLen)
		return (0);
	/* Validate key */
	if (!key->q || !key->p || !key->g || !key->priv)
		return (0);
	size_t qSize = (bigIntBitLength(key->q) + 7) / 8;
	if (digestLen > qSize)
		digestLen = qSize;
	h = bigIntFromBytes(digest, digestLen);
	if (!h)
		return (0);
	bigIntMod(h, h, key->q);
	k = bigIntNew(key->q->numWords);
	kinv = bigIntNew(key->q->numWords);
	r = bigIntNew(key->q->numWords);
	s = bigIntNew(key->q->numWords);
	tmp1 = bigIntNew(key->p->numWords + 1);
	tmp2 = bigIntNew(key->q->numWords + 1);
	if (!k || !kinv || !r || !s || !tmp1 || !tmp2)
		goto cleanup;
	while (1)
	{
		do {
			bigIntRandom(k, bigIntBitLength(key->q));
			bigIntMod(k, k, key->q);
		} while (bigIntIsZero(k));
		bigIntModExpConstTime(tmp1, key->g, k, key->p);
		bigIntMod(r, tmp1, key->q);
		if (bigIntIsZero(r))
			continue ;
		{
			t_bigInt *two = bigIntFromUint64(2);
			t_bigInt *exp = bigIntNew(key->q->numWords);
			if (!two || !exp) {
				bigIntFree(two); bigIntFree(exp);
				goto cleanup;
			}
			bigIntSub(exp, key->q, two);          /* exp = q - 2 */
			if (!bigIntModExpConstTime(kinv, k, exp, key->q)) {
				bigIntFree(two); bigIntFree(exp);
				continue;
			}
			bigIntFree(two);
			bigIntFree(exp);
		}
		bigIntMulMod(tmp2, key->priv, r, key->q);
		bigIntAdd(tmp2, tmp2, h);
		bigIntMod(tmp2, tmp2, key->q);
		bigIntMulMod(s, kinv, tmp2, key->q);
		if (bigIntIsZero(s))
			continue ;
		break ;
	}
	rDer = bigIntToDerInteger(r, &rDerLen);
	sDer = bigIntToDerInteger(s, &sDerLen);
	if (!rDer || !sDer)
		goto cleanup;
	{
		uint8_t	*elements[2];
		size_t	elemLens[2];

		elements[0] = rDer;
		elements[1] = sDer;
		elemLens[0] = rDerLen;
		elemLens[1] = sDerLen;
		seqDer = asn1EncodeSequence(elements, elemLens, 2, &seqLen);
	}
	if (!seqDer)
		goto cleanup;
	if (seqLen <= *sigLen)
	{
		ft_memcpy(sig, seqDer, seqLen);
		*sigLen = seqLen;
		ret = 1;
	} else
		HAJCRYPT_DPRINT("DSA sign: signature buffer too small, need %zu bytes but got %zu\n", seqLen, *sigLen);
cleanup:
	free(rDer); free(sDer); free(seqDer);
	bigIntFree(h); bigIntFree(k); bigIntFree(kinv); bigIntFree(r); bigIntFree(s); bigIntFree(tmp1); bigIntFree(tmp2);
	return (ret);
}

int	dsaVerifyPkcs15(const uint8_t	*digest,	size_t	digestLen,
					const t_dsaKey	*key,
					const uint8_t	*sig,		size_t	sigLen)
{
	uint8_t		*content;
	uint8_t		*rVal;
	uint8_t		*sVal;
	size_t		contentLen;
	size_t		consumed;
	size_t		rLen;
	size_t		sLen;
	t_bigInt	*r = NULL, *s = NULL, *w = NULL, *h = NULL;
	t_bigInt	*u1 = NULL, *u2 = NULL, *tmp1 = NULL, *tmp2 = NULL;
	int			ret = 0;

	if (!digest || !key || !sig || sigLen == 0)
		return (0);
	if (!key->q || !key->p || !key->g || !key->pub)
		return (0);
	if (!asn1ParseSequence(sig, sigLen, &content, &contentLen, &consumed))
		return (0);
	if (!asn1ParseInteger(content, contentLen, &rVal, &rLen, &consumed))
		return (0);
	content += consumed;
	contentLen -= consumed;

	if (!asn1ParseInteger(content, contentLen, &sVal, &sLen, &consumed))
		return (0);
	r = bigIntFromBytes(rVal, rLen);
	s = bigIntFromBytes(sVal, sLen);
	if (!r || !s)
		goto clean;

	if (bigIntIsZero(r) || bigIntCmp(r, key->q) >= 0
		|| bigIntIsZero(s) || bigIntCmp(s, key->q) >= 0)
		goto clean;

	w = bigIntNew(key->q->numWords);
	if (!bigIntModInverse(w, s, key->q))
		goto clean;

	size_t qSize = (bigIntBitLength(key->q) + 7) / 8;
	if (digestLen > qSize)
		digestLen = qSize;
	h = bigIntFromBytes(digest, digestLen);
	bigIntMod(h, h, key->q);
	u1 = bigIntNew(key->q->numWords);
	u2 = bigIntNew(key->q->numWords);
	bigIntMulMod(u1, h, w, key->q);
	bigIntMulMod(u2, r, w, key->q);
	tmp1 = bigIntNew(key->p->numWords + 1);
	tmp2 = bigIntNew(key->p->numWords + 1);
	if (!u1 || !u2 || !tmp1 || !tmp2)
		goto clean;

	bigIntModExp(tmp1, key->g, u1, key->p);
	bigIntModExp(tmp2, key->pub, u2, key->p);
	bigIntMulMod(tmp1, tmp1, tmp2, key->p);
	bigIntMod(tmp1, tmp1, key->q);
	ret = (bigIntCmp(tmp1, r) == 0);
clean:
	bigIntFree(r); bigIntFree(s); bigIntFree(w); bigIntFree(h);
	bigIntFree(u1); bigIntFree(u2); bigIntFree(tmp1); bigIntFree(tmp2);
	return (ret);
}


int	dsaSign(const uint8_t	*digest,	size_t	digestLen,
			const t_algoId	*digestAlgo,
			const void		*key,
			uint8_t			*sig,		size_t	*sigLen,
			t_pkeyPadding	padding)
{
	(void)digestAlgo;
	if (padding != PKEY_PADDING_NONE && padding != PKEY_PADDING_PKCS1V15)
	{
		HAJCRYPT_DPRINT("dsaSign: unsupported padding %d\n", padding);
		return (0);
	}
	return (dsaSignPkcs15(digest, digestLen, (const t_dsaKey *)key, sig, sigLen));
}

int	dsaVerify(const uint8_t		*digest,	size_t	digestLen,
			  const t_algoId	*digestAlgo,
			  const void		*key,
			  const uint8_t		*sig,		size_t	sigLen,
			  t_pkeyPadding		padding)
{
	(void)digestAlgo;
	if (padding != PKEY_PADDING_NONE && padding != PKEY_PADDING_PKCS1V15)
	{
		HAJCRYPT_DPRINT("dsaVerify: unsupported padding %d\n", padding);
		return (0);
	}
	return (dsaVerifyPkcs15(digest, digestLen, (const t_dsaKey *)key, sig, sigLen));
}
