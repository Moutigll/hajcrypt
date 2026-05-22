#include <stdlib.h>

#include "../../../hajlib/include/hprintf.h" /* IWYU pragma: keep */
#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/asymmetric/pkey.h"
#include "../../../includes/x509/asn1.h"
#include "../../../includes/cipher/cipher.h"

#include "../../../includes/asymmetric/dsa.h"

/**
 * @brief Encode a DSA public key in PKCS#1 / traditional DER format.
 *
 * DSAPublicKey ::= SEQUENCE {
 *    p  INTEGER,
 *    q  INTEGER,
 *    g  INTEGER,
 *    y  INTEGER   -- public key
 * }
 */
static uint8_t	*dsaPubEncodePkcs1(const void *key, size_t *outLen)
{
	const t_dsaKey	*k;
	uint8_t			*pDer;
	uint8_t			*qDer;
	uint8_t			*gDer;
	uint8_t			*yDer;
	uint8_t			*seq;
	size_t			pLen;
	size_t			qLen;
	size_t			gLen;
	size_t			yLen;
	size_t			seqLen;

	k = (const t_dsaKey *)key;
	if (!k || !outLen || !k->p || !k->q || !k->g || !k->pub)
		return (NULL);
	pDer = NULL;
	qDer = NULL;
	gDer = NULL;
	yDer = NULL;
	seq = NULL;
	pDer = bigIntToDerInteger(k->p, &pLen);
	if (!pDer)
		return (NULL);
	qDer = bigIntToDerInteger(k->q, &qLen);
	if (!qDer)
		goto exit;
	gDer = bigIntToDerInteger(k->g, &gLen);
	if (!gDer)
		goto exit;
	yDer = bigIntToDerInteger(k->pub, &yLen);
	if (!yDer)
		goto exit;
	{
		uint8_t	*elements[4];
		size_t	lens[4];

		elements[0] = pDer;
		lens[0] = pLen;
		elements[1] = qDer;
		lens[1] = qLen;
		elements[2] = gDer;
		lens[2] = gLen;
		elements[3] = yDer;
		lens[3] = yLen;
		seq = asn1EncodeSequence(elements, lens, 4, &seqLen);
	}
exit:
	free(pDer);
	free(qDer);
	free(gDer);
	free(yDer);
	if (seq)
	{
		*outLen = seqLen;
		return (seq);
	}
	return (NULL);
}

/**
 * @brief Encode a DSA public key payload for SubjectPublicKeyInfo (SPKI).
 *
 * Returns only INTEGER y (the public key value), because p, q, g are
 * already present in the AlgorithmIdentifier parameters.
 */
static uint8_t	*dsaPubEncodeSpki(const void *key, size_t *outLen)
{
	const t_dsaKey	*k;

	k = (const t_dsaKey *)key;
	if (!k || !outLen || !k->pub)
		return (NULL);
	return (bigIntToDerInteger(k->pub, outLen));
}

/**
 * @brief Encode a DSA private key in PKCS#1 / traditional DER format.
 *
 * DSAPrivateKey ::= SEQUENCE {
 *    version  INTEGER (0),
 *    p        INTEGER,
 *    q        INTEGER,
 *    g        INTEGER,
 *    y        INTEGER,   -- public key
 *    x        INTEGER    -- private key
 * }
 */
static uint8_t	*dsaPrivEncodePkcs1(const void *key, size_t *outLen)
{
	const t_dsaKey	*k;
	uint8_t			version[1];
	uint8_t			*vDer;
	uint8_t			*ders[5];
	uint8_t			*seq;
	size_t			vLen;
	size_t			lens[5];
	const t_bigInt	*ints[5];
	int				i;

	k = (const t_dsaKey *)key;
	if (!k || !outLen || !k->p || !k->q || !k->g || !k->pub || !k->priv)
		return (NULL);
	version[0] = 0x00;
	vDer = asn1EncodeInteger(version, 1, &vLen);
	if (!vDer)
		return (NULL);
	ints[0] = k->p;
	ints[1] = k->q;
	ints[2] = k->g;
	ints[3] = k->pub;
	ints[4] = k->priv;
	i = 0;
	while (i < 5)
	{
		ders[i] = bigIntToDerInteger(ints[i], &lens[i]);
		if (!ders[i])
		{
			while (i--)
				free(ders[i]);
			free(vDer);
			return (NULL);
		}
		i++;
	}
	{
		uint8_t	*elements[6];
		size_t	elemLen[6];
		size_t	seqLen;

		elements[0] = vDer;
		elemLen[0] = vLen;
		elements[1] = ders[0];
		elemLen[1] = lens[0];
		elements[2] = ders[1];
		elemLen[2] = lens[1];
		elements[3] = ders[2];
		elemLen[3] = lens[2];
		elements[4] = ders[3];
		elemLen[4] = lens[3];
		elements[5] = ders[4];
		elemLen[5] = lens[4];
		seq = asn1EncodeSequence(elements, elemLen, 6, &seqLen);
		*outLen = seqLen;
	}
	free(vDer);
	i = 0;
	while (i < 5)
	{
		free(ders[i]);
		i++;
	}
	return (seq);
}

/**
 * @brief Encode a DSA private key payload for PKCS#8 (OCTET STRING content).
 *
 * Returns only INTEGER x (the private key value), because p, q, g are
 * already present in the AlgorithmIdentifier parameters.
 */
static uint8_t	*dsaPrivEncodePkcs8(const void *key, size_t *outLen)
{
	const t_dsaKey	*k;

	k = (const t_dsaKey *)key;
	if (!k || !outLen || !k->priv)
		return (NULL);
	return (bigIntToDerInteger(k->priv, outLen));
}

/**
 * @brief Encode DSA algorithm parameters for AlgorithmIdentifier.
 *
 * Dss-Parms ::= SEQUENCE { p, q, g }
 */
static uint8_t	*dsaEncodeAlgoParams(const void *key, size_t *outLen)
{
	const t_dsaKey	*k;
	uint8_t			*pDer;
	uint8_t			*qDer;
	uint8_t			*gDer;
	uint8_t			*seq;
	size_t			pLen;
	size_t			qLen;
	size_t			gLen;
	size_t			seqLen;

	k = (const t_dsaKey *)key;
	if (!k || !outLen || !k->p || !k->q || !k->g)
		return (NULL);
	pDer = NULL;
	qDer = NULL;
	gDer = NULL;
	seq = NULL;
	pDer = bigIntToDerInteger(k->p, &pLen);
	if (!pDer)
		return (NULL);
	qDer = bigIntToDerInteger(k->q, &qLen);
	if (!qDer)
		goto exit;
	gDer = bigIntToDerInteger(k->g, &gLen);
	if (!gDer)
		goto exit;
	{
		uint8_t	*elements[3];
		size_t	lens[3];

		elements[0] = pDer;
		lens[0] = pLen;
		elements[1] = qDer;
		lens[1] = qLen;
		elements[2] = gDer;
		lens[2] = gLen;
		seq = asn1EncodeSequence(elements, lens, 3, &seqLen);
	}
exit:
	free(pDer);
	free(qDer);
	free(gDer);
	if (seq)
	{
		*outLen = seqLen;
		return (seq);
	}
	return (NULL);
}

/**
 * @brief Extract DSA domain parameters (p, q, g) from an AlgorithmIdentifier
 *        SEQUENCE and store them in the key.
 * @return 1 on success, 0 on failure (key left untouched on error).
 */
static int	dsaParseAlgoParams(const uint8_t *algoParams, size_t algoParamsLen, t_dsaKey *k)
{
	uint8_t		*seq;
	size_t		seqLen;
	size_t		parConsumed;
	uint8_t		*pVal;
	uint8_t		*qVal;
	uint8_t		*gVal;
	size_t		pLen;
	size_t		qLen;
	size_t		gLen;

	if (!asn1ParseSequence(algoParams, algoParamsLen,
			&seq, &seqLen, &parConsumed))
		return (0);

	{
		const uint8_t	*ptr;
		size_t		rem;

		ptr = seq;
		rem = seqLen;
		if (!asn1ParseInteger(ptr, rem, &pVal, &pLen, &parConsumed))
			return (0);
		ptr += parConsumed;
		rem -= parConsumed;
		if (!asn1ParseInteger(ptr, rem, &qVal, &qLen, &parConsumed))
			return (0);
		ptr += parConsumed;
		rem -= parConsumed;
		if (!asn1ParseInteger(ptr, rem, &gVal, &gLen, &parConsumed))
			return (0);
	}

	k->p = bigIntFromBytes(pVal, pLen);
	k->q = bigIntFromBytes(qVal, qLen);
	k->g = bigIntFromBytes(gVal, gLen);
	if (!k->p || !k->q || !k->g)
	{
		bigIntFree(k->p);
		bigIntFree(k->q);
		bigIntFree(k->g);
		k->p = NULL;
		k->q = NULL;
		k->g = NULL;
		return (0);
	}
	k->bits = bigIntBitLength(k->p);
	return (1);
}

/**
 * @brief Parse a DER-encoded DSA public key payload.
 *
 * Handles both PKCS#1 format (SEQUENCE { p, q, g, y }) and SPKI format
 * (INTEGER y alone, when p, q, g come from AlgorithmIdentifier).
 */
static int	dsaPubDecode(const uint8_t *der, size_t len, const uint8_t *algoParams, size_t algoParamsLen, void *key)
{
	t_dsaKey	*k;
	uint8_t		*content;
	uint8_t		*pVal;
	uint8_t		*qVal;
	uint8_t		*gVal;
	uint8_t		*yVal;
	size_t		contentLen;
	size_t		consumed;
	size_t		pLen;
	size_t		qLen;
	size_t		gLen;
	size_t		yLen;

	k = (t_dsaKey *)key;
	if (!k || !der || len == 0)
		return (0);

	/* SPKI : INTEGER y seul + paramètres externes */
	if (asn1ParseInteger(der, len, &yVal, &yLen, &consumed)
		&& consumed == len)
	{
		if (!algoParams || algoParamsLen == 0)
			return (0);
		if (!dsaParseAlgoParams(algoParams, algoParamsLen, k))
			return (0);
		k->pub = bigIntFromBytes(yVal, yLen);
		if (!k->pub)
		{
			bigIntFree(k->p);
			bigIntFree(k->q);
			bigIntFree(k->g);
			k->p = NULL;
			k->q = NULL;
			k->g = NULL;
			return (0);
		}
		return (1);
	}

	/* Traditionnel : SEQUENCE { p, q, g, y } */
	if (!asn1ParseSequence(der, len, &content, &contentLen, &consumed))
		return (0);
	if (!asn1ParseInteger(content, contentLen, &pVal, &pLen, &consumed))
		return (0);
	content += consumed;
	contentLen -= consumed;
	if (!asn1ParseInteger(content, contentLen, &qVal, &qLen, &consumed))
		return (0);
	content += consumed;
	contentLen -= consumed;
	if (!asn1ParseInteger(content, contentLen, &gVal, &gLen, &consumed))
		return (0);
	content += consumed;
	contentLen -= consumed;
	if (!asn1ParseInteger(content, contentLen, &yVal, &yLen, &consumed))
		return (0);
	k->p = bigIntFromBytes(pVal, pLen);
	k->q = bigIntFromBytes(qVal, qLen);
	k->g = bigIntFromBytes(gVal, gLen);
	k->pub = bigIntFromBytes(yVal, yLen);
	if (!k->p || !k->q || !k->g || !k->pub)
	{
		bigIntFree(k->p);
		bigIntFree(k->q);
		bigIntFree(k->g);
		bigIntFree(k->pub);
		k->p = NULL;
		k->q = NULL;
		k->g = NULL;
		k->pub = NULL;
		return (0);
	}
	k->bits = bigIntBitLength(k->p);
	return (1);
}

/**
 * @brief Parse a DER-encoded DSA private key payload.
 *
 * Handles both PKCS#1 format (SEQUENCE { v, p, q, g, y, x }) and PKCS#8
 * format (INTEGER x alone, when p, q, g come from AlgorithmIdentifier).
 */
static int	dsaPrivDecode(const uint8_t *der, size_t len, const uint8_t *algoParams, size_t algoParamsLen, void *key)
{
	t_dsaKey	*k;
	uint8_t		*xVal;
	size_t		xLen;
	uint8_t		*content;
	uint8_t		*vals[6];
	size_t		contentLen;
	size_t		consumed;
	size_t		lens[6];
	t_bigInt	**ptrs[6];
	int			i;
	int			ret;

	k = (t_dsaKey *)key;
	if (!k || !der || len == 0)
		return (0);

	/* PKCS#8 : INTEGER x seul + paramètres externes */
	if (asn1ParseInteger(der, len, &xVal, &xLen, &consumed)
		&& consumed == len)
	{
		if (!algoParams || algoParamsLen == 0)
			return (0);
		if (!dsaParseAlgoParams(algoParams, algoParamsLen, k))
			return (0);
		k->priv = bigIntFromBytes(xVal, xLen);
		if (!k->priv)
		{
			bigIntFree(k->p); bigIntFree(k->q); bigIntFree(k->g);
			k->p = NULL; k->q = NULL; k->g = NULL;
			return (0);
		}
		/* Recompute public key from algorithm parameters */
		k->pub = bigIntNew(k->p->numWords);
		if (!k->pub)
		{
			dsaFreeKey(k);
			return (0);
		}
		bigIntModExp(k->pub, k->g, k->priv, k->p);
		return (1);
	}

	/* Traditionnel : SEQUENCE { v, p, q, g, y, x } */
	ptrs[0] = NULL;
	ptrs[1] = &k->p;
	ptrs[2] = &k->q;
	ptrs[3] = &k->g;
	ptrs[4] = &k->pub;
	ptrs[5] = &k->priv;
	ret = 0;
	if (!asn1ParseSequence(der, len, &content, &contentLen, &consumed))
		return (0);
	i = 0;
	while (i < 6)
	{
		if (!asn1ParseInteger(content, contentLen, &vals[i], &lens[i],
				&consumed))
			goto cleanup;
		content += consumed;
		contentLen -= consumed;
		if (i == 0)
		{
			if (lens[0] != 1 || vals[0][0] != 0x00)
				goto cleanup;
		}
		else
		{
			*ptrs[i] = bigIntFromBytes(vals[i], lens[i]);
			if (!*ptrs[i])
				goto cleanup;
		}
		i++;
	}
	k->bits = bigIntBitLength(k->p);
	ret = 1;
cleanup:
	if (!ret)
	{
		i = 1;
		while (i < 6)
		{
			bigIntFree(*ptrs[i]);
			*ptrs[i] = NULL;
			i++;
		}
	}
	return (ret);
}

/* =========================================================================
 *              Utility wrappers
 * ========================================================================= */

static int	dsaValidateBits(int bits)
{
	if (bits != 1024 && bits != 2048 && bits != 3072)
		return (HAJCRYPT_DPRINT("Invalid DSA key size: %d bits. Supported sizes: 1024, 2048, 3072.\n", bits), (0));
	return (1);
}

static size_t	dsaKeySizeBytes(const void *key)
{
	const t_dsaKey	*k;

	k = (const t_dsaKey *)key;
	if (!k || !k->q)
		return (0);
	return ((bigIntBitLength(k->q) + 7) / 8);
}

static size_t	dsaMaxSignatureLen(const void *key)
{
	size_t	qb;

	qb = dsaKeySizeBytes(key);
	return (2 * qb + 8);
}

static int	dsaGenKey(void *key, int bits)
{
	return (dsaGenerateKey((t_dsaKey *)key, bits));
}



const t_pkeyDef	g_dsaPkeyDef = {
	/* Identity */
	.type			= PKEY_TYPE_DSA,
	.oid			= OID_DEF("dsa", DSA_OID),
	.name			= "dsa",
	.keyLen			= sizeof(t_dsaKey),
	.caps			= PKEY_CAP_SIGN,
	.defaultBits	= 2048,

	/* PEM serialization */
	.tradPubLabel		= "DSA PUBLIC KEY",
	.tradPrivLabel		= "DSA PRIVATE KEY",
	.encodeAlgoParams	= dsaEncodeAlgoParams,
	.encodePubKeyPkcs1	= dsaPubEncodePkcs1,
	.encodePubKeySpki	= dsaPubEncodeSpki,
	.encodePrivKeyPkcs1	= dsaPrivEncodePkcs1,
	.encodePrivKeyPkcs8	= dsaPrivEncodePkcs8,
	.decodePubKey		= dsaPubDecode,
	.decodePrivKey		= dsaPrivDecode,

	/* Key generation */
	.generate		= dsaGenKey,
	.freeKey		= (void (*)(void *))dsaFreeKey,
	.validateBits	= dsaValidateBits,

	/* Cryptographic operations */
	.encrypt		= NULL,
	.decrypt		= NULL,
	.sign			= dsaSign,
	.verify			= dsaVerify,

	/* Utility */
	.maxSignatureLen	= dsaMaxSignatureLen,
	.keySizeBytes		= dsaKeySizeBytes,
	.checkKey			= (int (*)(const void *))dsaCheckKey,
	.printKey			= (void (*)(const void *, int))dsaPrintKey
};


char	*dsaKeyToPem(t_dsaKey *key, int isPrivate, int useTraditional, const char *password, const t_cipher *cipher)
{
	t_pkey	pkey;

	pkey.def = &g_dsaPkeyDef;
	pkey.key = key;
	return (pkeyToPem(&pkey, isPrivate, useTraditional, password, cipher));
}

int	dsaKeyFromPem(const char *pem, t_dsaKey *key, int isPrivate, const char *password)
{
	t_pkey	pkey;
	int		ret;

	if (!pem || !key)
		return (0);
	ft_bzero(key, sizeof(t_dsaKey));
	pkey.def = &g_dsaPkeyDef;
	pkey.key = NULL;
	ret = pkeyFromPem(pem, &pkey, isPrivate, password);
	if (ret == 1)
	{
		ft_memcpy(key, pkey.key, sizeof(t_dsaKey));
		free(pkey.key);
		return (1);
	}
	return (ret);
}
