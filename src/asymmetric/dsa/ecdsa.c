#include <stdlib.h>
#include <sys/types.h>

#include "../../../hajlib/include/hmemory.h"
#include "../../../hajlib/include/hprintf.h"
#include "../../../includes/asymmetric/bigint.h"
#include "../../../includes/hash/sha/sha256.h"
#include "../../../includes/utils/utils.h"
#include "../../../includes/hash/hmac.h"
#include "../../../includes/x509/asn1.h"
#include "../../../includes/x509/oid.h"

#include "../../../includes/asymmetric/ecdsa.h"

static t_bigInt *hashToInt(const uint8_t *hash, size_t hashLen, const t_bigInt *n)
{
	t_bigInt	*h;
	size_t		orderBytes = (bigIntBitLength(n) + 7) / 8;
	
	if (hashLen > orderBytes)
		hashLen = orderBytes;
	
	h = bigIntFromBytes(hash, hashLen);
	if (!h) return (NULL);
	bigIntMod(h, h, n);
	return (h);
}

/* RFC 6979: bits2int */
static t_bigInt *bits2int(const uint8_t *bits, size_t bitLen, const t_bigInt *n)
{
	size_t		nLen = (bigIntBitLength(n) + 7) / 8;
	t_bigInt	*result;
	
	if (bitLen == 0) return (bigIntFromUint64(0));
	if (bitLen > nLen * 8)
		result = bigIntFromBytes(bits, nLen);
	else
		result = bigIntFromBytes(bits, (bitLen + 7) / 8);
	
	if (result)
		bigIntMod(result, result, n);
	return (result);
}

/* RFC 6979: bits2octets */
static void bits2octets(const t_bigInt *x, const t_bigInt *n, uint8_t *out, size_t outLen)
{
	size_t		nLen = (bigIntBitLength(n) + 7) / 8;
	t_bigInt	*tmp;
	
	tmp = bigIntDup(x);
	if (bigIntCmp(tmp, n) >= 0)
		bigIntSub(tmp, tmp, n);

	ft_bzero(out, outLen);
	bigIntToBytes(tmp, out + (outLen - nLen), nLen);
	
	bigIntFree(tmp);
}

/* RFC 6979 section 3.2: Generation of k */
static int generateK(t_bigInt		**k,	const t_bigInt	*n,
					 const uint8_t	*hash,	size_t			hashLen,
					 const t_bigInt	*priv)
{
	t_hmacDrbg	drbg;
	uint8_t		privOctets[66];	 /* max for P-521 (66 bytes) */
	size_t		nLen = (bigIntBitLength(n) + 7) / 8;
	size_t		hashLenAligned = (hashLen > nLen) ? nLen : hashLen;
	size_t		qLen = nLen * 8;
	uint8_t		*t = NULL;
	size_t		tLen;
	
	if (!k || !n || !hash || !priv)
		return (0);
	
	/* 1. Convert priv into octets */
	bits2octets(priv, n, privOctets, nLen);
	
	/* 2. h = hash (bits2octets) */
	uint8_t *hOctets = malloc(nLen);
	if (!hOctets) return (0);
	{
		t_bigInt *hInt = bigIntFromBytes(hash, hashLenAligned);
		if (!hInt) {
			free(hOctets);
			return (0);
		}
		bits2octets(hInt, n, hOctets, nLen);
		bigIntFree(hInt);
	}
	
	/* 3. Initialize DRBG with key = h and V = 0x01... */
	tLen = nLen * 2;
	t = malloc(tLen);
	if (!t) {
		free(hOctets);
		return (0);
	}
	ft_memcpy(t, privOctets, nLen);
	ft_memcpy(t + nLen, hOctets, nLen);
	
	/* 4. HMAC_DRBG_Init(entropy_input = t) */
	hmacDrbgInit(&drbg, &g_sha256Hash, t, tLen, NULL, 0, NULL, 0);
	
	/* 5. Generate k until it is in [1, n-1] */
	*k = bigIntNew(n->numWords);
	if (!*k) {
		free(t);
		free(hOctets);
		return (0);
	}
	
	do {
		uint8_t *kB = malloc(nLen);
		if (!kB) {
			free(t);
			free(hOctets);
			return (0);
		}
		
		/* Generate bits of k */
		hmacDrbgGenerate(&drbg, kB, nLen);
		
		/* Convert to integer */
		bigIntFree(*k);
		*k = bits2int(kB, qLen, n);
		
		secureZeroMemory(kB, nLen);
		free(kB);
		
		if (!*k) break;
		
		/* Reseed if k == 0 ou k >= n */
		if (bigIntIsZero(*k) || bigIntCmp(*k, n) >= 0) {
			uint8_t additional[1] = {0x01};
			hmacDrbgReseed(&drbg, NULL, 0, additional, sizeof(additional));
			continue;
		}
		
		break;
	} while (1);
	
	secureZeroMemory(t, tLen);
	secureZeroMemory(privOctets, sizeof(privOctets));
	secureZeroMemory(hOctets, nLen);
	secureZeroMemory(&drbg, sizeof(drbg));
	
	free(t);
	free(hOctets);
	
	return (*k != NULL);
}

static int ecdsaSignCore(t_bigInt					**r,	t_bigInt	**s,
						 const t_bigInt				*priv,
						 const uint8_t				*hash,	size_t		hashLen,
						 const t_weierstrassParams	*params)
{
	t_bigInt *k = NULL, *kinv = NULL, *r_temp = NULL, *s_temp = NULL;
	t_bigInt *hashInt = NULL;
	t_ecPoint R;
	int ret = 0;
	
	if (!priv || !hash || !params) return (0);
	
	hashInt = hashToInt(hash, hashLen, params->n);
	if (!hashInt) return (0);
	
	R.x = bigIntNew(params->p->numWords);
	R.y = bigIntNew(params->p->numWords);
	if (!R.x || !R.y) {
		bigIntFree(hashInt);
		return (0);
	}
	
	if (!generateK(&k, params->n, hash, hashLen, priv))
		goto cleanup;
	
	/* R = k * G */
	if (!ecWeierstrassScalarMult(&R, k, &params->G, params->p, params->a))
		goto cleanup;
	
	/* r = x(R) mod n */
	r_temp = bigIntNew(params->n->numWords);
	if (!r_temp) goto cleanup;
	bigIntMod(r_temp, R.x, params->n);
	if (bigIntIsZero(r_temp)) {
		/* r=0 est invalide, recommencer */
		bigIntFree(k);
		bigIntFree(r_temp);
		bigIntFree(R.x);
		bigIntFree(R.y);
		bigIntFree(hashInt);
		return ecdsaSignCore(r, s, priv, hash, hashLen, params);
	}
	
	/* s = k^-1 * (hashInt + r * priv) mod n */
	kinv = bigIntNew(params->n->numWords);
	if (!kinv) goto cleanup;
	if (!bigIntModInverse(kinv, k, params->n)) goto cleanup;
	
	s_temp = bigIntNew(params->n->numWords);
	if (!s_temp) goto cleanup;
	bigIntMulMod(s_temp, r_temp, priv, params->n);
	bigIntAdd(s_temp, s_temp, hashInt);
	bigIntMod(s_temp, s_temp, params->n);
	bigIntMulMod(s_temp, kinv, s_temp, params->n);
	
	if (bigIntIsZero(s_temp)) {
		bigIntFree(k); bigIntFree(kinv); bigIntFree(r_temp); bigIntFree(s_temp);
		bigIntFree(R.x); bigIntFree(R.y);
		bigIntFree(hashInt);
		return ecdsaSignCore(r, s, priv, hash, hashLen, params);
	}
	
	*r = r_temp;
	*s = s_temp;
	ret = 1;
	
cleanup:
	if (!ret) {
		bigIntFree(r_temp);
		bigIntFree(s_temp);
	}
	bigIntFree(k);
	bigIntFree(kinv);
	bigIntFree(R.x);
	bigIntFree(R.y);
	bigIntFree(hashInt);
	return (ret);
}

/* ECDSA verify core */
static int ecdsaVerifyCore(const t_bigInt				*r,		const t_bigInt	*s,
						   const t_bigInt				*hash,	const t_ecPoint	*pub,
						   const t_weierstrassParams	*params)
{
	t_bigInt *w = NULL, *u1 = NULL, *u2 = NULL;
	t_ecPoint P;
	int ret = 0;
	
	if (!r || !s || !hash || !pub || !params) return (0);
	
	/* Check 0 < r < n et 0 < s < n */
	if (bigIntIsZero(r) || bigIntCmp(r, params->n) >= 0) return (0);
	if (bigIntIsZero(s) || bigIntCmp(s, params->n) >= 0) return (0);
	
	w = bigIntNew(params->n->numWords);
	u1 = bigIntNew(params->n->numWords);
	u2 = bigIntNew(params->n->numWords);
	P.x = bigIntNew(params->p->numWords);
	P.y = bigIntNew(params->p->numWords);
	if (!w || !u1 || !u2 || !P.x || !P.y) goto cleanup;
	
	/* w = s^-1 mod n */
	if (!bigIntModInverse(w, s, params->n)) goto cleanup;
	
	/* u1 = hash * w mod n */
	bigIntMulMod(u1, hash, w, params->n);
	/* u2 = r * w mod n */
	bigIntMulMod(u2, r, w, params->n);
	
	/* P = u1 * G + u2 * pub */
	{
		t_ecPoint u1G, u2Pub;
		u1G.x = bigIntNew(params->p->numWords);
		u1G.y = bigIntNew(params->p->numWords);
		u2Pub.x = bigIntNew(params->p->numWords);
		u2Pub.y = bigIntNew(params->p->numWords);
		if (!u1G.x || !u1G.y || !u2Pub.x || !u2Pub.y) {
			bigIntFree(u1G.x); bigIntFree(u1G.y);
			bigIntFree(u2Pub.x); bigIntFree(u2Pub.y);
			goto cleanup;
		}
		
		if (!ecWeierstrassScalarMult(&u1G, u1, &params->G, params->p, params->a))
			{ bigIntFree(u1G.x); bigIntFree(u1G.y); bigIntFree(u2Pub.x); bigIntFree(u2Pub.y); goto cleanup; }
		if (!ecWeierstrassScalarMult(&u2Pub, u2, pub, params->p, params->a))
			{ bigIntFree(u1G.x); bigIntFree(u1G.y); bigIntFree(u2Pub.x); bigIntFree(u2Pub.y); goto cleanup; }
		if (!ecWeierstrassPointAdd(&P, &u1G, &u2Pub, params->p, params->a))
			{ bigIntFree(u1G.x); bigIntFree(u1G.y); bigIntFree(u2Pub.x); bigIntFree(u2Pub.y); goto cleanup; }
		
		bigIntFree(u1G.x); bigIntFree(u1G.y);
		bigIntFree(u2Pub.x); bigIntFree(u2Pub.y);
	}
	
	/* Check r == x(P) mod n */
	{
		t_bigInt *x_mod = bigIntNew(params->n->numWords);
		if (!x_mod) goto cleanup;
		bigIntMod(x_mod, P.x, params->n);
		ret = (bigIntCmp(r, x_mod) == 0);
		bigIntFree(x_mod);
	}
	
cleanup:
	bigIntFree(w);
	bigIntFree(u1);
	bigIntFree(u2);
	bigIntFree(P.x);
	bigIntFree(P.y);
	return (ret);
}



/* --------------- Public API --------------- */

int ecdsaGenerateKey(t_ecdsaKey *key, int curve)
{
	return ecdhInit(key, curve) && ecdhGenerateKeypair(key);
}

void ecdsaFreeKey(t_ecdsaKey *key)
{
	ecdhFree(key);
}

int ecdsaSetPublicKey(t_ecdsaKey	*key,	int		curveId,
					  const uint8_t	*pubX,	size_t	pubXLen,
					  const uint8_t	*pubY,	size_t	pubYLen)
{
	if (!key || !pubX || !pubY) return (0);
	key->curveId = curveId;
	key->pubX = bigIntFromBytes(pubX, pubXLen);
	key->pubY = bigIntFromBytes(pubY, pubYLen);
	return (key->pubX && key->pubY);
}

int ecdsaSetPrivateKey(t_ecdsaKey		*key,	int		curveId,
					   const uint8_t	*priv,	size_t	privLen)
{
	if (!key || !priv) return (0);
	key->curveId = curveId;
	key->priv = bigIntFromBytes(priv, privLen);
	return (key->priv != NULL);
}

int ecdsaSign(const uint8_t		*digest,	size_t	digestLen,
			  const t_algoId	*digestAlgo,
			  const void		*key,
			  uint8_t			*sig,		size_t	*sigLen,
			  t_pkeyPadding		padding)
{
	const t_ecdhCtx				*k = (const t_ecdhCtx *)key;
	const t_weierstrassParams	*params;
	t_bigInt					*hashInt = NULL, *r = NULL, *s = NULL;
	uint8_t						*rDer = NULL, *sDer = NULL, *seq = NULL;
	size_t						rDerLen, sDerLen, seqLen;
	int							ret = 0;
	
	(void)digestAlgo;
	if (padding != PKEY_PADDING_NONE) return (0);
	if (!digest || !k || !sig || !sigLen) return (0);
	
	params = ecdhGetCurveParams(k->curveId);
	if (!params) return (0);

	hashInt = hashToInt(digest, digestLen, params->n);
	if (!hashInt) return (0);
	
	/* Sign */
	if (!ecdsaSignCore(&r, &s, k->priv, digest, digestLen, params))
		goto cleanup;
	
	/* Encode r and s in DER */
	rDer = bigIntToDerInteger(r, &rDerLen);
	sDer = bigIntToDerInteger(s, &sDerLen);
	if (!rDer || !sDer) goto cleanup;
	
	/* Encode as SEQUENCE of two INTEGERs */
	{
		uint8_t	*elements[2] = { rDer, sDer };
		size_t	lens[2] = { rDerLen, sDerLen };
		seq = asn1EncodeSequence(elements, lens, 2, &seqLen);
	}
	if (!seq) goto cleanup;
	
	if (seqLen <= *sigLen) {
		ft_memcpy(sig, seq, seqLen);
		*sigLen = seqLen;
		ret = 1;
	}
	
cleanup:
	free(rDer);
	free(sDer);
	free(seq);
	bigIntFree(hashInt);
	bigIntFree(r);
	bigIntFree(s);
	return (ret);
}

int ecdsaVerify(const uint8_t	*digest,	size_t	digestLen,
				const t_algoId	*digestAlgo,
				const void		*key,
				const uint8_t	*sig,		size_t	sigLen,
				t_pkeyPadding	padding)
{
	const t_ecdhCtx				*k = (const t_ecdhCtx *)key;
	const t_weierstrassParams	*params;
	t_bigInt					*hashInt = NULL, *r = NULL, *s = NULL;
	t_ecPoint					pub;
	uint8_t						*content;
	size_t						contentLen, consumed;
	uint8_t						*rVal, *sVal;
	size_t						rLen, sLen;
	int							ret = 0;
	
	(void)digestAlgo;
	if (padding != PKEY_PADDING_NONE) return (0);
	if (!digest || !k || !sig || sigLen == 0) return (0);
	
	params = ecdhGetCurveParams(k->curveId);
	if (!params) return (0);
	
	/* Decode signature: SEQUENCE of two INTEGERs */
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
	if (!r || !s) goto cleanup;
	
	hashInt = hashToInt(digest, digestLen, params->n);
	if (!hashInt) goto cleanup;
	
	pub.x = k->pubX;
	pub.y = k->pubY;
	if (!pub.x || !pub.y) goto cleanup;

	ret = ecdsaVerifyCore(r, s, hashInt, &pub, params);
	
cleanup:
	bigIntFree(r);
	bigIntFree(s);
	bigIntFree(hashInt);
	return (ret);
}

void ecdsaPrintKey(const t_ecdsaKey *key, int showPrivate)
{
	if (!key) return;
	ft_printf("ECDSA Key (curve: %d)\n", key->curveId);
	ft_printf("Public X: "); printComponent("", key->pubX);
	ft_printf("Public Y: "); printComponent("", key->pubY);
	if (showPrivate && key->priv) {
		ft_printf("Private: "); printComponent("", key->priv);
	}
}

size_t ecdsaKeySizeBytes(const void *key)
{
	const t_ecdhCtx *k = (const t_ecdhCtx *)key;
	switch (k->curveId) {
		case ECDH_GROUP_SECP256R1: return 32;
		case ECDH_GROUP_SECP384R1: return 48;
		case ECDH_GROUP_SECP521R1: return 66;
		default: return (0);
	}
}

size_t ecdsaMaxSignatureLen(const void *key)
{
	size_t orderBytes = ecdsaKeySizeBytes(key);
	return 2 * orderBytes + 8; /* 2 * (order + overhead) */
}



const t_pkeyDef g_ecdsaPkeyDef = {
	.type				= PKEY_TYPE_ECDSA,
	.oid				= OID_DEF("ecdsa", ECDSA_OID),
	.name				= "ecdsa",
	.keyLen				= sizeof(t_ecdsaKey),
	.caps				= PKEY_CAP_SIGN,
	.defaultBits		= 256,  /* secp256r1 */
	
	.tradPubLabel		= "EC PUBLIC KEY",
	.tradPrivLabel		= "EC PRIVATE KEY",
	
	/* Not needed for now, used for tls 1.3 only */
	.encodeAlgoParams	= NULL,
	.encodePubKeyPkcs1	= NULL,
	.encodePubKeySpki	= NULL,
	.encodePrivKeyPkcs1	= NULL,
	.encodePrivKeyPkcs8	= NULL,
	.decodePubKey		= NULL,
	.decodePrivKey		= NULL,
	
	/* Key generation */
	.generate			= (int (*)(void *, int))ecdsaGenerateKey,
	.freeKey			= (void (*)(void *))ecdsaFreeKey,
	.validateBits		= NULL,
	
	/* Operations */
	.encrypt			= NULL,
	.decrypt			= NULL,
	.sign				= ecdsaSign,
	.verify				= ecdsaVerify,
	
	/* Utility */
	.maxSignatureLen	= ecdsaMaxSignatureLen,
	.keySizeBytes		= ecdsaKeySizeBytes,
	.checkKey			= NULL,
	.printKey			= (void (*)(const void *, int))ecdsaPrintKey,
};
