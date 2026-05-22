#include <stdlib.h>

#include "../../../hajlib/include/hprintf.h" /* IWYU pragma: keep */
#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/asymmetric/pkey.h"
#include "../../../includes/x509/asn1.h"

#include "../../../includes/asymmetric/rsa.h"

static uint8_t	*rsaPubEncode(const void *key, size_t *outLen)
{
	const t_rsaKey	*k = (const t_rsaKey *)key;
	size_t			nLen, eLen;
	uint8_t			*nDer, *eDer, *seq;
	size_t			seqLen;

	nDer = bigIntToDerInteger(k->n, &nLen);
	if (!nDer) return (NULL);
	eDer = bigIntToDerInteger(k->e, &eLen);
	if (!eDer) { free(nDer); return (NULL); }
	{
		uint8_t	*elements[2] = {nDer, eDer};
		size_t	lens[2] = {nLen, eLen};
		seq = asn1EncodeSequence(elements, lens, 2, &seqLen);
	}
	free(nDer);
	free(eDer);
	if (seq) *outLen = seqLen;
	return (seq);
}

static uint8_t	*rsaPrivEncode(const void *key, size_t *outLen)
{
	const t_rsaKey	*k = (const t_rsaKey *)key;
	uint8_t			version[1] = {0x00};
	size_t			vLen;
	uint8_t			*vDer, *ders[8], *seq;
	size_t			lens[8];
	const t_bigInt	*ints[8] = {k->n, k->e, k->d, k->p, k->q, k->dp, k->dq, k->qinv};
	int				i;

	vDer = asn1EncodeInteger(version, 1, &vLen);
	if (!vDer) return (NULL);

	for (i = 0; i < 8; i++) {
		ders[i] = bigIntToDerInteger(ints[i], &lens[i]);
		if (!ders[i]) {
			while (i--) free(ders[i]);
			free(vDer);
			return (NULL);
		}
	}
	{
		uint8_t	*elements[9] = {vDer, ders[0], ders[1], ders[2], ders[3],
								ders[4], ders[5], ders[6], ders[7]};
		size_t	elemLen[9] = {vLen, lens[0], lens[1], lens[2], lens[3],
							  lens[4], lens[5], lens[6], lens[7]};
		size_t	seqLen;
		seq = asn1EncodeSequence(elements, elemLen, 9, &seqLen);
		*outLen = seqLen;
	}
	free(vDer);
	for (i = 0; i < 8; i++) free(ders[i]);
	return (seq);
}

static int	rsaPubDecode(const uint8_t *der, size_t len, void *key)
{
	t_rsaKey	*k = (t_rsaKey *)key;
	uint8_t		*content, *nVal, *eVal;
	size_t		contentLen, consumed, nLen, eLen;

	if (!asn1ParseSequence(der, len, &content, &contentLen, &consumed))
		return (0);
	if (!asn1ParseInteger(content, contentLen, &nVal, &nLen, &consumed))
		return (0);
	content += consumed; contentLen -= consumed;
	if (!asn1ParseInteger(content, contentLen, &eVal, &eLen, &consumed))
		return (0);

	k->n = bigIntFromBytes(nVal, nLen);
	k->e = bigIntFromBytes(eVal, eLen);
	if (!k->n || !k->e) {
		bigIntFree(k->n); bigIntFree(k->e);
		return (0);
	}
	k->bits = bigIntBitLength(k->n);
	return (1);
}

static int	rsaPrivDecode(const uint8_t *der, size_t len, void *key)
{
	t_rsaKey	*k = (t_rsaKey *)key;
	uint8_t		*content, *vals[9];
	size_t		contentLen, consumed, lens[9];
	const char	*names[] = {"version", "n", "e", "d", "p", "q", "dp", "dq", "qinv"};
	t_bigInt	**ptrs[9] = {NULL, &k->n, &k->e, &k->d, &k->p, &k->q, &k->dp, &k->dq, &k->qinv};
	int ret = 0;

	if (!asn1ParseSequence(der, len, &content, &contentLen, &consumed))
		return (0);

	for (int i = 0; i < 9; i++) {
		if (!asn1ParseInteger(content, contentLen, &vals[i], &lens[i], &consumed)) {
			HAJCRYPT_DPRINT("rsaPrivDecode: failed to parse %s\n", names[i]);
			goto cleanup;
		}
		content += consumed; contentLen -= consumed;
		if (i == 0) {
			if (lens[0] != 1 || vals[0][0] != 0x00)
				goto cleanup;
		} else {
			*ptrs[i] = bigIntFromBytes(vals[i], lens[i]);
			if (!*ptrs[i]) goto cleanup;
		}
	}
	k->bits = bigIntBitLength(k->n);
	ret = 1;

cleanup:
	if (!ret)
		for (int i = 1; i < 9; i++) { bigIntFree(*ptrs[i]); *ptrs[i] = NULL; }
	return (ret);
}


static int rsaValidateBits(int bits)
{
	if (bits < RSA_MIN_BITS || bits > RSA_MAX_BITS)
		return (HAJCRYPT_DPRINT("Invalid RSA key size: %d bits. Supported range: %d - %d bits.\n", bits, RSA_MIN_BITS, RSA_MAX_BITS), (0));
	return (1);
}

static size_t rsaKeySizeBytes(const void *key)
{
	const t_rsaKey	*k;

	k = (const t_rsaKey *)key;
	return ((k->bits + 7) / 8);
}

/* =========================================================================
 *              Wrappers for generic interface
 * ========================================================================= */

static int	rsaGenerateWrapper(void *key, int bits)
{
	if (bits <= 0)
		return (0);
	return (rsaGenerateKey((t_rsaKey *)key, (size_t)bits, 65537));
}

static int	rsaCheckKeyWrapper(const void *key)
{
	return (rsaCheckKey((t_rsaKey *)key, 64));
}

const t_pkeyDef	g_rsaPkeyDef = {
	/* Identity */
	.type			= PKEY_TYPE_RSA,
	.oid			= OID_DEF("RSA", RSA_OID),
	.name			= "rsa",
	.keyLen			= sizeof(t_rsaKey),
	.caps			= PKEY_CAP_ENCRYPT | PKEY_CAP_SIGN | PKEY_CAP_KEY_ENCIPHER,
	.defaultBits	= 2048,

	/* PEM serialization */
	.tradPubLabel		= "RSA PUBLIC KEY",
	.tradPrivLabel		= "RSA PRIVATE KEY",
	.encodeAlgoParams	= NULL,
	.encodePubKey		= rsaPubEncode,
	.encodePrivKey		= rsaPrivEncode,
	.decodePubKey		= rsaPubDecode,
	.decodePrivKey		= rsaPrivDecode,

	/* Key generation */
	.generate		= rsaGenerateWrapper,
	.freeKey		= (void (*)(void *))rsaFreeKey,
	.validateBits	= rsaValidateBits,

	/* Cryptographic operations */
	.encrypt		= rsaEncrypt,
	.decrypt		= rsaDecrypt,
	.sign			= rsaSign,
	.verify			= rsaVerify,

	/* Utility */
	.maxSignatureLen	= rsaKeySizeBytes,
	.keySizeBytes		= rsaKeySizeBytes,
	.checkKey			= rsaCheckKeyWrapper,
	.printKey			= (void (*)(const void *, int))rsaPrintKey
};

char *rsaKeyToPem(t_rsaKey *key, int isPrivate, int useTraditional, const char *password, const t_cipher *cipher)
{
	t_pkey	pkey;

	pkey.def = &g_rsaPkeyDef;
	pkey.key = key;
	return (pkeyToPem(&pkey, isPrivate, useTraditional, password, cipher));
}

int rsaKeyFromPem(const char *pem, t_rsaKey *key, int isPrivate, const char *password)
{
	t_pkey	pkey;
	int		ret;

	if (!pem || !key)
		return (0);
	ft_bzero(key, sizeof(t_rsaKey));
	pkey.def = &g_rsaPkeyDef;
	pkey.key = NULL;
	ret = pkeyFromPem(pem, &pkey, isPrivate, password);
	if (ret == 1)
	{
		ft_memcpy(key, pkey.key, sizeof(t_rsaKey));
		free(pkey.key);
		return (1);
	}
	return (ret);
}
