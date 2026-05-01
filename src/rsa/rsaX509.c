#include <stdlib.h>

#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hstring.h"
#include "../../includes/x509/asn1.h"
#include "../../includes/x509/pem.h"

#include "../../includes/rsa/rsa.h"

/**
 * @brief Parses an ASN.1 TLV (Tag-Length-Value) structure from DER encoded data.
 *
 * This function reads an ASN.1 TLV structure from the provided input buffer,
 * extracting the tag, length, and value while ensuring that the length is valid
 * and does not exceed the maximum allowed length.
 *
 * The function handles both short-form and long-form length encodings as defined
 * in ASN.1 DER. It also ensures that the total number of bytes read does not
 * exceed the specified maximum length to prevent buffer overflows.
 *
 * @param data Pointer to the input buffer containing the ASN.1 DER encoded data.
 * @param maxLen Maximum length of the input buffer to prevent overflows.
 * @param tlv Pointer to a t_asn1_tlv structure where the parsed tag, length, and
 *            value will be stored.
 * @param consumed Pointer to a size_t variable where the total number of bytes
 *                 read from the input buffer for this TLV will be stored.
 *
 * @return 1 on successful parsing, or 0 if parsing fails (e.g., invalid format,
 *         insufficient data).
 */
static uint8_t *bigIntToDerInteger(const t_bigInt *n, size_t *outLen)
{
	size_t len = (bigIntBitLength(n) + 7) / 8;
	if (len == 0) len = 1;

	uint8_t *data = malloc(len);
	if (!data) return (NULL);
	bigIntToBytes(n, data, len);

	uint8_t *der = asn1EncodeInteger(data, len, outLen);
	free(data);
	return (der);
}

/**
 * @brief Parses an ASN.1 INTEGER from DER encoded data and converts it to t_bigInt.
 *
 * This function reads an ASN.1 INTEGER structure from the provided input buffer,
 * extracts the integer value, and converts it into a t_bigInt structure. It
 * handles the big-endian byte order of ASN.1 INTEGERs and ensures that the
 * resulting t_bigInt is properly normalized (no leading zero words).
 *
 * @param data Pointer to the input buffer containing the ASN.1 DER encoded data.
 * @param maxLen Maximum length of the input buffer to prevent overflows.
 * @param consumed Pointer to a size_t variable where the total number of bytes
 *                 read from the input buffer for this INTEGER will be stored.
 *
 * @return Pointer to a newly allocated t_bigInt containing the parsed integer,
 *         or NULL if parsing fails (e.g., invalid format, insufficient data).
 */
static t_bigInt *derIntegerToBigInt(const uint8_t *data, size_t maxLen, size_t *consumed)
{
	uint8_t	*value;
	size_t	valueLen;
	size_t	localConsumed = 0;

	if (!asn1ParseInteger(data, maxLen, &value, &valueLen, &localConsumed))
		return (NULL);

	if (consumed)
		*consumed = localConsumed;

	/* Convert big-endian bytes to t_bigInt */
	size_t numWords = (valueLen + 7) / 8;
	if (numWords == 0) numWords = 1;
	
	t_bigInt *result = bigIntNew(numWords);
	if (!result) return (NULL);

	/* Copy bytes in big-endian order */
	for (size_t i = 0; i < valueLen; i++) {
		size_t bytePos = valueLen - 1 - i;
		size_t wordIdx = bytePos / 8;
		size_t byteInWord = bytePos % 8;
		result->words[wordIdx] |= ((uint64_t)value[i]) << (byteInWord * 8);
	}
	
	result->used = numWords;
	while (result->used > 0 && result->words[result->used - 1] == 0)
		result->used--;
	
	if (result->used == 0)
		result->used = 1;
		
	return (result);
}

/**
 * @brief Convert RSA public key to DER format (PKCS#1 RSAPublicKey structure).
 *
 * This function takes an RSA key structure and encodes the public key components
 * (modulus n and public exponent e) into DER format according to the PKCS#1
 * RSAPublicKey structure. The resulting DER-encoded byte array is allocated
 * dynamically and should be freed by the caller.
 *
 * @param key Pointer to the t_rsaKey structure containing the RSA key components.
 * @param outLen Pointer to a size_t variable where the length of the output DER
 *               data will be stored.
 *
 * @return Pointer to a newly allocated byte array containing the DER-encoded
 *         public key, or NULL if encoding fails (e.g., memory allocation failure).
 */
static uint8_t *rsaPublicKeyToDer(t_rsaKey *key, size_t *outLen)
{
	/* RSAPublicKey ::= SEQUENCE {
	 * 	modulus		INTEGER,
	 * 	publicExponent	INTEGER
	 * }
	 */
	uint8_t	*nDer, *eDer;
	size_t	nLen, eLen;
	uint8_t	*elements[2];
	size_t	elemLens[2];
	uint8_t	*sequence;
	size_t	seqLen;

	nDer = bigIntToDerInteger(key->n, &nLen);
	if (!nDer) return (NULL);
	eDer = bigIntToDerInteger(key->e, &eLen);
	if (!eDer) {
		free(nDer);
		return (NULL);
	}

	elements[0] = nDer;
	elements[1] = eDer;
	elemLens[0] = nLen;
	elemLens[1] = eLen;

	sequence = asn1EncodeSequence(elements, elemLens, 2, &seqLen);
	free(nDer);
	free(eDer);

	if (sequence)
		*outLen = seqLen;
	return (sequence);
}

/**
 * @brief Convert RSA private key to DER format (PKCS#1 RSAPrivateKey structure).
 *
 * This function takes an RSA key structure and encodes the private key components
 * into DER format according to the PKCS#1 RSAPrivateKey structure. The resulting DER-encoded byte array is allocated
 * dynamically and should be freed by the caller.
 *
 * @param key Pointer to the t_rsaKey structure containing the RSA key components.
 * @param outLen Pointer to a size_t variable where the length of the output DER
 *               data will be stored.
 *
 * @return Pointer to a newly allocated byte array containing the DER-encoded
 *         private key, or NULL if encoding fails (e.g., memory allocation failure).
 */
static uint8_t *rsaPrivateKeyToDer(t_rsaKey *key, size_t *outLen)
{
	/* RSAPrivateKey ::= SEQUENCE {
	 * 	version			INTEGER, (0 for two-prime RSA)
	 * 	modulus			INTEGER,
	 * 	publicExponent	INTEGER,
	 * 	privateExponent	INTEGER,
	 * 	prime1			INTEGER,
	 * 	prime2			INTEGER,
	 * 	exponent1		INTEGER,
	 * 	exponent2		INTEGER,
	 * 	coefficient		INTEGER
	 * }
	 */
	uint8_t	version[] = {0x00};  /* version 0 */
	uint8_t	*versionDer, *nDer, *eDer, *dDer, *pDer, *qDer, *dpDer, *dqDer, *qinvDer;
	size_t	vLen, nLen, eLen, dLen, pLen, qLen, dpLen, dqLen, qinvLen;
	uint8_t	*elements[9];
	size_t	elemLens[9];
	uint8_t	*sequence;
	size_t	seqLen;

	versionDer = asn1EncodeInteger(version, 1, &vLen);
	nDer = bigIntToDerInteger(key->n, &nLen);
	eDer = bigIntToDerInteger(key->e, &eLen);
	dDer = bigIntToDerInteger(key->d, &dLen);
	pDer = bigIntToDerInteger(key->p, &pLen);
	qDer = bigIntToDerInteger(key->q, &qLen);
	dpDer = bigIntToDerInteger(key->dp, &dpLen);
	dqDer = bigIntToDerInteger(key->dq, &dqLen);
	qinvDer = bigIntToDerInteger(key->qinv, &qinvLen);

	if (!versionDer || !nDer || !eDer || !dDer || !pDer || !qDer || !dpDer || !dqDer || !qinvDer) {
		free(versionDer); free(nDer); free(eDer); free(dDer);
		free(pDer); free(qDer); free(dpDer); free(dqDer); free(qinvDer);
		return (NULL);
	}

	elements[0] = versionDer;
	elements[1] = nDer;
	elements[2] = eDer;
	elements[3] = dDer;
	elements[4] = pDer;
	elements[5] = qDer;
	elements[6] = dpDer;
	elements[7] = dqDer;
	elements[8] = qinvDer;

	elemLens[0] = vLen;
	elemLens[1] = nLen;
	elemLens[2] = eLen;
	elemLens[3] = dLen;
	elemLens[4] = pLen;
	elemLens[5] = qLen;
	elemLens[6] = dpLen;
	elemLens[7] = dqLen;
	elemLens[8] = qinvLen;

	sequence = asn1EncodeSequence(elements, elemLens, 9, &seqLen);

	free(versionDer); free(nDer); free(eDer); free(dDer);
	free(pDer); free(qDer); free(dpDer); free(dqDer); free(qinvDer);

	if (sequence)
		*outLen = seqLen;
	return (sequence);
}

char *rsaKeyToPem(t_rsaKey *key, int isPrivate)
{
	uint8_t		*der;
	size_t		derLen;
	char		*pem;
	const char	*type;

	if (!key || !key->n || !key->e)
		return (NULL);

	if (isPrivate) {
		if (!key->d || !key->p || !key->q)
			return (NULL);
		der = rsaPrivateKeyToDer(key, &derLen);
		type = "RSA PRIVATE KEY";
	} else {
		der = rsaPublicKeyToDer(key, &derLen);
		type = "RSA PUBLIC KEY";
	}

	if (!der)
		return (NULL);

	pem = pemEncode(der, derLen, type);
	free(der);
	return (pem);
}



/**
 * @brief Parse DER to RSA public key.
 *
 * This function parses a DER-encoded RSA public key and populates the provided
 * t_rsaKey structure with the extracted components.
 *
 * @param der Pointer to the DER-encoded public key data.
 * @param derLen Length of the DER-encoded data.
 * @param key Pointer to the t_rsaKey structure to populate.
 *
 * @return 1 if parsing is successful, 0 otherwise.
 */
static int rsaPublicKeyFromDer(const uint8_t *der, size_t derLen, t_rsaKey *key)
{
	uint8_t		*content;
	size_t		contentLen;
	size_t		consumed;
	uint8_t		*nValue, *eValue;
	size_t		nLen, eLen;
	size_t		consumed2;
	t_bigInt	*n = NULL, *e = NULL;
	int			ret = 0;

	/* Parse SEQUENCE */
	if (!asn1ParseSequence(der, derLen, &content, &contentLen, &consumed))
		return (0);

	/* Parse modulus INTEGER */
	if (!asn1ParseInteger(content, contentLen, &nValue, &nLen, &consumed2))
		goto cleanup;
	
	/* Parse publicExponent INTEGER */
	if (!asn1ParseInteger(content + consumed2, contentLen - consumed2, &eValue, &eLen, &consumed2))
		goto cleanup;

	n = derIntegerToBigInt(nValue, nLen, &consumed);
	e = derIntegerToBigInt(eValue, eLen, &consumed);

	if (!n || !e)
		goto cleanup;

	key->n = n;
	key->e = e;
	key->bits = bigIntBitLength(n);
	ret = 1;

cleanup:
	if (!ret) {
		bigIntFree(n);
		bigIntFree(e);
	}
	return (ret);
}

/**
 * @brief Parse DER to RSA private key (PKCS#1).
 *
 * This function parses a DER-encoded RSA private key and populates the provided
 * t_rsaKey structure with the extracted components.
 *
 * @param der Pointer to the DER-encoded private key data.
 * @param derLen Length of the DER-encoded data.
 * @param key Pointer to the t_rsaKey structure to populate.
 *
 * @return 1 if parsing is successful, 0 otherwise.
 */
static int rsaPrivateKeyFromDer(const uint8_t *der, size_t derLen, t_rsaKey *key)
{
	uint8_t		*content;
	size_t		contentLen;
	size_t		consumed;
	uint8_t		*versionValue, *nValue, *eValue, *dValue, *pValue, *qValue;
	uint8_t		*dpValue, *dqValue, *qinvValue;
	size_t		vLen, nLen, eLen, dLen, pLen, qLen, dpLen, dqLen, qinvLen;
	size_t		offset = 0;
	t_bigInt	*n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL;
	t_bigInt	*dp = NULL, *dq = NULL, *qinv = NULL;
	int			ret = 0;

	if (!asn1ParseSequence(der, derLen, &content, &contentLen, &consumed))
		return (0);

	/* Parse version (should be 0) */
	if (!asn1ParseInteger(content + offset, contentLen - offset, &versionValue, &vLen, &consumed))
		goto cleanup;
	offset += consumed;
	
	if (vLen != 1 || versionValue[0] != 0x00) {
		/* Only version 0 (two-prime RSA) is supported */
		goto cleanup;
	}
	
	if (!asn1ParseInteger(content + offset, contentLen - offset, &nValue, &nLen, &consumed))
		goto cleanup;
	offset += consumed;
	
	if (!asn1ParseInteger(content + offset, contentLen - offset, &eValue, &eLen, &consumed))
		goto cleanup;
	offset += consumed;
	
	if (!asn1ParseInteger(content + offset, contentLen - offset, &dValue, &dLen, &consumed))
		goto cleanup;
	offset += consumed;
	
	if (!asn1ParseInteger(content + offset, contentLen - offset, &pValue, &pLen, &consumed))
		goto cleanup;
	offset += consumed;
	
	if (!asn1ParseInteger(content + offset, contentLen - offset, &qValue, &qLen, &consumed))
		goto cleanup;
	offset += consumed;
	
	if (!asn1ParseInteger(content + offset, contentLen - offset, &dpValue, &dpLen, &consumed))
		goto cleanup;
	offset += consumed;
	
	if (!asn1ParseInteger(content + offset, contentLen - offset, &dqValue, &dqLen, &consumed))
		goto cleanup;
	offset += consumed;
	
	if (!asn1ParseInteger(content + offset, contentLen - offset, &qinvValue, &qinvLen, &consumed))
		goto cleanup;

	n = derIntegerToBigInt(nValue, nLen, &consumed);
	e = derIntegerToBigInt(eValue, eLen, &consumed);
	d = derIntegerToBigInt(dValue, dLen, &consumed);
	p = derIntegerToBigInt(pValue, pLen, &consumed);
	q = derIntegerToBigInt(qValue, qLen, &consumed);
	dp = derIntegerToBigInt(dpValue, dpLen, &consumed);
	dq = derIntegerToBigInt(dqValue, dqLen, &consumed);
	qinv = derIntegerToBigInt(qinvValue, qinvLen, &consumed);

	if (!n || !e || !d || !p || !q || !dp || !dq || !qinv)
		goto cleanup;

	key->n = n;
	key->e = e;
	key->d = d;
	key->p = p;
	key->q = q;
	key->dp = dp;
	key->dq = dq;
	key->qinv = qinv;
	key->bits = bigIntBitLength(n);
	ret = 1;

cleanup:
	if (!ret) {
		bigIntFree(n); bigIntFree(e); bigIntFree(d);
		bigIntFree(p); bigIntFree(q); bigIntFree(dp);
		bigIntFree(dq); bigIntFree(qinv);
	}
	return (ret);
}

int rsaKeyFromPem(const char *pem, t_rsaKey *key, int isPrivate)
{
	t_pem_block block;
	int ret = 0;

	if (!pem || !key)
		return (0);

	/* Initialize key to zeros */
	ft_bzero(key, sizeof(t_rsaKey));

	if (!pemDecode(pem, &block))
		return (0);

	/* Check header matches expected type */
	if (isPrivate) {
		if (ft_strcmp(block.header, "RSA PRIVATE KEY") != 0 &&
				ft_strcmp(block.header, "PRIVATE KEY") != 0) {
			pemFreeBlock(&block);
			return (0);
		}
		ret = rsaPrivateKeyFromDer(block.der, block.derLen, key);
	} else {
		if (ft_strcmp(block.header, "RSA PUBLIC KEY") != 0 &&
				ft_strcmp(block.header, "PUBLIC KEY") != 0) {
			pemFreeBlock(&block);
			return (0);
		}
		ret = rsaPublicKeyFromDer(block.der, block.derLen, key);
	}

	pemFreeBlock(&block);
	return (ret);
}
