#include <stdlib.h>

#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hprintf.h" /* IWYU pragma: keep */
#include "../../hajlib/include/hstring.h"
#include "../../includes/x509/asn1.h"
#include "../../includes/x509/pem.h"

#include "../../includes/rsa/rsa.h"

static const uint8_t rsaOid[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};

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
 *			value will be stored.
 * @param consumed Pointer to a size_t variable where the total number of bytes
 *				 read from the input buffer for this TLV will be stored.
 *
 * @return 1 on successful parsing, or 0 if parsing fails (e.g., invalid format,
 *		 insufficient data).
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
 * @brief Convert RSA public key to DER format (PKCS#1 RSAPublicKey structure).
 *
 * This function takes an RSA key structure and encodes the public key components
 * (modulus n and public exponent e) into DER format according to the PKCS#1
 * RSAPublicKey structure. The resulting DER-encoded byte array is allocated
 * dynamically and should be freed by the caller.
 *
 * @param key Pointer to the t_rsaKey structure containing the RSA key components.
 * @param outLen Pointer to a size_t variable where the length of the output DER
 *			   data will be stored.
 *
 * @return Pointer to a newly allocated byte array containing the DER-encoded
 *		 public key, or NULL if encoding fails (e.g., memory allocation failure).
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
 *			   data will be stored.
 *
 * @return Pointer to a newly allocated byte array containing the DER-encoded
 *		 private key, or NULL if encoding fails (e.g., memory allocation failure).
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

/**
 * @brief Convert RSA private key to PKCS#8 DER format.
 *
 * This function takes an RSA key structure and encodes the private key components
 * into PKCS#8 DER format. The resulting DER-encoded byte array is allocated
 * dynamically and should be freed by the caller.
 *
 * @param key Pointer to the t_rsaKey structure containing the RSA key components.
 * @param outLen Pointer to a size_t variable where the length of the output DER
 *			   data will be stored.
 *
 * @return Pointer to a newly allocated byte array containing the PKCS#8 DER-encoded
 *		 private key, or NULL if encoding fails (e.g., memory allocation failure).
 */
static uint8_t *rsaPrivateKeyToPkcs8Der(t_rsaKey *key, size_t *outLen)
{
	uint8_t	*rsaPrivDer, *octetDer, *oidDer, *nullDer, *algoSeq, *pkcs8Der;
	size_t	rsaPrivLen, octetLen, oidLen, nullLen, algoLen;
	uint8_t	*elements[3];
	size_t	elemLens[3];
	uint8_t	versionDer[] = {0x02, 0x01, 0x00}; /* INTEGER 0 */

	/* 1. PKCS#1 RSAPrivateKey DER */
	rsaPrivDer = rsaPrivateKeyToDer(key, &rsaPrivLen);
	if (!rsaPrivDer) return (NULL);

	/* 2. Wrap in OCTET STRING */
	octetDer = asn1EncodeOctetString(rsaPrivDer, rsaPrivLen, &octetLen);
	free(rsaPrivDer);
	if (!octetDer) return (NULL);

	/* 3. AlgorithmIdentifier (rsaEncryption OID + NULL) */
	oidDer = asn1EncodeOid(rsaOid, RSA_OID_LEN, &oidLen);
	nullDer = asn1EncodeNull(&nullLen);
	if (!oidDer || !nullDer) {
		free(octetDer); free(oidDer); free(nullDer);
		return (NULL);
	}
	algoSeq = asn1EncodeSequence((uint8_t*[]){oidDer, nullDer}, (size_t[]){oidLen, nullLen}, 2, &algoLen);
	free(oidDer); free(nullDer);
	if (!algoSeq) { free(octetDer); return (NULL); }

	/* 4. PrivateKeyInfo SEQUENCE */
	elements[0] = versionDer;
	elements[1] = algoSeq;
	elements[2] = octetDer;
	elemLens[0] = sizeof(versionDer);
	elemLens[1] = algoLen;
	elemLens[2] = octetLen;
	pkcs8Der = asn1EncodeSequence(elements, elemLens, 3, outLen);
	free(algoSeq);
	free(octetDer);
	return (pkcs8Der);
}

/**
 * @brief Convert RSA public key to PKCS#8 DER format.
 *
 * This function takes an RSA key structure and encodes the public key components
 * into PKCS#8 DER format. The resulting DER-encoded byte array is allocated
 * dynamically and should be freed by the caller.
 *
 * @param key Pointer to the t_rsaKey structure containing the RSA key components.
 * @param outLen Pointer to a size_t variable where the length of the output DER
 *			   data will be stored.
 *
 * @return Pointer to a newly allocated byte array containing the PKCS#8 DER-encoded
 *		 public key, or NULL if encoding fails (e.g., memory allocation failure).
 */
static uint8_t *rsaPublicKeyToPkcs8Der(t_rsaKey *key, size_t *outLen)
{
	uint8_t	*rsaPubDer, *bitStr, *oidDer, *nullDer, *algoSeq, *spkiDer;
	size_t	rsaPubLen, bitLen, oidLen, nullLen, algoLen;
	uint8_t	*elements[2];
	size_t	elemLens[2];

	/* 1. PKCS#1 RSAPublicKey DER */
	rsaPubDer = rsaPublicKeyToDer(key, &rsaPubLen);
	if (!rsaPubDer) return (NULL);

	/* 2. Wrap in BIT STRING (with 0 unused bits) */
	bitStr = asn1EncodeBitString(rsaPubDer, rsaPubLen, &bitLen);
	free(rsaPubDer);
	if (!bitStr) return (NULL);

	/* 3. AlgorithmIdentifier (same as above) */
	oidDer = asn1EncodeOid(rsaOid, RSA_OID_LEN, &oidLen);
	nullDer = asn1EncodeNull(&nullLen);
	if (!oidDer || !nullDer) {
		free(bitStr); free(oidDer); free(nullDer);
		return (NULL);
	}
	algoSeq = asn1EncodeSequence((uint8_t*[]){oidDer, nullDer}, (size_t[]){oidLen, nullLen}, 2, &algoLen);
	free(oidDer); free(nullDer);
	if (!algoSeq) { free(bitStr); return (NULL); }

	/* 4. SubjectPublicKeyInfo SEQUENCE */
	elements[0] = algoSeq;
	elements[1] = bitStr;
	elemLens[0] = algoLen;
	elemLens[1] = bitLen;
	spkiDer = asn1EncodeSequence(elements, elemLens, 2, outLen);
	free(algoSeq);
	free(bitStr);
	return (spkiDer);
}

char *rsaKeyToPem(t_rsaKey			*key,
				  int				isPrivate,
				  int				useTraditional,
				  const char		*password,
				  const t_cipher	*cipher)
{
	uint8_t		*der = NULL;
	size_t		derLen;
	char		*pem = NULL;
	const char	*type;

	if (!key || !key->n || !key->e)
		return (NULL);

	/* Public key: ignore password and encryption */
	if (!isPrivate) {
		if (useTraditional) {
			der = rsaPublicKeyToDer(key, &derLen);
			type = "RSA PUBLIC KEY";
		} else {
			der = rsaPublicKeyToPkcs8Der(key, &derLen);
			type = "PUBLIC KEY";
		}
		if (!der) return (NULL);
		pem = pemEncode(der, derLen, type);
		free(der);
		return (pem);
	}

	/* Private key */
	if (!key->d || !key->p || !key->q)
		return (NULL);

	/* Determine which DER to encode (traditional PKCS#1 or PKCS#8) */
	if (useTraditional) {
		der = rsaPrivateKeyToDer(key, &derLen);
		type = "RSA PRIVATE KEY";
	} else {
		der = rsaPrivateKeyToPkcs8Der(key, &derLen);
		type = "PRIVATE KEY";
	}
	if (!der) return (NULL);

	/* If no password, output plain PEM */
	if (!password) {
		pem = pemEncode(der, derLen, type);
		free(der);
		return (pem);
	}

	/* Encrypted private key */
	const t_cipher *encCipher = cipher;
	if (!encCipher) {
		/* Default cipher: AES-256-CBC (must be available in your cipher list) */
		extern const t_cipher g_aes256CbcCipher;
		encCipher = &g_aes256CbcCipher;
	}

	if (useTraditional) {
		/* Legacy PKCS#1 encryption (non‑standard, but provided by pkcs1EncryptPem) */
		pem = pkcs1EncryptPem(type, der, derLen, encCipher, password);
	} else {
		/* Modern PKCS#8 encryption */
		pem = pkcs8EncryptPem(der, derLen, encCipher, password, NULL);
	}
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
		return (HAJCRYPT_DPRINT("rsaPublicKeyFromDer: failed to parse SEQUENCE\n"), 0);

	/* Parse modulus INTEGER */
	if (!asn1ParseInteger(content, contentLen, &nValue, &nLen, &consumed2))
	{
		HAJCRYPT_DPRINT("rsaPublicKeyFromDer: failed to parse modulus\n");
		goto cleanup;
	}
	
	/* Parse publicExponent INTEGER */
	if (!asn1ParseInteger(content + consumed2, contentLen - consumed2, &eValue, &eLen, &consumed2))
	{
		HAJCRYPT_DPRINT("rsaPublicKeyFromDer: failed to parse public exponent\n");
		goto cleanup;
	}

	n = bigIntFromBytes(nValue, nLen);
	e = bigIntFromBytes(eValue, eLen);

	if (!n || !e)
	{
		HAJCRYPT_DPRINT("rsaPublicKeyFromDer: failed to create big integers\n");
		goto cleanup;
	}

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
	{
		HAJCRYPT_DPRINT("rsaPrivateKeyFromDer: failed to parse SEQUENCE\n");
		return (0);
	}

	/* Parse version (should be 0) */
	if (!asn1ParseInteger(content + offset, contentLen - offset, &versionValue, &vLen, &consumed))
		{HAJCRYPT_DPRINT("rsaPrivateKeyFromDer: failed to parse version\n"); goto cleanup;}
	offset += consumed;
	
	if (vLen != 1 || versionValue[0] != 0x00) {
		/* Only version 0 (two-prime RSA) is supported */
		HAJCRYPT_DPRINT("rsaPrivateKeyFromDer: unsupported version\n");
		goto cleanup;
	}
	
	if (!asn1ParseInteger(content + offset, contentLen - offset, &nValue, &nLen, &consumed))
		{HAJCRYPT_DPRINT("rsaPrivateKeyFromDer: failed to parse modulus\n"); goto cleanup;}
	offset += consumed;
	
	if (!asn1ParseInteger(content + offset, contentLen - offset, &eValue, &eLen, &consumed))
		{HAJCRYPT_DPRINT("rsaPrivateKeyFromDer: failed to parse public exponent\n"); goto cleanup;}
	offset += consumed;
	
	if (!asn1ParseInteger(content + offset, contentLen - offset, &dValue, &dLen, &consumed))
		{HAJCRYPT_DPRINT("rsaPrivateKeyFromDer: failed to parse private exponent\n"); goto cleanup;}
	offset += consumed;
	
	if (!asn1ParseInteger(content + offset, contentLen - offset, &pValue, &pLen, &consumed))
		{HAJCRYPT_DPRINT("rsaPrivateKeyFromDer: failed to parse prime1\n"); goto cleanup;}
	offset += consumed;
	
	if (!asn1ParseInteger(content + offset, contentLen - offset, &qValue, &qLen, &consumed))
		{HAJCRYPT_DPRINT("rsaPrivateKeyFromDer: failed to parse prime2\n"); goto cleanup;}
	offset += consumed;
	
	if (!asn1ParseInteger(content + offset, contentLen - offset, &dpValue, &dpLen, &consumed))
		{HAJCRYPT_DPRINT("rsaPrivateKeyFromDer: failed to parse dp\n"); goto cleanup;}
	offset += consumed;
	
	if (!asn1ParseInteger(content + offset, contentLen - offset, &dqValue, &dqLen, &consumed))
		{HAJCRYPT_DPRINT("rsaPrivateKeyFromDer: failed to parse dq\n"); goto cleanup;}
	offset += consumed;
	
	if (!asn1ParseInteger(content + offset, contentLen - offset, &qinvValue, &qinvLen, &consumed))
		{HAJCRYPT_DPRINT("rsaPrivateKeyFromDer: failed to parse qinv\n"); goto cleanup;}

	n = bigIntFromBytes(nValue, nLen);
	e = bigIntFromBytes(eValue, eLen);
	d = bigIntFromBytes(dValue, dLen);
	p = bigIntFromBytes(pValue, pLen);
	q = bigIntFromBytes(qValue, qLen);
	dp = bigIntFromBytes(dpValue, dpLen);
	dq = bigIntFromBytes(dqValue, dqLen);
	qinv = bigIntFromBytes(qinvValue, qinvLen);

	if (!n || !e || !d || !p || !q || !dp || !dq || !qinv)
		{HAJCRYPT_DPRINT("rsaPrivateKeyFromDer: failed to create big integers\n"); goto cleanup;}

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

/**
 * @brief Parse PKCS#8 SubjectPublicKeyInfo DER to RSA public key.
 *
 * @param der Pointer to PKCS#8 SubjectPublicKeyInfo DER data.
 * @param derLen Length of the DER data.
 * @param key Pointer to t_rsaKey structure to populate.
 * @return 1 on success, 0 on failure.
 */
static int rsaPublicKeyFromPkcs8Der(const uint8_t *der, size_t derLen, t_rsaKey *key)
{
	uint8_t	*content;
	size_t	contentLen;
	size_t	consumed;
	uint8_t	*bitString;
	size_t	bitStringLen;

	/* Parse SEQUENCE (SubjectPublicKeyInfo) */
	if (!asn1ParseSequence(der, derLen, &content, &contentLen, &consumed))
	{
		HAJCRYPT_DPRINT("rsaPublicKeyFromPkcs8Der: failed to parse SEQUENCE (SubjectPublicKeyInfo)\n");
		return (0);
	}

	/* Skip algorithmIdentifier (we only care about the BIT STRING) */
	uint8_t	*algoSeq;
	size_t	algoSeqLen;
	size_t	algoConsumed;
	if (!asn1ParseSequence(content, contentLen, &algoSeq, &algoSeqLen, &algoConsumed))
	{
		HAJCRYPT_DPRINT("rsaPublicKeyFromPkcs8Der: failed to parse algorithmIdentifier\n");
		return (0);
	}

	/* Parse OID inside algorithmIdentifier */
	uint8_t	*algoOid;
	size_t	oidLen;
	if (!asn1ParseOid(algoSeq, algoSeqLen, &algoOid, &oidLen, NULL))
	{
		HAJCRYPT_DPRINT("rsaPublicKeyFromPkcs8Der: failed to parse OID\n");
		return (0);
	}

	/* Check if OID is RSA encryption OID */
	if (oidLen != RSA_OID_LEN || ft_memcmp(algoOid, rsaOid, RSA_OID_LEN) != 0)
	{
		HAJCRYPT_DPRINT("rsaPublicKeyFromPkcs8Der: unsupported algorithm OID\n");
		return (0);
	}

	/* Skip algorithmIdentifier and parse BIT STRING (subjectPublicKey) */
	content += algoConsumed;
	contentLen -= algoConsumed;
	if (!asn1ParseBitString(content, contentLen, &bitString, &bitStringLen, &consumed))
	{
		HAJCRYPT_DPRINT("rsaPublicKeyFromPkcs8Der: failed to parse BIT STRING\n");
		return (0);
	}

	/* Now parse the inner PKCS#1 RSAPublicKey */
	if (!rsaPublicKeyFromDer(bitString, bitStringLen, key))
	{
		HAJCRYPT_DPRINT("rsaPublicKeyFromPkcs8Der: failed to parse inner PKCS#1 key\n");
		return (0);
	}

	return (1);
}

/**
 * @brief Parse PKCS#8 PrivateKeyInfo DER to RSA private key.
 *
 * @param der Pointer to PKCS#8 PrivateKeyInfo DER data.
 * @param derLen Length of the DER data.
 * @param key Pointer to t_rsaKey structure to populate.
 * @return 1 on success, 0 on failure.
 */
static int rsaPrivateKeyFromPkcs8Der(const uint8_t *der, size_t derLen, t_rsaKey *key)
{
	uint8_t	*content;
	size_t	contentLen, consumed, offset = 0;
	uint8_t	*versionValue;
	size_t	vLen;
	uint8_t	*algoOid;
	size_t	oidLen;
	int		ret = 0;

	/* Parse outer PrivateKeyInfo SEQUENCE */
	if (!asn1ParseSequence(der, derLen, &content, &contentLen, &consumed))
		return (0);

	/* Parse version (should be 0) */
	if (!asn1ParseInteger(content + offset, contentLen - offset, &versionValue, &vLen, &consumed))
		return (0);
	if (vLen != 1 || versionValue[0] != 0x00)
		return (0);
	offset += consumed;

	/* Parse AlgorithmIdentifier */
	uint8_t	*algoSeq;
	size_t	algoSeqLen;
	if (!asn1ParseSequence(content + offset, contentLen - offset, &algoSeq, &algoSeqLen, &consumed))
		return (0);
	offset += consumed;

	/* Parse OID inside AlgorithmIdentifier */
	if (!asn1ParseOid(algoSeq, algoSeqLen, &algoOid, &oidLen, NULL))
		return (0);
	if (oidLen != RSA_OID_LEN || ft_memcmp(algoOid, rsaOid, RSA_OID_LEN) != 0)
		return (0);

	/* Parse OCTET STRING containing the PKCS#1 key */
	uint8_t	*octetValue;
	size_t	octetLen;
	if (!asn1ParseOctetString(content + offset, contentLen - offset, &octetValue, &octetLen, &consumed))
		return (0);
	/* Now parse the inner PKCS#1 DER */
	ret = rsaPrivateKeyFromDer(octetValue, octetLen, key);
	return (ret);
}

int rsaKeyFromPem(const char *pem, t_rsaKey *key, int isPrivate, const char *password)
{
	t_pemBlock	block;
	uint8_t		*decryptedDer = NULL;
	size_t		decryptedLen = 0;
	int			ret = 0;

	if (!pem || !key)
		return (0);
	ft_bzero(key, sizeof(t_rsaKey));
	
	/* --- Public key (never encrypted) --- */
	if (!isPrivate) {
		if (ft_strstr(pem, "-----BEGIN RSA PUBLIC KEY-----")) {
			if (!pemDecode(pem, &block))
			return (0);
		ret = rsaPublicKeyFromDer(block.der, block.derLen, key);
		pemFreeBlock(&block);
			return (ret);
		}
		if (ft_strstr(pem, "-----BEGIN PUBLIC KEY-----")) {
			if (!pemDecode(pem, &block))
				return (0);
			ret = rsaPublicKeyFromPkcs8Der(block.der, block.derLen, key);
			pemFreeBlock(&block);
			return (ret);
		}
		HAJCRYPT_DPRINT("Unsupported public key PEM header\n");
		return (0);
	}

	/* --- Private key --- */

	/* 1. Encrypted PKCS#8 (ENCRYPTED PRIVATE KEY) */
	if (ft_strstr(pem, "-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
		if (!password)
			return (-2); /* Indicate that password is required for encrypted key */
		decryptedDer = pkcs8DecryptedDer(pem, password, &decryptedLen);
		if (!decryptedDer) {
			HAJCRYPT_DPRINT("PKCS#8 decryption failed\n");
			return (0);
		}
		ret = rsaPrivateKeyFromPkcs8Der(decryptedDer, decryptedLen, key);
		free(decryptedDer);
		return (ret);
	}

	/* 2. Unencrypted PKCS#8 (PRIVATE KEY) */
	if (ft_strstr(pem, "-----BEGIN PRIVATE KEY-----")) {
		if (!pemDecode(pem, &block))
			return (0);
		ret = rsaPrivateKeyFromPkcs8Der(block.der, block.derLen, key);
		pemFreeBlock(&block);
		return (ret);
	}

	/* 3. Traditional PKCS#1 (RSA PRIVATE KEY) – may be encrypted with legacy format */
	if (ft_strstr(pem, "-----BEGIN RSA PRIVATE KEY-----")) {
		/* Detect encryption by presence of Proc-Type header */
		if (ft_strstr(pem, "Proc-Type: 4,ENCRYPTED") != NULL) {
			/* Legacy encrypted: use pkcs1DecryptedDer */
			if (!password)
				return (-2); /* Indicate that password is required for encrypted key */
			decryptedDer = pkcs1DecryptedDer(pem, password, &decryptedLen);
			if (!decryptedDer) {
				HAJCRYPT_DPRINT("Legacy decryption failed\n");
				return (0);
			}
			ret = rsaPrivateKeyFromDer(decryptedDer, decryptedLen, key);
			free(decryptedDer);
			return (ret);
		} else {
			/* Plain traditional PKCS#1 */
			if (!pemDecode(pem, &block))
				return (0);
			ret = rsaPrivateKeyFromDer(block.der, block.derLen, key);
			pemFreeBlock(&block);
			return (ret);
		}
	}

	/* No recognized header */
	HAJCRYPT_DPRINT("Unsupported PEM header for private key\n");
	return (0);
}
