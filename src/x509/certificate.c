#include <stdlib.h>

#include "../../hajlib/include/hprintf.h" /* IWYU pragma: keep */
#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hstring.h"
#include "../../includes/asymmetric/ecdsa.h"
#include "../../includes/asymmetric/rsa.h"
#include "../../includes/hash/sha/sha256.h"
#include "../../includes/hash/sha/sha384.h"
#include "../../includes/hash/hmac.h"
#include "../../includes/x509/asn1.h"

#include "../../includes/x509/cert.h"

static const t_algoId g_oidCommonName				= OID_DEF("CN", OID_COMMON_NAME);
static const t_algoId g_oidCountryName				= OID_DEF("C", OID_COUNTRY_NAME);
static const t_algoId g_oidOrganizationName			= OID_DEF("O", OID_ORG_NAME);
static const t_algoId g_oidOrganizationalUnitName	= OID_DEF("OU", OID_ORG_UNIT_NAME);
static const t_algoId g_oidLocalityName				= OID_DEF("L", OID_LOCALITY_NAME);
static const t_algoId g_oidStateName				= OID_DEF("ST", OID_STATE_NAME);
static const t_algoId g_oidEmailAddress				= OID_DEF("emailAddress", OID_EMAIL_ADDRESS);
static const t_algoId g_sha256WithRSAEncryption		= OID_DEF("sha256WithRSAEncryption", OID_SHA256_WITH_RSA_ENCRYPTION);

t_x509Cert *x509CertParse(const uint8_t *der, size_t derLen)
{
	t_x509Cert *cert = ft_calloc(1, sizeof(t_x509Cert));
	if (!cert)
		return (NULL);

	/* Store raw DER data */
	cert->der = malloc(derLen);
	if (!cert->der)
		goto error;
	ft_memcpy(cert->der, der, derLen);
	cert->derLen = derLen;

	/* 1. Unwrap the outermost Certificate SEQUENCE */
	uint8_t	*certPayload;
	size_t	certPayloadLen;
	size_t	totalConsumed;

	if (!asn1ParseSequence(der, derLen, &certPayload, &certPayloadLen, &totalConsumed))
		{ HAJCRYPT_DPRINT("x509CertParse: failed to parse outermost certificate SEQUENCE\n"); goto error; }

	uint8_t	*ptr = certPayload;
	size_t	remain = certPayloadLen;

	/* 2. Extract TBSCertificate (the signed portion) */
	uint8_t	*tbsInner;
	size_t	tbsInnerLen;
	size_t	tbsConsumed;
	if (!asn1ParseSequence(ptr, remain, &tbsInner, &tbsInnerLen, &tbsConsumed))
		{ HAJCRYPT_DPRINT("x509CertParse: failed to parse TBSCertificate SEQUENCE\n"); goto error; }
	
	ptr += tbsConsumed;
	remain -= tbsConsumed;

	/* 3. Extract signature algorithm identifier */
	uint8_t	*sigAlgo;
	size_t	sigAlgoLen;
	size_t	algoConsumed;
	if (!asn1ParseAny(ptr, remain, &sigAlgo, &sigAlgoLen, &algoConsumed))
		{ HAJCRYPT_DPRINT("x509CertParse: failed to parse signature algorithm\n"); goto error; }
	
	ptr += algoConsumed;
	remain -= algoConsumed;

	/* 4. Extract signature value (BIT STRING) */
	uint8_t	*signature;
	size_t	sigLen;
	size_t	sigConsumed;
	if (!asn1ParseBitString(ptr, remain, &signature, &sigLen, &sigConsumed))
		{ HAJCRYPT_DPRINT("x509CertParse: failed to parse signature BIT STRING\n"); goto error; }

	/* Set up the 'rest' pointer to parse the inside of the TBSCertificate */
	uint8_t	*rest = tbsInner;
	size_t	restLen = tbsInnerLen;

	/* Optional version field - explicit tag [0] */
	if (restLen > 0 && rest[0] == 0xa0) {
		size_t	tagConsumed;
		uint8_t	*verTag;
		size_t	verTagLen;
		if (!asn1ParseAny(rest, restLen, &verTag, &verTagLen, &tagConsumed))
			{ HAJCRYPT_DPRINT("x509CertParse: failed to parse version field\n"); goto error; }
		
		uint8_t	*verVal;
		size_t	verLen;
		size_t	dummy;
		if (!asn1ParseInteger(verTag, verTagLen, &verVal, &verLen, &dummy))
			{ HAJCRYPT_DPRINT("x509CertParse: failed to parse version integer\n"); goto error; }
		
		/* Advance by the whole explicit tag, not just the inner integer */
		rest += tagConsumed;
		restLen -= tagConsumed;
	}

	/* In x509CertParse, replace the serial-number block with: */
	{
		uint8_t	*rawSerial;
		size_t	rawSerialLen;
		size_t	serConsumed;
		if (!asn1ParseInteger(rest, restLen, &rawSerial, &rawSerialLen, &serConsumed))
			{ HAJCRYPT_DPRINT("x509CertParse: failed to parse serial number\n"); goto error; }

		cert->serial = malloc(rawSerialLen);
		if (!cert->serial) goto error;
		ft_memcpy(cert->serial, rawSerial, rawSerialLen);
		cert->serialLen = rawSerialLen;

		rest	+= serConsumed;
		restLen -= serConsumed;
	}

	/* Skip signature algorithm field in TBSCertificate */
	uint8_t	*tbsSigAlgo;
	size_t	tbsSigAlgoLen;
	if (!asn1ParseAny(rest, restLen, &tbsSigAlgo, &tbsSigAlgoLen, &algoConsumed))
		{ HAJCRYPT_DPRINT("x509CertParse: failed to parse signature algorithm in TBS\n"); goto error; }
	rest += algoConsumed;
	restLen -= algoConsumed;

	/* Extract issuer Distinguished Name - store the whole SEQUENCE */
	uint8_t	*issuerContent;
	size_t	issuerContentLen;
	size_t	issuerTotalConsumed;
	if (!asn1ParseSequence(rest, restLen, &issuerContent, &issuerContentLen, &issuerTotalConsumed))
		{ HAJCRYPT_DPRINT("x509CertParse: failed to parse issuer Distinguished Name\n"); goto error; }
	
	cert->issuer = malloc(issuerTotalConsumed);
	if (!cert->issuer)
		{ HAJCRYPT_DPRINT("x509CertParse: failed to allocate memory for issuer\n"); goto error; }
	ft_memcpy(cert->issuer, rest, issuerTotalConsumed);
	cert->issuerLen = issuerTotalConsumed;
	
	rest += issuerTotalConsumed;
	restLen -= issuerTotalConsumed;

	/* Extract validity period SEQUENCE */
	uint8_t	*validity;
	size_t	validityLen;
	size_t	validityConsumed;
	if (!asn1ParseSequence(rest, restLen, &validity, &validityLen, &validityConsumed))
		{ HAJCRYPT_DPRINT("x509CertParse: failed to parse validity period\n"); goto error; }
	rest += validityConsumed;
	restLen -= validityConsumed;

	/* Parse notBefore and notAfter timestamps */
	{
		uint8_t	*vt = validity;
		size_t	vtLen = validityLen;
		size_t	nbConsumed;
		if (!asn1DecodeTime(vt, vtLen, &cert->notBefore, &nbConsumed))
			{ HAJCRYPT_DPRINT("x509CertParse: failed to parse notBefore timestamp\n"); goto error; }
		vt += nbConsumed;
		vtLen -= nbConsumed;
		if (!asn1DecodeTime(vt, vtLen, &cert->notAfter, &nbConsumed))
			{ HAJCRYPT_DPRINT("x509CertParse: failed to parse notAfter timestamp\n"); goto error; }
	}

	/* Extract subject Distinguished Name - store the whole SEQUENCE */
	uint8_t	*subjectContent;
	size_t	subjectContentLen;
	size_t	subjectTotalConsumed;
	if (!asn1ParseSequence(rest, restLen, &subjectContent, &subjectContentLen, &subjectTotalConsumed))
		{ HAJCRYPT_DPRINT("x509CertParse: failed to parse subject Distinguished Name\n"); goto error; }
	
	cert->subject = malloc(subjectTotalConsumed);
	if (!cert->subject)
		{ HAJCRYPT_DPRINT("x509CertParse: failed to allocate memory for subject\n"); goto error; }
	ft_memcpy(cert->subject, rest, subjectTotalConsumed);
	cert->subjectLen = subjectTotalConsumed;
	
	rest += subjectTotalConsumed;
	restLen -= subjectTotalConsumed;

	/* Extract SubjectPublicKeyInfo SEQUENCE */
	uint8_t	*spki;
	size_t	spkiLen;
	size_t	spkiConsumed;
	if (!asn1ParseSequence(rest, restLen, &spki, &spkiLen, &spkiConsumed))
		{ HAJCRYPT_DPRINT("x509CertParse: failed to parse SubjectPublicKeyInfo SEQUENCE\n"); goto error; }
	rest += spkiConsumed;
	restLen -= spkiConsumed;

	/* Parse SubjectPublicKeyInfo (unchanged from your version - already correct) */
	{
		uint8_t	*spkiAlgo,		*spkiParams;
		size_t	spkiAlgoLen,	spkiParamsLen;
		size_t	spkiConsumed2;

		if (!asn1ParseSequence(spki, spkiLen, &spkiAlgo, &spkiAlgoLen, &spkiConsumed2))
			{ HAJCRYPT_DPRINT("x509CertParse: failed to parse algorithm sequence\n"); goto error; }

		const uint8_t *algoPtr = spkiAlgo;
		size_t	algoRemain = spkiAlgoLen;
		uint8_t	*oid;
		size_t	oidLen;
		size_t	oidConsumed;
		if (!asn1ParseAny(algoPtr, algoRemain, &oid, &oidLen, &oidConsumed))
			{ HAJCRYPT_DPRINT("x509CertParse: failed to parse algorithm OID\n"); goto error; }
		algoPtr += oidConsumed;
		algoRemain -= oidConsumed;

		spkiParams = NULL;
		spkiParamsLen = 0;
		if (algoRemain > 0) {
			if (!asn1ParseAny(algoPtr, algoRemain, &spkiParams, &spkiParamsLen, &oidConsumed))
				{ HAJCRYPT_DPRINT("x509CertParse: failed to parse algorithm parameters\n"); goto error; }
		}

		const uint8_t	*afterAlgo = spki + spkiConsumed2;
		size_t			afterAlgoLen = spkiLen - spkiConsumed2;
		uint8_t			*pubKeyBits;
		size_t			pubKeyBitsLen;
		size_t			bsConsumed;
		if (!asn1ParseBitString(afterAlgo, afterAlgoLen, &pubKeyBits, &pubKeyBitsLen, &bsConsumed))
			{ HAJCRYPT_DPRINT("x509CertParse: failed to parse public key BIT STRING\n"); goto error; }

		const t_pkeyDef *def;
		if (oidLen == g_rsaPkeyDef.oid.len && ft_memcmp(oid, g_rsaPkeyDef.oid.data, oidLen) == 0)
			def = &g_rsaPkeyDef;
		else if (oidLen == g_ecdsaPkeyDef.oid.len && ft_memcmp(oid, g_ecdsaPkeyDef.oid.data, oidLen) == 0)
			def = &g_ecdsaPkeyDef;
		else
			{ HAJCRYPT_DPRINT("x509CertParse: unsupported algorithm\n"); goto error; }

		void *key = ft_calloc(1, def->keyLen); 
		if (!key)
			{ HAJCRYPT_DPRINT("x509CertParse: failed to allocate memory for public key\n"); goto error; }
		
		if (!def->decodePubKey(pubKeyBits, pubKeyBitsLen, spkiParams, spkiParamsLen, key)) {
			free(key);
			{ HAJCRYPT_DPRINT("x509CertParse: failed to decode public key\n"); goto error; }
		}
		
		cert->pubKey.def = def;
		cert->pubKey.key = key;

		cert->pubKeyRaw = malloc(pubKeyBitsLen);
		if (!cert->pubKeyRaw) {
			def->freeKey(key);
			cert->pubKey.key = NULL;
			cert->pubKey.def = NULL;
			{ HAJCRYPT_DPRINT("x509CertParse: failed to allocate memory for raw public key\n"); goto error; }
		}
		ft_memcpy(cert->pubKeyRaw, pubKeyBits, pubKeyBitsLen);
		cert->pubKeyRawLen = pubKeyBitsLen;
	}

	/**
	 * Parse X.509 extensions (explicit tag [3])
	 * Extensions are optional and appear after the public key
	 */
	if (restLen > 0 && rest[0] == 0xa3) {
		size_t	extConsumed;
		uint8_t	*extSeq;
		size_t	extSeqLen;
		if (!asn1ParseAny(rest, restLen, &extSeq, &extSeqLen, &extConsumed))
			{ HAJCRYPT_DPRINT("x509CertParse: failed to parse extensions\n"); goto error; }

		const uint8_t	*extData = extSeq;
		size_t			extDataLen = extSeqLen;
		size_t			extCount = 0;
		uint8_t			**extensions = NULL;
		size_t			*extLens = NULL;

		/* First pass: Count number of extensions */
		size_t			tmpLen = extDataLen;
		const uint8_t	*tmpPtr = extData;
		while (tmpLen > 0) {
			uint8_t	*dummy;
			size_t	dummyLen;
			size_t	consumed2;
			if (!asn1ParseSequence(tmpPtr, tmpLen, &dummy, &dummyLen, &consumed2))
				break;
			tmpPtr += consumed2;
			tmpLen -= consumed2;
			extCount++;
		}

		/* Second pass: Copy each extension data */
		if (extCount > 0) {
			extensions = malloc(extCount * sizeof(uint8_t*));
			extLens = malloc(extCount * sizeof(size_t));
			if (!extensions || !extLens) {
				free(extensions);
				free(extLens);
				{ HAJCRYPT_DPRINT("x509CertParse: failed to allocate memory for extensions\n"); goto error; }
			}
			
			tmpPtr = extData;
			tmpLen = extDataLen;
			for (size_t i = 0; i < extCount; i++) {
				uint8_t	*extItem;
				size_t	extItemLen;
				size_t	consumed2;
				if (!asn1ParseSequence(tmpPtr, tmpLen, &extItem, &extItemLen, &consumed2)) {
					/* Clean up on failure */
					for (size_t j = 0; j < i; j++)
						free(extensions[j]);
					free(extensions);
					free(extLens);
					{ HAJCRYPT_DPRINT("x509CertParse: failed to parse extension\n"); goto error; }
				}
				
				uint8_t *copy = malloc(extItemLen);
				if (!copy) {
					for (size_t j = 0; j < i; j++)
						free(extensions[j]);
					free(extensions);
					free(extLens);
					{ HAJCRYPT_DPRINT("x509CertParse: failed to allocate memory for extension\n"); goto error; }
				}
				ft_memcpy(copy, extItem, extItemLen);
				extensions[i] = copy;
				extLens[i] = extItemLen;
				tmpPtr += consumed2;
				tmpLen -= consumed2;
			}
		}
		cert->extensions = extensions;
		cert->extLens = extLens;
		cert->extCount = extCount;
	}

	/* Store signature */
	cert->signature = malloc(sigLen);
	if (!cert->signature)
		{ HAJCRYPT_DPRINT("x509CertParse: failed to allocate memory for signature\n"); goto error; }
	ft_memcpy(cert->signature, signature, sigLen);
	cert->sigLen = sigLen;

	/* Compute fingerprints using heap-allocated hash contexts */
	{
		t_hash	*sha256 = malloc(HASH_MAX_CTX_SIZE);
		t_hash	*sha384 = malloc(HASH_MAX_CTX_SIZE);
		if (!sha256 || !sha384) {
			free(sha256);
			free(sha384);
			goto error;
		}
		sha256Init(sha256);
		sha256Update(sha256, der, derLen);
		sha256Final(cert->sha256Fingerprint, sha256);
		
		sha384Init(sha384);
		sha384Update(sha384, der, derLen);
		sha384Final(cert->sha384Fingerprint, sha384);
		
		free(sha256);
		free(sha384);
	}

	return (cert);

error:
	x509CertFree(cert);
	return (NULL);
}





/* --------------- Encoding --------------- */


static int parseDnString(const char *dn, t_dnAttr *attrs, int maxAttrs)
{
	char	**tokens = ft_split(dn, '/');
	int		count = 0;
	if (!tokens) return (0);
	for (int i = 0; tokens[i] && count < maxAttrs; i++) {
		if (tokens[i][0] == '\0') continue;
		char *eq = ft_strchr(tokens[i], '=');
		if (!eq) continue;
		*eq = '\0';
		char *key = tokens[i];
		char *val = eq + 1;
		if (ft_strcmp(key, "CN") == 0)
			attrs[count].oid = &g_oidCommonName;
		else if (ft_strcmp(key, "C") == 0)
			attrs[count].oid = &g_oidCountryName;
		else if (ft_strcmp(key, "O") == 0)
			attrs[count].oid = &g_oidOrganizationName;
		else if (ft_strcmp(key, "OU") == 0)
			attrs[count].oid = &g_oidOrganizationalUnitName;
		else if (ft_strcmp(key, "L") == 0)
			attrs[count].oid = &g_oidLocalityName;
		else if (ft_strcmp(key, "ST") == 0)
			attrs[count].oid = &g_oidStateName;
		else if (ft_strcmp(key, "emailAddress") == 0)
			attrs[count].oid = &g_oidEmailAddress;
		else
		{
			HAJCRYPT_DPRINT("parseDnString: unknown DN attribute '%s'\n", key);
			continue;
		};
		attrs[count].value = ft_strdup(val);
		count++;
	}
	for (int i = 0; tokens[i]; i++) free(tokens[i]);
	free(tokens);
	return (count);
}

static void freeDnAttrs(t_dnAttr *attrs, int count)
{
	for (int i = 0; i < count; i++) free(attrs[i].value);
}

static uint8_t *encodeRDN(const t_dnAttr *attr, size_t *outLen)
{
	size_t	oidLen, seqLen;
	uint8_t	*oidDer = asn1EncodeOid(attr->oid->data, attr->oid->len, &oidLen);
	if (!oidDer) return (NULL);
	size_t	vlen = ft_strlen(attr->value);
	uint8_t	*valueDer = malloc(vlen + 2);
	if (!valueDer) { free(oidDer); return (NULL); }
	valueDer[0] = 0x13; /* PrintableString */
	valueDer[1] = (uint8_t)vlen;
	ft_memcpy(valueDer + 2, attr->value, vlen);
	size_t	valueLen = vlen + 2;
	uint8_t	*seqElems[2] = {oidDer, valueDer};
	size_t	seqSizes[2] = {oidLen, valueLen};
	uint8_t	*atavDer = asn1EncodeSequence(seqElems, seqSizes, 2, &seqLen); /* AttributeTypeAndValue */
	free(oidDer); free(valueDer);
	if (!atavDer) return (NULL);
	uint8_t	*setDer = asn1EncodeSequence(&atavDer, &seqLen, 1, outLen);	/* RDN wrapper */
	free(atavDer);
	if (setDer) setDer[0] = 0x31;
	return (setDer);
}

static uint8_t *encodeName(const char *dn, size_t *outLen)
{
	t_dnAttr	attrs[10];
	int			n = parseDnString(dn, attrs, 10);
	if (n == 0) {
		uint8_t *empty = malloc(2);
		if (empty) { empty[0] = 0x30; empty[1] = 0x00; }
		*outLen = 2;
		return (empty);
	}
	uint8_t	**rdns = malloc(n * sizeof(uint8_t*));
	size_t	*rdnLens = malloc(n * sizeof(size_t));
	if (!rdns || !rdnLens) { free(rdns); free(rdnLens); freeDnAttrs(attrs, n); return (NULL); }
	int ok = 1;
	for (int i = 0; i < n; i++) {
		rdns[i] = encodeRDN(&attrs[i], &rdnLens[i]);
		if (!rdns[i]) { ok = 0; break; }
	}
	uint8_t *nameDer = NULL;
	if (ok) nameDer = asn1EncodeSequence(rdns, rdnLens, n, outLen);
	for (int i = 0; i < n; i++) free(rdns[i]);
	free(rdns); free(rdnLens);
	freeDnAttrs(attrs, n);
	return (nameDer);
}

static uint8_t *encodeTime(time_t t, int generalized, size_t *outLen)
{
	struct tm *tm = gmtime(&t);
	if (!tm) return (NULL);
	char	buf[20];
	int		len;
	if (!generalized && tm->tm_year >= 50 && tm->tm_year < 150) {
		len = ft_snprintf(buf, sizeof(buf), "%02d%02d%02d%02d%02d%02dZ",
			tm->tm_year % 100, tm->tm_mon + 1, tm->tm_mday,
			tm->tm_hour, tm->tm_min, tm->tm_sec);
		uint8_t *der = malloc(len + 2);
		if (!der) return (NULL);
		der[0] = 0x17; der[1] = len;
		ft_memcpy(der + 2, buf, len);
		*outLen = len + 2;
		return (der);
	} else {
		len = ft_snprintf(buf, sizeof(buf), "%04d%02d%02d%02d%02d%02dZ",
			tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
			tm->tm_hour, tm->tm_min, tm->tm_sec);
		uint8_t *der = malloc(len + 2);
		if (!der) return (NULL);
		der[0] = 0x18; der[1] = len;
		ft_memcpy(der + 2, buf, len);
		*outLen = len + 2;
		return (der);
	}
}

static uint8_t *encodeValidity(time_t notBefore, time_t notAfter, size_t *outLen)
{
	size_t	nbLen, naLen;
	uint8_t	*nbDer = encodeTime(notBefore, 0, &nbLen);
	uint8_t	*naDer = encodeTime(notAfter, 0, &naLen);
	if (!nbDer || !naDer) { free(nbDer); free(naDer); return (NULL); }
	uint8_t	*elems[2] = {nbDer, naDer};
	size_t	lens[2] = {nbLen, naLen};
	uint8_t	*seq = asn1EncodeSequence(elems, lens, 2, outLen);
	free(nbDer); free(naDer);
	return (seq);
}

static uint8_t *encodeAlgorithmIdentifier(const t_algoId *algo, size_t *outLen)
{
	size_t	oidLen, nullLen;
	uint8_t	*oidDer = asn1EncodeOid(algo->data, algo->len, &oidLen);
	if (!oidDer) return (NULL);
	uint8_t	*null = asn1EncodeNull(&nullLen);
	if (!null) { free(oidDer); return (NULL); }
	uint8_t	*elems[2] = {oidDer, null};
	size_t	lens[2] = {oidLen, nullLen};
	uint8_t *seq = asn1EncodeSequence(elems, lens, 2, outLen);
	free(oidDer); free(null);
	return (seq);
}

static uint8_t *encodePublicKeyInfo(const t_pkey *pkey, size_t *outLen)
{
	uint8_t	*algo = NULL, *pubKeyBits = NULL, *spki = NULL;
	size_t	algoLen = 0, bitsLen = 0;

	if (pkey->def->type == PKEY_TYPE_RSA) {
		algo = encodeAlgorithmIdentifier(&g_rsaPkeyDef.oid, &algoLen);
	} else if (pkey->def->type == PKEY_TYPE_ECDSA) {
		/* AlgorithmIdentifier: ecPublicKey + curve OID (use secp256r1 from oid.h) */
		size_t	oidLen, curveLen;
		uint8_t	*ecOid = asn1EncodeOid(g_ecdsaPkeyDef.oid.data, g_ecdsaPkeyDef.oid.len, &oidLen);
		uint8_t	*curveOid = asn1EncodeOid((const uint8_t[]){0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}, 8, &curveLen); /* secp256r1 */
		if (!ecOid || !curveOid) { free(ecOid); free(curveOid); goto error; }
		uint8_t	*elems[2] = {ecOid, curveOid};
		size_t	lens[2] = {oidLen, curveLen};
		algo = asn1EncodeSequence(elems, lens, 2, &algoLen);
		free(ecOid); free(curveOid);
	} else goto error;
	if (!algo) goto error;

	size_t	pubKeyRawLen;
	uint8_t	*pubKeyRaw = pkey->def->encodePubKeySpki(pkey->key, &pubKeyRawLen);
	if (!pubKeyRaw) goto error;
	pubKeyBits = asn1EncodeBitString(pubKeyRaw, pubKeyRawLen, &bitsLen);
	free(pubKeyRaw);
	if (!pubKeyBits) goto error;

	uint8_t	*elems2[2] = {algo, pubKeyBits};
	size_t	lens2[2] = {algoLen, bitsLen};
	spki = asn1EncodeSequence(elems2, lens2, 2, outLen);
error:
	free(algo); free(pubKeyBits);
	return (spki);
}
 

t_x509Cert *x509CertNew(const t_pkey	*pkey,
						const char		*subject,	const char	*issuer,
						time_t			notBefore,	time_t		notAfter,
						uint8_t			*serial,	size_t		serialLen)
{
	uint8_t		*versionDer = NULL, *serialDer = NULL, *sigAlgoTbsDer = NULL;
	uint8_t		*issuerDer = NULL, *validityDer = NULL, *subjectDer = NULL, *spkiDer = NULL;
	uint8_t		*tbsDer = NULL, *sigAlgoDer = NULL, *signatureDer = NULL, *certDer = NULL;
	size_t		verIntLen, serialLenDer, sigAlgoTbsLen, issuerLen, validityLen, subjectLen, spkiLen;
	size_t		tbsLen, sigAlgoLen, sigLen, certLen, versionLen = 0;
	t_x509Cert	*cert = NULL;

	/* Version v3 (2) as explicit [0] */
	{
		uint8_t *intVer = asn1EncodeInteger((const uint8_t*)"\x02", 1, &verIntLen);
		if (!intVer) goto error;
		versionDer = malloc(verIntLen + 2);
		if (!versionDer) { free(intVer); goto error; }
		versionDer[0] = 0xa0;
		versionDer[1] = (uint8_t)verIntLen;
		ft_memcpy(versionDer + 2, intVer, verIntLen);
		free(intVer);
		versionLen = verIntLen + 2;
	}
	serialDer = asn1EncodeInteger(serial, serialLen, &serialLenDer);
	if (!serialDer) goto error;
	sigAlgoTbsDer = encodeAlgorithmIdentifier(&g_sha256WithRSAEncryption, &sigAlgoTbsLen);
	if (!sigAlgoTbsDer) goto error;
	issuerDer = encodeName(issuer ? issuer : subject, &issuerLen);
	if (!issuerDer) goto error;
	validityDer = encodeValidity(notBefore, notAfter, &validityLen);
	if (!validityDer) goto error;
	subjectDer = encodeName(subject ? subject : "", &subjectLen);
	if (!subjectDer) goto error;
	spkiDer = encodePublicKeyInfo(pkey, &spkiLen);
	if (!spkiDer) goto error;

	uint8_t *tbsElems[] = {versionDer, serialDer, sigAlgoTbsDer, issuerDer, validityDer, subjectDer, spkiDer};
	size_t tbsSizes[] = {versionLen, serialLenDer, sigAlgoTbsLen, issuerLen, validityLen, subjectLen, spkiLen};
	tbsDer = asn1EncodeSequence(tbsElems, tbsSizes, 7, &tbsLen);
	if (!tbsDer) goto error;

	/* Compute signature over TBSCertificate using SHA-256 and the provided private key */
	uint8_t	digest[32];
	t_hash	sha256;
	sha256Init(&sha256);
	sha256Update(&sha256, tbsDer, tbsLen);
	sha256Final(digest, &sha256);

	uint8_t			signature[512];
	size_t			sigOutLen = sizeof(signature);
	const t_algoId	*digestAlgo = &g_sha256Hash.oid;
	t_pkeyPadding	padding = (pkey->def->type == PKEY_TYPE_RSA) ? PKEY_PADDING_PKCS1V15 : PKEY_PADDING_NONE;
	if (!pkeySign((t_pkey*)pkey, digest, 32, digestAlgo, signature, &sigOutLen, padding))
		goto error;

	signatureDer = asn1EncodeBitString(signature, sigOutLen, &sigLen);
	if (!signatureDer) goto error;

	sigAlgoDer = encodeAlgorithmIdentifier(&g_sha256WithRSAEncryption, &sigAlgoLen);
	if (!sigAlgoDer) goto error;

	uint8_t	*certElems[] = {tbsDer, sigAlgoDer, signatureDer};
	size_t	certSizes[] = {tbsLen, sigAlgoLen, sigLen};
	certDer = asn1EncodeSequence(certElems, certSizes, 3, &certLen);
	if (!certDer) goto error;

	cert = x509CertParse(certDer, certLen);
error:
	free(versionDer); free(serialDer); free(sigAlgoTbsDer); free(issuerDer);
	free(validityDer); free(subjectDer); free(spkiDer); free(tbsDer);
	free(sigAlgoDer); free(signatureDer); free(certDer);
	return cert;
}





const char *getDnAttrName(const uint8_t *oid, size_t oidLen)
{
	static const struct {
		const t_algoId	*oid;
		const char		*name;
	} map[] = {
		{ &g_oidCommonName,				"CN" },
		{ &g_oidCountryName,			"C"  },
		{ &g_oidOrganizationName,		"O"  },
		{ &g_oidOrganizationalUnitName,	"OU" },
		{ &g_oidLocalityName,			"L"  },
		{ &g_oidStateName,				"ST" },
		{ &g_oidEmailAddress,			"emailAddress" },
	};
	for (size_t i = 0; i < sizeof(map)/sizeof(map[0]); i++) {
		if (oidLen == map[i].oid->len &&
			ft_memcmp(oid, map[i].oid->data, oidLen) == 0)
			return map[i].name;
	}
	return (NULL);
}

void x509CertFree(t_x509Cert *cert)
{
	if (!cert)
		return;
	
	free(cert->der);
	free(cert->issuer);
	free(cert->subject);
	free(cert->serial);
	free(cert->pubKeyRaw);
	free(cert->signature);
	
	/* Free public key using algorithm-specific destructor */
	if (cert->pubKey.def && cert->pubKey.key)
	{
		cert->pubKey.def->freeKey(cert->pubKey.key);
		free(cert->pubKey.key);
	}
	
	/* Free all extensions */
	for (size_t i = 0; i < cert->extCount; i++)
		free(cert->extensions[i]);
	free(cert->extensions);
	free(cert->extLens);
	
	free(cert);
}

t_certChain *certChainNew(void)
{
	t_certChain *chain = calloc(1, sizeof(t_certChain));
	return (chain);
}

int certChainAdd(t_certChain *chain, t_x509Cert *cert)
{
	if (!chain || !cert)
		return (0);
	
	t_x509Cert **tmp = realloc(chain->certs, (chain->count + 1) * sizeof(t_x509Cert*));
	if (!tmp)
		return (0);
	
	chain->certs = tmp;
	chain->certs[chain->count++] = cert;
	return (1);
}

int certChainAddDER(t_certChain *chain, const uint8_t *der, size_t derLen)
{
	t_x509Cert *cert = x509CertParse(der, derLen);
	if (!cert)
		return (0);
	
	if (!certChainAdd(chain, cert)) {
		x509CertFree(cert);
		return (0);
	}
	return (1);
}

void certChainFree(t_certChain *chain)
{
	if (!chain)
		return;
	
	for (size_t i = 0; i < chain->count; i++)
		x509CertFree(chain->certs[i]);
	free(chain->certs);
	free(chain);
}
