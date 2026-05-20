#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"
#include "../../includes/x509/asn1.h"
#include "../../includes/x509/pem.h"
#include "../../includes/asymmetric/pkeyPem.h"
#include "../../includes/utils/dispatch.h"

/**
 * @brief Build a DER-encoded SubjectPublicKeyInfo (SPKI) structure.
 *
 * This function assembles an SPKI SEQUENCE containing an AlgorithmIdentifier
 * (OID plus optional parameters, or NULL if parameters are absent) and a
 * BIT STRING that wraps the provided public key DER bytes.
 *
 * @param oid        Pointer to the algorithm OID bytes.
 * @param oidLen     Length of the OID in bytes.
 * @param paramsDer  Optional DER-encoded parameters (NULL to encode NULL).
 * @param paramsLen  Length of the parameters DER.
 * @param pubKeyDer  DER-encoded public key bytes to wrap in a BIT STRING.
 * @param pubKeyLen  Length of the public key bytes.
 * @param outLen     Output pointer to receive the total SPKI DER length.
 *
 * @return Newly allocated DER-encoded SPKI buffer on success; NULL on failure.
 *         Caller is responsible for freeing the returned buffer.
 */
static uint8_t	*makeSubjectPublicKeyInfo(const uint8_t	*oid,		size_t	oidLen,
										 const uint8_t	*paramsDer,	size_t	paramsLen,
										 const uint8_t	*pubKeyDer,	size_t	pubKeyLen,
										 size_t			*outLen)
{
	uint8_t	*oidDer,	*algoSeq,	*bitStr, *spkiDer;
	size_t	oidDerLen,	algoLen,	bitLen;

	oidDer = asn1EncodeOid(oid, oidLen, &oidDerLen);
	if (!oidDer) return (NULL);

	/* AlgorithmIdentifier */
	if (paramsDer) {
		uint8_t	*elems[2] = {oidDer, (uint8_t *)paramsDer};
		size_t	lens[2]  = {oidDerLen, paramsLen};
		algoSeq = asn1EncodeSequence(elems, lens, 2, &algoLen);
	} else {
		uint8_t	*nullDer = asn1EncodeNull(&paramsLen);
		if (!nullDer) { free(oidDer); return (NULL); }
		uint8_t	*elems[2] = {oidDer, nullDer};
		size_t	lens[2]  = {oidDerLen, paramsLen};
		algoSeq = asn1EncodeSequence(elems, lens, 2, &algoLen);
		free(nullDer);
	}
	free(oidDer);
	if (!algoSeq) return (NULL);

	/* BIT STRING wrapping the public key */
	bitStr = asn1EncodeBitString(pubKeyDer, pubKeyLen, &bitLen);
	if (!bitStr) { free(algoSeq); return (NULL); }

	/* SubjectPublicKeyInfo SEQUENCE */
	uint8_t	*elems[2] = {algoSeq, bitStr};
	size_t	lens[2]  = {algoLen, bitLen};
	spkiDer = asn1EncodeSequence(elems, lens, 2, outLen);
	free(algoSeq);
	free(bitStr);
	return (spkiDer);
}


/**
 * @brief Build a PKCS#8 PrivateKeyInfo DER structure.
 *
 * Constructs a DER-encoded PrivateKeyInfo sequence containing:
 * version = 0, AlgorithmIdentifier (OID + parameters or NULL),
 * and an OCTET STRING wrapping the traditional private key.
 *
 * @param oid         DER OID bytes identifying the algorithm.
 * @param oidLen      Length of @p oid.
 * @param paramsDer   DER-encoded algorithm parameters, or NULL to use NULL.
 * @param paramsLen   Length of @p paramsDer.
 * @param privKeyDer  DER-encoded traditional private key bytes.
 * @param privKeyLen  Length of @p privKeyDer.
 * @param outLen      Output parameter receiving total DER length.
 *
 * @return Newly allocated DER-encoded PrivateKeyInfo buffer on success,
 *         or NULL on allocation/encoding failure.
 */
static uint8_t	*makePrivateKeyInfo(const uint8_t	*oid,			size_t	oidLen,
									const uint8_t	*paramsDer,		size_t	paramsLen,
									const uint8_t	*privKeyDer,	size_t	privKeyLen,
									size_t			*outLen)
{
	uint8_t	versionDer[] = {0x02, 0x01, 0x00};
	uint8_t	*oidDer,	*algoSeq,	*octetDer,	*pkcs8Der;
	size_t	oidDerLen,	algoLen,	octetLen;

	oidDer = asn1EncodeOid(oid, oidLen, &oidDerLen);
	if (!oidDer) return (NULL);

	/* AlgorithmIdentifier */
	if (paramsDer) {
		uint8_t	*elems[2] = {oidDer, (uint8_t *)paramsDer};
		size_t	lens[2]  = {oidDerLen, paramsLen};
		algoSeq = asn1EncodeSequence(elems, lens, 2, &algoLen);
	} else {
		uint8_t	*nullDer = asn1EncodeNull(&paramsLen);
		if (!nullDer) { free(oidDer); return (NULL); }
		uint8_t	*elems[2] = {oidDer, nullDer};
		size_t	lens[2]  = {oidDerLen, paramsLen};
		algoSeq = asn1EncodeSequence(elems, lens, 2, &algoLen);
		free(nullDer);
	}
	free(oidDer);
	if (!algoSeq) return (NULL);

	/* OCTET STRING containing the traditional private key */
	octetDer = asn1EncodeOctetString(privKeyDer, privKeyLen, &octetLen);
	if (!octetDer) { free(algoSeq); return (NULL); }

	/* PrivateKeyInfo SEQUENCE */
	uint8_t	*elems[3] = {versionDer, algoSeq, octetDer};
	size_t	lens[3]  = {sizeof(versionDer), algoLen, octetLen};
	pkcs8Der = asn1EncodeSequence(elems, lens, 3, outLen);
	free(algoSeq);
	free(octetDer);
	return (pkcs8Der);
}



char	*pkeyToPem(t_pkey *key, int isPrivate, int useTraditional, const char *password, const void *cipher)
{
	const t_pkeyPemDef	*def;
	uint8_t				*der = NULL;
	size_t				derLen;
	const char			*type;

	if (!key || !key->key || (!key->def && !key->type))
		return (NULL);
	if (!key->def && key->type) {
		key->def = getPkeyPemDefByPkeyType(key->type);
		if (!key->def)
			return (HAJCRYPT_DPRINT("Pem: Unsupported key type"), NULL);
	}
	def = key->def;

	if (!isPrivate) {
		/* Public key */
		if (useTraditional) {
			der = def->encodePubKey(key->key, &derLen);
			type = def->tradPubLabel;
		} else {
			uint8_t	*pubDer = def->encodePubKey(key->key, &derLen);
			if (!pubDer) return (NULL);
			uint8_t	*paramsDer = NULL;
			size_t	paramsLen = 0;
			if (def->encodeAlgoParams) {
				paramsDer = def->encodeAlgoParams(key->key, &paramsLen);
				if (!paramsDer) { free(pubDer); return (NULL); }
			}
			der = makeSubjectPublicKeyInfo(def->oid.data, def->oid.len,
										  paramsDer, paramsLen,
										  pubDer, derLen, &derLen);
			free(pubDer);
			free(paramsDer);
			type = "PUBLIC KEY";
		}
	} else {
		/* Private key */
		if (useTraditional) {
			der = def->encodePrivKey(key->key, &derLen);
			type = def->tradPrivLabel;
		} else {
			uint8_t	*privDer = def->encodePrivKey(key->key, &derLen);
			if (!privDer) return (NULL);
			uint8_t	*paramsDer = NULL;
			size_t	paramsLen = 0;
			if (def->encodeAlgoParams) {
				paramsDer = def->encodeAlgoParams(key->key, &paramsLen);
				if (!paramsDer) { free(privDer); return (NULL); }
			}
			der = makePrivateKeyInfo(def->oid.data, def->oid.len,
									paramsDer, paramsLen,
									privDer, derLen, &derLen);
			free(privDer);
			free(paramsDer);
			type = "PRIVATE KEY";
		}
	}

	if (!der) return (NULL);

	/* Encryption */
	if (password && isPrivate) {
		const t_cipher *encCipher = (const t_cipher *)cipher;
		if (!encCipher) {
			extern const t_cipher g_aes256CbcCipher;
			encCipher = &g_aes256CbcCipher;
		}
		char *pem;
		if (useTraditional)
			pem = pkcs1EncryptPem(type, der, derLen, encCipher, password);
		else
			pem = pkcs8EncryptPem(der, derLen, encCipher, password, NULL);
		free(der);
		return (pem);
	}
	char *pem = pemEncode(der, derLen, type);
	free(der);
	return (pem);
}


/**
 * parsePubKey - Parse a public key from a PEM string using a definition.
 *
 * Attempts to decode a public key from the provided PEM data. It first tries
 * the traditional PEM label specified by the definition, then falls back to
 * parsing a SubjectPublicKeyInfo ("PUBLIC KEY") structure. On success, it
 * decodes the key into the caller-provided storage via the definition's
 * decode callback.
 *
 * @pem: Null-terminated PEM string containing the public key.
 * @key: Output pointer where the decoded key is stored.
 * @def: Definition containing labels and decode callbacks for the key type.
 *
 * Return: Non-zero on success, 0 on failure.
 */

static int	parsePubKey(const char *pem, void *key, const t_pkeyPemDef *def)
{
	t_pemBlock	block;
	char		header[128];

	/* Traditional label */
	ft_snprintf(header, sizeof(header), "-----BEGIN %s-----", def->tradPubLabel);
	if (ft_strstr(pem, header)) {
		if (!pemDecode(pem, &block))
			return (0);
		int ret = def->decodePubKey(block.der, block.derLen, key);
		pemFreeBlock(&block);
		return (ret);
	}

	/* SubjectPublicKeyInfo */
	if (ft_strstr(pem, "-----BEGIN PUBLIC KEY-----")) {
		if (!pemDecode(pem, &block))
			return (0);
		uint8_t	*content, *algoSeq, *bitStr;
		size_t	contentLen, consumed, algoLen, bitLen;
		if (!asn1ParseSequence(block.der, block.derLen, &content, &contentLen, &consumed)
			|| !asn1ParseSequence(content, contentLen, &algoSeq, &algoLen, &consumed)) {
			pemFreeBlock(&block);
			return (HAJCRYPT_DPRINT("Failed to parse sequence\n"), 0);
		}
		content += consumed; contentLen -= consumed;
		if (!asn1ParseBitString(content, contentLen, &bitStr, &bitLen, &consumed)) {
			pemFreeBlock(&block);
			return (HAJCRYPT_DPRINT("Failed to parse bit string\n"), 0);
		}
		int ret = def->decodePubKey(bitStr, bitLen, key);
		pemFreeBlock(&block);
		return (ret);
	}
	return (0);
}

static int parsePrivateKeyInfoDer(const uint8_t *der, size_t derLen,  void *key, const t_pkeyPemDef *def)
{
	uint8_t	*content,	*algoSeq,	*octetStr;
	size_t	contentLen,	consumed,	algoLen, octetLen;

	if (!asn1ParseSequence(der, derLen, &content, &contentLen, &consumed))
		return (HAJCRYPT_DPRINT("Failed to parse sequence\n"), (0));

	/* version (INTEGER, must be 0) */
	uint8_t	*ver;
	size_t	verLen;
	if (!asn1ParseInteger(content, contentLen, &ver, &verLen, &consumed))
		return (HAJCRYPT_DPRINT("Failed to parse integer\n"), (0));
	content += consumed;
	contentLen -= consumed;

	/* AlgorithmIdentifier (SEQUENCE ignored for the moment) */
	if (!asn1ParseSequence(content, contentLen, &algoSeq, &algoLen, &consumed))
		return (HAJCRYPT_DPRINT("Failed to parse algorithm sequence\n"), (0));
	content += consumed;
	contentLen -= consumed;

	/* privateKey OCTET STRING */
	if (!asn1ParseOctetString(content, contentLen, &octetStr, &octetLen, &consumed))
		return (HAJCRYPT_DPRINT("Failed to parse octet string\n"), (0));

	return (def->decodePrivKey(octetStr, octetLen, key));
}

/**
 * Parses an unencrypted PKCS#8 private key from a PEM-encoded string.
 *
 * Decodes the PEM block, parses the ASN.1 sequence (version, algorithm
 * identifier, and private key octet string), then delegates private key
 * decoding to the provided definition.
 *
 * @param pem  NUL-terminated PEM text containing a PKCS#8 private key.
 * @param key  Output key structure to be filled by the decoder.
 * @param def  Definition containing the private key decoder callback.
 * @return     Non-zero on success; 0 on failure.
 */
static int	parsePrivateUnencryptedPkcs8(const char *pem, void *key, const t_pkeyPemDef *def)
{
	t_pemBlock	block;
	int			ret;
	if (!pemDecode(pem, &block))
		return (0);

	ret = parsePrivateKeyInfoDer(block.der, block.derLen, key, def);
	pemFreeBlock(&block);
	return (ret);
}

/**
 * Parses an encrypted PKCS#8 PEM blob, decrypts it using the provided password,
 * and decodes the contained private key with the supplied definition.
 *
 * @param pem       NUL-terminated PEM string containing the encrypted PKCS#8 key.
 * @param key       Output key object to be filled by def->decodePrivKey.
 * @param def       Algorithm-specific decoder definition.
 * @param password  Password used to decrypt the PKCS#8 payload.
 *
 * @return Non-zero on successful decode, or 0 on failure (including missing
 *         password, decryption failure, or ASN.1 parsing errors).
 */

static int	parsePrivateEncryptedPkcs8(const char *pem, void *key, const t_pkeyPemDef *def, const char *password)
{
	uint8_t	*decryptedDer = NULL;
	size_t	decryptedLen = 0;
	int		ret;

	const char	*header = "-----BEGIN ENCRYPTED PRIVATE KEY-----";

	if (ft_strncmp(pem, header, ft_strlen(header)) == 0) {
		if (!password)
			return (2); /* Password needed */
		decryptedDer = pkcs8DecryptedDer(pem, password, &decryptedLen);
		if (!decryptedDer)
			return (0);
	}

	ret = parsePrivateKeyInfoDer(decryptedDer, decryptedLen, key, def);
	free(decryptedDer);
	return (ret);
}

static int	parsePrivateTraditional(const char *pem, void *key, const t_pkeyPemDef *def, const char *password)
{
	t_pemBlock	block;
	char		header[128];

	ft_snprintf(header, sizeof(header), "-----BEGIN %s-----", def->tradPrivLabel);
	if (!ft_strstr(pem, header))
		return (0);

	/* Encrypted (Proc-Type: 4,ENCRYPTED) */
	if (ft_strstr(pem, "Proc-Type: 4,ENCRYPTED") != NULL) {
		if (!password)
			return (2); /* Password needed */
		uint8_t	*decryptedDer = NULL;
		size_t	decryptedLen = 0;
		decryptedDer = pkcs1DecryptedDer(pem, password, &decryptedLen);
		if (!decryptedDer)
			return (0);
		int ret = def->decodePrivKey(decryptedDer, decryptedLen, key);
		free(decryptedDer);
		return (ret);
	}
	/* Unencrypted */
	if (!pemDecode(pem, &block))
		return (0);
	int ret = def->decodePrivKey(block.der, block.derLen, key);
	pemFreeBlock(&block);
	return (ret);
}

static int tryParseKey(const char *pem, t_pkey *key, const t_pkeyPemDef *def, int isPrivate, const char *password)
{
	void	*concreteKey;
	int		ret = 0;
	
	/* Allocate a key structure of the required size */
	concreteKey = malloc(def->keyLen);
	if (!concreteKey)
		return (HAJCRYPT_DPRINT("Failed to allocate key structure\n"), 0);

	/* Attempt to parse as public or private according to isPrivate flag */
	if (isPrivate) {
		/* Private key: try encrypted PKCS#8, unencrypted PKCS#8, traditional */
		ret = parsePrivateEncryptedPkcs8(pem, concreteKey, def, password);
		if (ret == 0) { /* Not recognized */
			ret = parsePrivateUnencryptedPkcs8(pem, concreteKey, def);
			if (ret == 0)
				ret = parsePrivateTraditional(pem, concreteKey, def, password);
		}
	} else
		ret = parsePubKey(pem, concreteKey, def);
	if (ret == 1) { /* Parsing successfull */
		key->key = concreteKey;
		key->def = def;
	} else /* Either incorrect or password needed */
		free(concreteKey);
	return (ret);
}

int	pkeyFromPem(const char *pem, t_pkey *key, int isPrivate, const char *password)
{
	const t_pkeyPemDef	*def;
	int					type;

	if (!pem || !key)
		return (1);
	
	def = key->def;
	if (!key->def && key->type)
		def = getPkeyPemDefByPkeyType(key->type);
	if (def)
		return (tryParseKey(pem, key, def, isPrivate, password));
	else
	{
		for (type = PKEY_TYPE_UNKNOWN + 1; type < PKEY_TYPE_MAX; type++)
		{
			def = getPkeyPemDefByPkeyType(type);
			if (def)
			{
				int ret = tryParseKey(pem, key, def, isPrivate, password);
				if (ret) /* Either successful or password needed */
					return (ret);
			}
		}
	}
	return (0);
}
