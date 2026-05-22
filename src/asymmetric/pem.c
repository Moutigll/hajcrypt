#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"
#include "../../hajlib/include/hmemory.h"
#include "../../includes/x509/asn1.h"
#include "../../includes/x509/pem.h"
#include "../../includes/utils/dispatch.h"

#include "../../includes/asymmetric/pkey.h"


/**
 * Builds a DER-encoded SubjectPublicKeyInfo (SPKI) structure.
 *
 * This function assembles the AlgorithmIdentifier sequence from the given OID
 * and optional parameters, encodes the public key as a BIT STRING, and wraps
 * both into an outer SEQUENCE. On success, it returns the allocated DER buffer
 * and stores its length in `outLen`.
 *
 * @param oid        Pointer to the algorithm OID bytes.
 * @param oidLen     Length of the OID bytes.
 * @param paramsDer  Optional DER-encoded parameters (NULL to use ASN.1 NULL).
 * @param paramsLen  Length of the parameters DER.
 * @param pubKeyDer  DER-encoded public key bytes.
 * @param pubKeyLen  Length of the public key bytes.
 * @param outLen     Output pointer to receive the SPKI DER length.
 * @return           Newly allocated DER buffer on success; NULL on failure.
 */
static uint8_t	*makeSpki(const uint8_t	*oid,		size_t	oidLen,
						  const uint8_t	*paramsDer,	size_t	paramsLen,
						  const uint8_t	*pubKeyDer,	size_t	pubKeyLen,
						  size_t		*outLen)
{
	uint8_t	*spkiDer;
	uint8_t	*elems[2];
	size_t	lens[2];
	uint8_t	*oidDer,	*algoSeq,	*bitStr;
	size_t	oidDerLen,	algoLen,	bitLen;

	oidDer = asn1EncodeOid(oid, oidLen, &oidDerLen);
	if (!oidDer)
		return (NULL);

	/* Build AlgorithmIdentifier */
	if (paramsDer)
	{
		uint8_t	*elems[2];
		size_t	lens[2];

		elems[0] = oidDer;
		lens[0] = oidDerLen;
		elems[1] = (uint8_t *)paramsDer;
		lens[1] = paramsLen;
		algoSeq = asn1EncodeSequence(elems, lens, 2, &algoLen);
	}
	else
	{
		uint8_t	*nullDer;

		nullDer = asn1EncodeNull(&paramsLen);
		if (!nullDer)
		{
			free(oidDer);
			return (NULL);
		}
		elems[0] = oidDer;
		lens[0] = oidDerLen;
		elems[1] = nullDer;
		lens[1] = paramsLen;
		algoSeq = asn1EncodeSequence(elems, lens, 2, &algoLen);
		free(nullDer);
	}
	free(oidDer);
	if (!algoSeq)
		return (NULL);

	/* BIT STRING wrapping the public key */
	bitStr = asn1EncodeBitString(pubKeyDer, pubKeyLen, &bitLen);
	if (!bitStr)
	{
		free(algoSeq);
		return (NULL);
	}

	/* SubjectPublicKeyInfo SEQUENCE */
	{
		elems[0] = algoSeq;
		lens[0] = algoLen;
		elems[1] = bitStr;
		lens[1] = bitLen;
		spkiDer = asn1EncodeSequence(elems, lens, 2, outLen);
	}
	free(algoSeq);
	free(bitStr);
	return (spkiDer);
}

/**
 * Build a PKCS#8 PrivateKeyInfo DER sequence from the given algorithm OID,
 * optional parameters, and private key DER blob.
 *
 * @param oid        DER-encoded algorithm OID bytes (raw OID, not TLV).
 * @param oidLen     Length of the OID bytes.
 * @param paramsDer  Optional DER-encoded algorithm parameters (TLV), or NULL
 *                   to encode a NULL parameters field.
 * @param paramsLen  Length of @p paramsDer (ignored when NULL).
 * @param privKeyDer DER-encoded private key (TLV) to wrap in an OCTET STRING.
 * @param privKeyLen Length of @p privKeyDer.
 * @param outLen     Output: length of the generated PKCS#8 DER.
 *
 * @return Newly allocated DER buffer containing the PKCS#8 sequence, or NULL
 *         on allocation/encoding failure. Caller must free the returned buffer.
 */
static uint8_t	*makePkcs8(const uint8_t	*oid,			size_t	oidLen,
						   const uint8_t	*paramsDer,		size_t	paramsLen,
						   const uint8_t	*privKeyDer,	size_t	privKeyLen,
						   size_t			*outLen)
{
	uint8_t	versionDer[] = {0x02, 0x01, 0x00};
	uint8_t	*pkcs8Der;
	uint8_t	*elems[2];
	size_t	lens[2];
	uint8_t	*oidDer, *algoSeq, *octetDer;
	size_t	oidDerLen, algoLen, octetLen;

	oidDer = asn1EncodeOid(oid, oidLen, &oidDerLen);
	if (!oidDer)
		return (NULL);

	/* Build AlgorithmIdentifier */
	if (paramsDer)
	{
		elems[0] = oidDer;
		lens[0] = oidDerLen;
		elems[1] = (uint8_t *)paramsDer;
		lens[1] = paramsLen;
		algoSeq = asn1EncodeSequence(elems, lens, 2, &algoLen);
	}
	else
	{
		uint8_t	*nullDer;

		nullDer = asn1EncodeNull(&paramsLen);
		if (!nullDer)
		{
			free(oidDer);
			return (NULL);
		}
		elems[0] = oidDer;
		lens[0] = oidDerLen;
		elems[1] = nullDer;
		lens[1] = paramsLen;
		algoSeq = asn1EncodeSequence(elems, lens, 2, &algoLen);
		free(nullDer);
	}
	free(oidDer);
	if (!algoSeq)
		return (NULL);

	/* OCTET STRING containing the private key */
	octetDer = asn1EncodeOctetString(privKeyDer, privKeyLen, &octetLen);
	if (!octetDer)
	{
		free(algoSeq);
		return (NULL);
	}

	/* PrivateKeyInfo SEQUENCE */
	{
		uint8_t	*e[3];
		size_t	l[3];

		e[0] = versionDer;
		l[0] = sizeof(versionDer);
		e[1] = algoSeq;
		l[1] = algoLen;
		e[2] = octetDer;
		l[2] = octetLen;
		pkcs8Der = asn1EncodeSequence(e, l, 3, outLen);
	}
	free(algoSeq);
	free(octetDer);
	return (pkcs8Der);
}




char	*pkeyToPem(t_pkey *pkey, int isPrivate, int useTraditional, const char *password, const void *cipher)
{
	const t_pkeyDef	*def;
	uint8_t			*der;
	size_t			derLen;
	const char		*type;

	if (!pkey || !pkey->key || !pkey->def)
		return (NULL);
	def = pkey->def;
	if (!isPrivate)
	{
		if (useTraditional && def->encodePubKeyPkcs1)
		{
			der = def->encodePubKeyPkcs1(pkey->key, &derLen);
			type = def->tradPubLabel;
		}
		else
		{
			uint8_t	*pubDer, *paramsDer;
			size_t	paramsLen;

			pubDer = def->encodePubKeySpki(pkey->key, &derLen);
			if (!pubDer)
				return (NULL);
			paramsDer = NULL;
			paramsLen = 0;
			if (def->encodeAlgoParams)
			{
				paramsDer = def->encodeAlgoParams(pkey->key, &paramsLen);
				if (!paramsDer)
				{
					free(pubDer);
					return (NULL);
				}
			}
			der = makeSpki(def->oid.data, def->oid.len,
					paramsDer, paramsLen, pubDer, derLen, &derLen);
			free(pubDer);
			free(paramsDer);
			type = "PUBLIC KEY";
		}
	}
	else
	{
		if (useTraditional && def->encodePrivKeyPkcs1)
		{
			der = def->encodePrivKeyPkcs1(pkey->key, &derLen);
			type = def->tradPrivLabel;
		}
		else
		{
			uint8_t	*privDer, *paramsDer;
			size_t	paramsLen;

			privDer = def->encodePrivKeyPkcs8(pkey->key, &derLen);
			if (!privDer)
				return (NULL);
			paramsDer = NULL;
			paramsLen = 0;
			if (def->encodeAlgoParams)
			{
				paramsDer = def->encodeAlgoParams(pkey->key, &paramsLen);
				if (!paramsDer)
				{
					free(privDer);
					return (NULL);
				}
			}
			der = makePkcs8(def->oid.data, def->oid.len,
					paramsDer, paramsLen, privDer, derLen, &derLen);
			free(privDer);
			free(paramsDer);
			type = "PRIVATE KEY";
		}
	}
	if (!der)
		return (NULL);
	if (password && isPrivate)
	{
		const t_cipher	*encCipher;
		char			*pem;

		encCipher = (const t_cipher *)cipher;
		if (!encCipher)
		{
			extern const t_cipher	g_aes256CbcCipher;

			encCipher = &g_aes256CbcCipher;
		}
		if (useTraditional && def->encodePrivKeyPkcs1)
			pem = pkcs1EncryptPem(type, der, derLen, encCipher, password);
		else
			pem = pkcs8EncryptPem(der, derLen, encCipher, password, NULL);
		free(der);
		return (pem);
	}
	else
	{
		char	*pem;

		pem = pemEncode(der, derLen, type);
		free(der);
		return (pem);
	}
}



/* =========================================================================
 *            pkeyFromPem - parsing helpers
 * ========================================================================= */

/**
 * Parse a PEM-encoded public key and decode it using the provided definition.
 *
 * This function supports both traditional public key PEM labels (as specified
 * by the key definition) and the generic "PUBLIC KEY" (SubjectPublicKeyInfo)
 * format. It decodes the PEM block, parses ASN.1 as needed, and invokes the
 * definition's public key decoder.
 *
 * @param pem	PEM-encoded string containing the public key.
 * @param key	Output key structure to fill.
 * @param def	Key definition containing labels and decoder callbacks.
 *
 * @return Non-zero on successful decoding, 0 on failure.
 */
static int	parsePublicKey(const char *pem, void *key, const t_pkeyDef *def)
{
	t_pemBlock	block;
	char		header[128];
	int			ret = 0;

	ft_snprintf(header, sizeof(header), "-----BEGIN %s-----", def->tradPubLabel);
	if (ft_strstr(pem, header))
	{
		if (!pemDecode(pem, &block))
			return (0);
		if (def->decodePubKey)
		{
			ret = def->decodePubKey(block.der, block.derLen, NULL, 0, key);
		}
	}
	else if (ft_strstr(pem, "-----BEGIN PUBLIC KEY-----"))
	{
		uint8_t			*content,	*algoSeq,	*bitStr,	*oid;
		size_t			contentLen,	consumed,	algoLen,	bitLen,	oidLen;
		const uint8_t	*params = NULL;
		size_t			paramsLen = 0;

		if (!pemDecode(pem, &block))
			return (0);
		if (!asn1ParseSequence(block.der, block.derLen,
				&content, &contentLen, &consumed)
			|| !asn1ParseSequence(content, contentLen,
				&algoSeq, &algoLen, &consumed))
			goto exit;
		content += consumed; contentLen -= consumed;
		if (!asn1ParseOid(algoSeq, algoLen, &oid, &oidLen, &consumed))
			goto exit;
		algoSeq += consumed; algoLen -= consumed;

		if (algoLen > 0)
		{
			params = algoSeq;
			paramsLen = algoLen;
		}
		if (!asn1ParseBitString(content, contentLen,
				&bitStr, &bitLen, &consumed))
			goto exit;
		ret = 0;
		if (def->decodePubKey)
			ret = def->decodePubKey(bitStr, bitLen, params, paramsLen, key);
	}
exit:
	pemFreeBlock(&block);
	return (ret);
}

/**
 * Parses a DER-encoded PKCS#8 PrivateKeyInfo structure and decodes the
 * contained private key using the provided key definition.
 *
 * Expects a sequence containing an integer version, an algorithm identifier
 * sequence, and an octet string with the private key data. The algorithm
 * sequence is parsed for structure validation only; the actual key decoding
 * is delegated to def->decodePrivKey().
 *
 * @param der     Pointer to DER-encoded data.
 * @param derLen  Length of the DER data.
 * @param key     Output key structure to populate.
 * @param def     Key definition providing the private key decoder.
 * @return 1 on success, 0 on failure.
 */
static int	parsePrivateKeyInfoDer(const uint8_t *der, size_t derLen, void *key, const t_pkeyDef *def)
{
	uint8_t			*content,	*algoSeq,	*octetStr, *oid;
	size_t			contentLen,	consumed,	algoLen,	octetLen, oidLen;
	const uint8_t	*params = NULL;
	size_t			paramsLen = 0;
	uint8_t			*ver;
	size_t			verLen;

	if (!asn1ParseSequence(der, derLen, &content, &contentLen, &consumed))
		return (0);
	if (!asn1ParseInteger(content, contentLen, &ver, &verLen, &consumed))
		return (0);
	content += consumed;
	contentLen -= consumed;
	if (!asn1ParseSequence(content, contentLen, &algoSeq, &algoLen, &consumed))
		return (0);
	content += consumed;
	contentLen -= consumed;
	if (!asn1ParseOid(algoSeq, algoLen, &oid, &oidLen, &consumed))
		return (0);
	algoSeq += consumed;
	algoLen -= consumed;

	if (algoLen > 0)
	{
		params = algoSeq;
		paramsLen = algoLen;
	}
	if (!asn1ParseOctetString(content, contentLen,
			&octetStr, &octetLen, &consumed))
		return (0);
	if (!def->decodePrivKey)
		return (0);
	return (def->decodePrivKey(octetStr, octetLen, params, paramsLen, key));
}


/**
 * Parses an encrypted PKCS#8 private key from a PEM buffer, decrypts it with
 * the provided password, and delegates DER parsing to the PKI parser.
 *
 * @param pem       NUL-terminated PEM string containing the encrypted key.
 * @param key       Output key structure to populate.
 * @param def       Key definition describing expected type/parameters.
 * @param password  Password used to decrypt the PKCS#8 payload.
 *
 * @return 2 if password is missing, 0 on decryption/format failure,
 *         otherwise the return value of parsePrivateKeyInfoDer().
 */
static int	parsePrivateEncryptedPkcs8(const char *pem, void *key, const t_pkeyDef *def, const char *password)
{
	uint8_t	*decryptedDer;
	size_t	decryptedLen;
	int		ret;

	decryptedDer = NULL;
	decryptedLen = 0;
	if (ft_strstr(pem, "-----BEGIN ENCRYPTED PRIVATE KEY-----"))
	{
		if (!password)
			return (2);
		decryptedDer = pkcs8DecryptedDer(pem, password, &decryptedLen);
		if (!decryptedDer)
			return (0);
	}
	else
		return (0);
	ret = parsePrivateKeyInfoDer(decryptedDer, decryptedLen, key, def);
	free(decryptedDer);
	return (ret);
}

/**
 * Parse a traditional PEM-encoded private key block and decode it.
 *
 * This function searches the PEM text for the traditional private key header,
 * handles optional legacy PKCS#1 encryption using the provided password, and
 * decodes the resulting DER with the decoder specified by the key definition.
 *
 * @param pem       Null-terminated PEM text to parse.
 * @param key       Output key structure to populate on success.
 * @param def       Key definition containing labels and decode callbacks.
 * @param password  Password used to decrypt legacy encrypted PEM, or NULL.
 *
 * @return 1 on successful decode, 0 on failure, or 2 if a password is required.
 */
static int	parsePrivateTraditional(const char *pem, void *key, const t_pkeyDef *def, const char *password)
{
	t_pemBlock	block;
	char		header[128];

	ft_snprintf(header, sizeof(header),
		"-----BEGIN %s-----", def->tradPrivLabel);
	if (!ft_strstr(pem, header))
		return (0);
	if (ft_strstr(pem, "Proc-Type: 4,ENCRYPTED") != NULL)
	{
		uint8_t	*decryptedDer;
		size_t	decryptedLen;
		int		ret;

		if (!password)
			return (2);
		decryptedDer = pkcs1DecryptedDer(pem, password, &decryptedLen);
		if (!decryptedDer)
			return (0);
		ret = 0;
		if (def->decodePrivKey)
			ret = def->decodePrivKey(decryptedDer, decryptedLen, NULL, 0, key);
		free(decryptedDer);
		return (ret);
	}
	if (!pemDecode(pem, &block))
		return (0);
	if (!def->decodePrivKey)
	{
		pemFreeBlock(&block);
		return (0);
	}
	{
		int	ret;

		ret = def->decodePrivKey(block.der, block.derLen, NULL, 0, key);
		pemFreeBlock(&block);
		return (ret);
	}
}


static int	tryParseWithDef(const char *pem, t_pkey *pkey, const t_pkeyDef *def, int isPrivate, const char *password)
{
	void	*concreteKey;
	int		ret;

	concreteKey = malloc(def->keyLen);
	if (!concreteKey)
		return (0);
	ft_bzero(concreteKey, def->keyLen);
	if (isPrivate)
	{
		ret = parsePrivateEncryptedPkcs8(pem, concreteKey, def, password);
		if (ret == 0)
		{
			t_pemBlock	block;
			if (!pemDecode(pem, &block))
				return (0);
			ret = parsePrivateKeyInfoDer(block.der, block.derLen, concreteKey, def);
			pemFreeBlock(&block);
		}
		if (ret == 0)
			ret = parsePrivateTraditional(pem, concreteKey, def, password);
	}
	else
		ret = parsePublicKey(pem, concreteKey, def);
	if (ret == 1)
	{
		pkey->key = concreteKey;
		return (1);
	}
	free(concreteKey);
	return (ret);
}

int	pkeyFromPem(const char *pem, t_pkey *pkey, int isPrivate, const char *password)
{
	const t_pkeyDef	*def;
	int				ret;

	if (!pem || !pkey)
		return (0);
	def = NULL;
	if (pkey->def)
		return (tryParseWithDef(pem, pkey, pkey->def, isPrivate, password));

	{
		t_pkeyType	t;

		t = PKEY_TYPE_UNDEFINED + 1;
		while (t < PKEY_TYPE_MAX)
		{
			def = getPkeyDefByType(t);
			if (def)
			{
				ret = tryParseWithDef(pem, pkey, def, isPrivate, password);
				if (ret != 0)
				{
					pkey->def = def;
					return (ret);
				}
			}
			t++;
		}
	}
	return (0);
}
