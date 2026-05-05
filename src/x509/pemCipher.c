#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"
#include "../../includes/utils/dispatch.h"
#include "../../includes/x509/asn1.h"
#include "../../includes/hash/md5.h"

#include "../../includes/x509/pemCipher.h"

void pkcs1KeyDerivation(const char *password, const uint8_t *salt, uint8_t *key, size_t keySize)
{
	t_md5Ctx	ctx;
	uint8_t		md5Digest[16];
	uint8_t		*keyPos = key;
	size_t		keyRemaining = keySize;
	
	if (keySize <= 16) {
		md5Init(&ctx);
		md5Update(&ctx, (const uint8_t *)password, ft_strlen(password));
		md5Update(&ctx, salt, 8);
		md5Final(key, &ctx);
	} else {
		uint8_t	prevHash[16] = {0};
		int		first = 1;
		
		while (keyRemaining > 0) {
			md5Init(&ctx);
			md5Update(&ctx, (const uint8_t *)password, ft_strlen(password));
			md5Update(&ctx, salt, 8);
			
			if (!first)
				md5Update(&ctx, prevHash, 16);
			
			md5Final(md5Digest, &ctx);

			ft_memcpy(prevHash, md5Digest, 16);

			size_t toCopy = (keyRemaining < 16) ? keyRemaining : 16;
			ft_memcpy(keyPos, md5Digest, toCopy);
			keyPos += toCopy;
			keyRemaining -= toCopy;
			first = 0;
		}
	}
}

uint8_t *encryptDerWithCipher(const t_cipher	*cipher,
							  const uint8_t		*key,
							  const uint8_t		*iv,
							  const uint8_t		*der,
							  size_t			derLen,
							  size_t			*outLen)
{
	void	*ctx;
	uint8_t	*enc;
	size_t	processed = 0;
	size_t	finalLen = 0;

	if (!cipher || !key || !der || !outLen)
		return (NULL);

	ctx = malloc(cipher->ctxSize);
	if (!ctx)
		return (NULL);

	if (cipher->init(ctx, key, cipher->keySize,
					 cipher->ivSize > 0 ? iv : NULL,
					 CIPHER_ENCRYPT) != 0) {
		free(ctx);
		return (NULL);
	}

	enc = malloc(derLen + cipher->blockSize);
	if (!enc) {
		cipher->free(ctx);
		free(ctx);
		return (NULL);
	}

	cipher->update(ctx, der, derLen, enc, &processed);
	cipher->final(ctx, enc + processed, &finalLen);
	*outLen = processed + finalLen;

	cipher->free(ctx);
	free(ctx);
	return (enc);
}

uint8_t *decryptDerWithCipher(const t_cipher	*cipher,
							  const uint8_t		*key,
							  const uint8_t		*iv,
							  const uint8_t		*encDer,
							  size_t			encLen,
							  size_t			*outLen)
{
	void	*ctx;
	uint8_t	*dec;
	size_t	processed = 0;
	size_t	finalLen = 0;

	if (!cipher || !key || !encDer || !outLen)
		return (NULL);

	ctx = malloc(cipher->ctxSize);
	if (!ctx)
		return (NULL);

	if (cipher->init(ctx, key, cipher->keySize,
					 cipher->ivSize > 0 ? iv : NULL,
					 CIPHER_DECRYPT) != 0) {
		free(ctx);
		return (NULL);
	}

	dec = malloc(encLen);
	if (!dec) {
		cipher->free(ctx);
		free(ctx);
		return (NULL);
	}

	cipher->update(ctx, encDer, encLen, dec, &processed);
	cipher->final(ctx, dec + processed, &finalLen);
	*outLen = processed + finalLen;

	if (cipher->unpad) {
		if (cipher->unpad(dec, outLen, cipher->blockSize) != 0) {
			cipher->free(ctx);
			free(ctx);
			free(dec);
			return (NULL);
		}
	}

	cipher->free(ctx);
	free(ctx);
	return (dec);
}

/**
 * @brief Builds ASN.1 parameters for PBKDF2 KDF based on the provided parameters structure.
 * This is used for PKCS#8 encryption to include the KDF parameters in the PEM header.
 * 
 * @param params	Pointer to a t_pkcs8Params structure containing the KDF parameters
 * @param outLen	Output parameter that will receive the length of the encoded parameters
 * 
 * @return		  Pointer to a newly allocated buffer containing the ASN.1 DER encoding of the PBKDF2 parameters, or NULL on error
 */
static uint8_t *buildPbkdf2Params(const t_pkcs8Params *params, size_t *outLen)
{
	uint8_t	*saltDer,	*iterDer;
	uint8_t	*prfOidDer,	*prfNullDer, *prfSeq;
	uint8_t	*elements[5];
	size_t	lens[5];
	size_t	count = 0;
	uint8_t	iterBytes[4];
	size_t	iterLen;

	/* Salt */
	saltDer = asn1EncodeOctetString(params->salt, params->saltLen, &lens[count]);
	if (!saltDer) return (NULL);
	elements[count++] = saltDer;

	/* Iterations */
	iterLen = 1;
	if (params->iterations > 255) iterLen = 2;
	if (params->iterations > 65535) iterLen = 3;
	if (params->iterations > 16777215) iterLen = 4;
	for (size_t i = 0; i < iterLen; i++)
		iterBytes[i] = (params->iterations >> (8 * (iterLen - 1 - i))) & 0xFF;
	iterDer = asn1EncodeInteger(iterBytes, iterLen, &lens[count]);
	if (!iterDer) {
		free(saltDer);
		return (NULL);
	}
	elements[count++] = iterDer;

	/* PRF (HMAC-SHA256) */
	prfOidDer = asn1EncodeOid(hmacSha256Oid, sizeof(hmacSha256Oid), &lens[count]);
	if (prfOidDer) {
		prfNullDer = asn1EncodeNull(&lens[count + 1]);
		if (prfNullDer) {
			prfSeq = asn1EncodeSequence(
						(uint8_t*[]){prfOidDer, prfNullDer},
						(size_t[]){lens[count], lens[count + 1]},
						2, &lens[count]);	// réutilise lens[count] pour la longueur de la séquence
			free(prfOidDer);
			free(prfNullDer);
			if (prfSeq) {
				elements[count++] = prfSeq;
			}
		} else {
			free(prfOidDer);
		}
	}

	uint8_t *seq = asn1EncodeSequence(elements, lens, count, outLen);
	for (size_t i = 0; i < count; i++)
		free(elements[i]);
	return (seq);
}



uint8_t *buildPbes2Algo(const t_cipher		*cipher,
						const t_pkcs8Params	*params,
						size_t				*outLen)
{
	uint8_t *kdfOid = NULL, *kdfParams = NULL, *kdfSeq = NULL;
	uint8_t *encOid = NULL, *encParams = NULL, *encSeq = NULL;
	uint8_t *pbes2Params = NULL, *pbes2OidEnc = NULL, *algoSeq = NULL;
	size_t   kdfOidLen, kdfParamsLen, kdfSeqLen;		// séparation des longueurs
	size_t   encOidLen, encParamsLen, encLen;
	size_t   pbes2ParamsLen, pbes2OidLen;

	/* 1. KDF : OID PBKDF2 + PBKDF2-params */
	kdfOid = asn1EncodeOid(pkcs5Pbkdf2Oid, sizeof(pkcs5Pbkdf2Oid), &kdfOidLen);
	if (!kdfOid) goto cleanup;

	kdfParams = buildPbkdf2Params(params, &kdfParamsLen);
	if (!kdfParams) goto cleanup;

	kdfSeq = asn1EncodeSequence(
		(uint8_t*[]){kdfOid, kdfParams},
		(size_t[]){kdfOidLen, kdfParamsLen},
		2, &kdfSeqLen);
	if (!kdfSeq) goto cleanup;

	/* 2. EncryptionScheme : OID du cipher + IV dans OCTET STRING */
	if (cipher->oid.len == 0)
	{
		ft_dprintf(STDERR_FILENO, "[ERROR] Unsupported cipher for PBES2: %s\n", cipher->name);
		goto cleanup;
	}

	encOid = asn1EncodeOid(cipher->oid.data, cipher->oid.len, &encOidLen);
	if (!encOid) goto cleanup;

	encParams = asn1EncodeOctetString(params->iv, params->ivLen, &encParamsLen);
	if (!encParams) goto cleanup;

	encSeq = asn1EncodeSequence(
		(uint8_t*[]){encOid, encParams},
		(size_t[]){encOidLen, encParamsLen},
		2, &encLen);
	if (!encSeq) goto cleanup;

	/* 3. PBES2-params : SEQUENCE { KDF, EncryptionScheme } */
	pbes2Params = asn1EncodeSequence(
		(uint8_t*[]){kdfSeq, encSeq},
		(size_t[]){kdfSeqLen, encLen},
		2, &pbes2ParamsLen);
	if (!pbes2Params) goto cleanup;

	/* 4. OID PBES2 */
	pbes2OidEnc = asn1EncodeOid(pkcs5Pbes2Oid, sizeof(pkcs5Pbes2Oid), &pbes2OidLen);
	if (!pbes2OidEnc) goto cleanup;

	/* 5. AlgorithmIdentifier final : SEQUENCE { OID PBES2, PBES2-params } */
	algoSeq = asn1EncodeSequence(
		(uint8_t*[]){pbes2OidEnc, pbes2Params},
		(size_t[]){pbes2OidLen, pbes2ParamsLen},
		2, outLen);

cleanup:
	free(kdfOid);
	free(kdfParams);
	free(kdfSeq);
	free(encOid);
	free(encParams);
	free(encSeq);
	free(pbes2Params);
	free(pbes2OidEnc);
	return (algoSeq);
}

int parsePbes2Params(const uint8_t	*algoDer,
					size_t			algoLen,
					const t_cipher	**cipher,
					t_pkcs8Params	*params)
{
	uint8_t	*seqContent, *pbes2Params, *kdfIdContent, *pbkdf2SubParams;
	uint8_t	*encSchemeContent, *oid, *saltVal, *iterVal, *encOid, *ivVal;
	size_t	seqContentLen, pbes2ParamsLen, kdfIdLen, pbkdf2SubParamsLen, encSchemeLen;
	size_t	oidLen, sLen, iterValLen, encOidLen, iLen;
	size_t	consumed = 0;

	/* --- Outer SEQUENCE (AlgorithmIdentifier) --- */
	if (algoDer[0] == 0x30) {
		if (!asn1ParseSequence(algoDer, algoLen, &seqContent, &seqContentLen, NULL))
			return (HAJCRYPT_DPRINT("PKCS#8: invalid outer sequence\n"), 0);
	} else if (algoDer[0] == 0x06) {
		seqContent = (uint8_t *)algoDer;
		seqContentLen = algoLen;
	} else
		return (HAJCRYPT_DPRINT("PKCS#8: invalid start tag 0x%02X\n", algoDer[0]), 0);

	/* --- PBES2 OID --- */
	if (!asn1ParseOid(seqContent, seqContentLen, &oid, &oidLen, &consumed))
		return (HAJCRYPT_DPRINT("PKCS#8: PBES2 OID not found\n"), 0);
	if (oidLen != sizeof(pkcs5Pbes2Oid) || ft_memcmp(oid, pkcs5Pbes2Oid, oidLen) != 0)
		return (HAJCRYPT_DPRINT("PKCS#8: not a PBES2 OID\n"), 0);

	/* --- PBES2 params SEQUENCE --- */
	if (!asn1ParseSequence(seqContent + consumed, seqContentLen - consumed, &pbes2Params, &pbes2ParamsLen, NULL))
		return (HAJCRYPT_DPRINT("PKCS#8: PBES2 params sequence missing\n"), 0);

	/* --- KDF AlgorithmIdentifier --- */
	consumed = 0;
	if (!asn1ParseSequence(pbes2Params, pbes2ParamsLen, &kdfIdContent, &kdfIdLen, &consumed))
		return (HAJCRYPT_DPRINT("PKCS#8: KDF AlgorithmIdentifier missing\n"), 0);

	/* Parse KDF OID from the KDF AlgorithmIdentifier */
	size_t kdfConsumed = 0;
	if (!asn1ParseOid(kdfIdContent, kdfIdLen, &oid, &oidLen, &kdfConsumed))
		return (HAJCRYPT_DPRINT("PKCS#8: KDF OID not found\n"), 0);
	if (oidLen != sizeof(pkcs5Pbkdf2Oid) || ft_memcmp(oid, pkcs5Pbkdf2Oid, oidLen) != 0)
		return (HAJCRYPT_DPRINT("PKCS#8: KDF is not PBKDF2\n"), 0);

	/* --- PBKDF2-params SEQUENCE --- */
	if (!asn1ParseSequence(kdfIdContent + kdfConsumed, kdfIdLen - kdfConsumed, &pbkdf2SubParams, &pbkdf2SubParamsLen, NULL))
		return (HAJCRYPT_DPRINT("PKCS#8: PBKDF2-params missing\n"), 0);

	/* --- Salt --- */
	size_t pbkdf2Consumed = 0;
	if (!asn1ParseOctetString(pbkdf2SubParams, pbkdf2SubParamsLen, &saltVal, &sLen, &pbkdf2Consumed))
		return (HAJCRYPT_DPRINT("PKCS#8: salt missing\n"), 0);
	if (sLen > sizeof(params->salt))
		return (HAJCRYPT_DPRINT("PKCS#8: salt too long (%zu > %zu)\n", sLen, sizeof(params->salt)), 0);
	ft_memcpy(params->salt, saltVal, sLen);
	params->saltLen = sLen;

	/* --- Iteration count --- */
	if (!asn1ParseInteger(pbkdf2SubParams + pbkdf2Consumed, pbkdf2SubParamsLen - pbkdf2Consumed, &iterVal, &iterValLen, NULL))
		return (HAJCRYPT_DPRINT("PKCS#8: iteration count missing\n"), 0);
	params->iterations = 0;
	for (size_t i = 0; i < iterValLen; i++)
		params->iterations = (params->iterations << 8) | iterVal[i];

	/* Move to the encryption scheme part (second element of PBES2 params) */
	size_t encStart = consumed;  // consumed from parsing the KDF sequence
	if (!asn1ParseSequence(pbes2Params + encStart, pbes2ParamsLen - encStart, 
						   &encSchemeContent, &encSchemeLen, NULL))
		return (HAJCRYPT_DPRINT("PKCS#8: encryption scheme missing\n"), 0);

	/* --- Cipher OID --- */
	size_t encConsumed = 0;
	if (!asn1ParseOid(encSchemeContent, encSchemeLen, &encOid, &encOidLen, &encConsumed))
		return (HAJCRYPT_DPRINT("PKCS#8: encryption OID missing\n"), 0);

	*cipher = getCipherByOid(encOid, encOidLen);
	if (!*cipher) {
		HAJCRYPT_DPRINT("PKCS#8: unknown or unsupported cipher OID: ");
		for (size_t i = 0; i < encOidLen; i++)
			HAJCRYPT_DPRINT("%02X", encOid[i]);
		HAJCRYPT_DPRINT("\n");
		return (0);
	}

	/* --- IV --- */
	if (!asn1ParseOctetString(encSchemeContent + encConsumed, encSchemeLen - encConsumed, &ivVal, &iLen, NULL))
		return (HAJCRYPT_DPRINT("PKCS#8: IV missing\n"), 0);
	if (iLen > sizeof(params->iv))
		return (HAJCRYPT_DPRINT("PKCS#8: IV too long\n"), 0);
	ft_memcpy(params->iv, ivVal, iLen);
	params->ivLen = iLen;

	return (1);
}
