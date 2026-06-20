#include <stdlib.h>

#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hprintf.h" /* IWYU pragma: keep */
#include "../../includes/utils/utils.h"
#include "../includes/hkdf.h"
#include "../includes/tlsCipher.h"
#include "../includes/record.h"

static void buildAdditionalData(uint8_t		contentType,		uint16_t	legacyVersion,
								uint16_t	length,
								uint8_t		*additionalData,	size_t		*adLen)
{
	additionalData[0] = contentType;
	additionalData[1] = (legacyVersion >> 8) & 0xFF;
	additionalData[2] = legacyVersion & 0xFF;
	additionalData[3] = (length >> 8) & 0xFF;
	additionalData[4] = length & 0xFF;
	*adLen = 5;
}

/**
 * Build explicit nonce: implicit_iv XOR seq_num (left-padded to ivLen)
 * RFC 8446 Section 5.3: nonce = write_iv XOR sequence_number
 */
static void	buildNonce(const uint8_t *iv, size_t ivLen, uint64_t seqNum, uint8_t *nonce)
{
	uint8_t	seqBytes[12];
	size_t	i;

	ft_memset(seqBytes, 0, ivLen);
	for (i = 0; i < 8 && i < ivLen; i++)
		seqBytes[ivLen - 1 - i] = (seqNum >> (i * 8)) & 0xFF;

	for (i = 0; i < ivLen; i++)
		nonce[i] = iv[i] ^ seqBytes[i];
}

/**
 * @brief Derive TLS 1.3 traffic keys from a secret using HKDF
 *
 * This function derives the traffic key and IV from the given secret
 * using TLS 1.3 HKDF label expansion.
 *
 * @param secret		Traffic secret
 * @param secretLen		Length of the secret
 * @param hash			Hash algorithm for HKDF
 * @param key			Output buffer for traffic key
 * @param keyLen		Length of the traffic key
 * @param iv			Output buffer for traffic IV
 * @param ivLen			Length of the traffic IV
 * @return				1 on success, 0 on error
 */
static int	deriveTls13TrafficKeys(const uint8_t	*secret,	size_t	secretLen,
								   const t_hash		*hash,
								   uint8_t			*key,		size_t	keyLen,
								   uint8_t			*iv,		size_t	ivLen)
{
	if (!tlsHkdfExpandLabel(secret, secretLen,
							TLS13_LABEL_TRAFFIC_KEY, NULL, 0,
							key, keyLen, hash))
		return (0);

	if (!tlsHkdfExpandLabel(secret, secretLen,
							TLS13_LABEL_TRAFFIC_IV, NULL, 0,
							iv, ivLen, hash))
		return (0);

	return (1);
}

/**
 * @brief Initialize record context for TLS 1.3 with traffic secret
 *
 * This function derives encryption key and IV from the traffic secret
 * using HKDF and initializes the cipher context.
 *
 * NOTE: contrairement a une derivation implicite (direction == DECRYPT
 * => serveur), isServer doit etre fourni explicitement par l'appelant.
 * direction (ENCRYPT/DECRYPT) et role (client/serveur) sont deux notions
 * independantes : un serveur a lui aussi un contexte d'encryption
 * (avec son propre traffic secret) et un client a lui aussi un contexte
 * de decryption (avec le traffic secret du serveur). Deduire isServer
 * de la seule direction donne un resultat correct cote client mais
 * inverse cote serveur.
 *
 * @param ctx			Record context to initialize
 * @param suite			Cipher suite to use
 * @param secret		Traffic secret (clientHandshakeTrafficSecret, etc.)
 * @param secretLen		Length of the secret
 * @param hash			Hash algorithm for HKDF
 * @param direction		Direction of the record (client or server)
 * @param isServer		1 if this context belongs to the server, 0 otherwise
 * @return				1 on success, 0 on error
 */
int	tlsRecordCtxInit(t_tlsRecordCtx			*ctx,
					 const t_tlsCipherSuite	*suite,
					 const uint8_t			*secret, size_t	secretLen,
					 const t_hash			*hash,
					 t_cipherDirection		direction,
					 int					isServer)
{
	uint8_t				key[32];
	uint8_t				iv[12];
	size_t				keyLen;
	size_t				ivLen;
	const t_aeadCipher	*aead;

	if (!ctx || !suite || !secret || !hash)
		return (0);

	/* Get cipher parameters from the suite's AEAD cipher */
	aead = suite->cipher;
	if (!aead)
		return (0);

	keyLen = aead->keySize;
	ivLen = aead->ivSize;

	if (keyLen > sizeof(key) || ivLen > sizeof(iv))
		return (0);

	/* Derive traffic keys using TLS 1.3 HKDF */
	if (!deriveTls13TrafficKeys(secret, secretLen, hash,
								key, keyLen, iv, ivLen))
	{
		secureZeroMemory(key, sizeof(key));
		secureZeroMemory(iv, sizeof(iv));
		return (0);
	}

	ft_bzero(ctx, sizeof(t_tlsRecordCtx));

	/* Initialize the unified cipher context for AEAD */
	if (!tlsCipherInit(&ctx->cipher, suite,
					   key, keyLen,
					   iv, ivLen,
					   NULL, 0,  /* No MAC key for AEAD */
					   direction,
					   isServer))
	{
		secureZeroMemory(key, sizeof(key));
		secureZeroMemory(iv, sizeof(iv));
		return (0);
	}

	ctx->suite = suite;
	ctx->seqNumClient = 0;
	ctx->seqNumServer = 0;
	ctx->direction = direction;

	secureZeroMemory(key, sizeof(key));
	secureZeroMemory(iv, sizeof(iv));
	return (1);
}

/**
 * @brief Initialize record context for TLS 1.2 with direct keys
 *
 * This function initializes the cipher context with pre-derived keys
 * and IVs, suitable for TLS 1.2 where the PRF is used externally.
 *
 * @param ctx			Record context to initialize
 * @param suite			Cipher suite to use
 * @param key			Encryption key (pre-derived)
 * @param keyLen		Length of the encryption key
 * @param iv			IV/nonce (pre-derived)
 * @param ivLen			Length of the IV
 * @param macKey		MAC key (for CBC+HMAC) or NULL for AEAD
 * @param macKeyLen		Length of the MAC key
 * @param direction		Direction of the record (client or server)
 * @param isServer		1 if server, 0 if client
 * @return				1 on success, 0 on error
 */
int	tlsRecordCtxInitTls12(t_tlsRecordCtx			*ctx,
						  const t_tlsCipherSuite	*suite,
						  const uint8_t				*key,		size_t	keyLen,
						  const uint8_t				*iv,		size_t	ivLen,
						  const uint8_t				*macKey,	size_t	macKeyLen,
						  t_cipherDirection			direction,
						  int						isServer)
{
	if (!ctx || !suite || !key || !iv)
		return (0);

	ft_bzero(ctx, sizeof(t_tlsRecordCtx));

	/* Initialize the unified cipher context */
	if (!tlsCipherInit(&ctx->cipher, suite,
					   key, keyLen,
					   iv, ivLen,
					   macKey, macKeyLen,
					   direction,
					   isServer))
		return (0);

	ctx->suite = suite;
	ctx->seqNumClient = 0;
	ctx->seqNumServer = 0;
	ctx->direction = direction;

	return (1);
}

void	tlsRecordCtxFree(t_tlsRecordCtx *ctx)
{
	if (!ctx)
		return;
	tlsCipherFree(&ctx->cipher);
	ft_bzero(ctx, sizeof(t_tlsRecordCtx));
}

void	tlsRecordResetSeqNum(t_tlsRecordCtx *ctx)
{
	if (!ctx)
		return;
	ctx->seqNumClient = 0;
	ctx->seqNumServer = 0;
}

int	tlsRecordEncrypt(t_tlsRecordCtx	*ctx,
					 const uint8_t	*fragment,	size_t	fragmentLen,
					 uint8_t		innerType,
					 int			isClient,
					 uint8_t		*output,	size_t	*outputLen)
{
	uint64_t			seqNum;
	uint8_t				additionalData[13];
	size_t				adLen;
	uint8_t				nonce[12];
	uint8_t				*innerPlaintext;
	size_t				innerPlainLen;
	uint8_t				*ciphertext;
	uint8_t				*tag;
	size_t				encryptedLen;
	size_t				tagLen;
	const t_aeadCipher	*aead;
	int					ret;

	if (!ctx || !ctx->suite || !output || !outputLen)
		return (0);
	if (fragmentLen > TLS_MAX_FRAGMENT_LEN - 1)  /* -1 for the type byte */
		return (0);

	aead = ctx->suite->cipher;
	if (!aead)
		{ BTLS_DEBUG("Invalid cipher suite"); return (0); }
	tagLen = aead->tagLen;

	/* Choose sequence number based on direction */
	if (isClient)
		seqNum = ctx->seqNumClient;
	else
		seqNum = ctx->seqNumServer;

	/*
	 * TLS 1.3 inner plaintext = fragment || type || (optional padding)
	 * We build it without padding (only for handshake messages).
	 */
	innerPlainLen = fragmentLen + 1;
	innerPlaintext = ft_calloc(1, innerPlainLen);
	if (!innerPlaintext)
		return (0);

	/* Copy fragment first, then append the real content type */
	ft_memcpy(innerPlaintext, fragment, fragmentLen);
	innerPlaintext[fragmentLen] = innerType;

	/* Total length of the encrypted content (ciphertext + tag) */
	encryptedLen = innerPlainLen + tagLen;

	/* Build Additional Data (AAD) using the outer content type (0x17) */
	buildAdditionalData(TLS_RT_APPLICATION_DATA, TLS_LEGACY_VERSION, encryptedLen, additionalData, &adLen);

	/* Build per-record nonce from the cipher's IV */
	buildNonce(ctx->cipher.iv, aead->ivSize, seqNum, nonce);

	/* Allocate buffer for ciphertext + tag */
	ciphertext = ft_calloc(1, encryptedLen);
	if (!ciphertext)
	{
		secureZeroMemory(innerPlaintext, innerPlainLen);
		free(innerPlaintext);
		return (0);
	}
	tag = ciphertext + innerPlainLen;

	/* AEAD encryption using the unified cipher (nonce is mandatory:
	 * it is recomputed per-record above via buildNonce()) */
	ret = tlsCipherSeal(&ctx->cipher,
						nonce, aead->ivSize,
						additionalData, adLen,
						innerPlaintext, innerPlainLen,
						ciphertext, tag);

	secureZeroMemory(innerPlaintext, innerPlainLen);
	free(innerPlaintext);

	if (!ret)
	{
		secureZeroMemory(ciphertext, encryptedLen);
		free(ciphertext);
		return (0);
	}

	/* Build output record header: outer type = 0x17, version = 0x0303, length = encryptedLen */
	output[0] = TLS_RT_APPLICATION_DATA;
	output[1] = (TLS_LEGACY_VERSION >> 8) & 0xFF;
	output[2] = TLS_LEGACY_VERSION & 0xFF;
	output[3] = (encryptedLen >> 8) & 0xFF;
	output[4] = encryptedLen & 0xFF;

	ft_memcpy(output + TLS_RECORD_HEADER_SIZE, ciphertext, encryptedLen);
	*outputLen = TLS_RECORD_HEADER_SIZE + encryptedLen;

	/* Update sequence number */
	if (isClient)
		ctx->seqNumClient++;
	else
		ctx->seqNumServer++;

	secureZeroMemory(nonce, sizeof(nonce));
	secureZeroMemory(additionalData, sizeof(additionalData));
	secureZeroMemory(ciphertext, encryptedLen);
	free(ciphertext);

	return (1);
}

int tlsRecordDecrypt(t_tlsRecordCtx	*ctx,
					 const uint8_t	*ciphertext,	size_t	ciphertextLen,
					 int			isClient,
					 uint8_t		*fragment,		size_t	*fragmentLen,
					 uint8_t		*innerType)
{
	uint64_t			seqNum;
	uint8_t				header[5];
	uint8_t				additionalData[13];
	size_t				adLen;
	uint8_t				nonce[12];
	const uint8_t		*encrypted;
	const uint8_t		*tag;
	size_t				encryptedLen;
	size_t				innerPlainLen;
	size_t				tagLen;
	size_t				realLen;
	uint8_t				*innerPlain;
	const t_aeadCipher	*aead;
	int					ret;

	if (!ctx || !ctx->suite || !ciphertext || !fragment || !fragmentLen || !innerType)
		{ BTLS_DEBUG("Missing decrypt parameters"); return (0); }

	/* Get tag length from the suite's AEAD cipher (no silent fallback) */
	aead = ctx->suite->cipher;
	if (!aead)
		{ BTLS_DEBUG("Invalid cipher suite"); return (0); }
	tagLen = aead->tagLen;

	if (ciphertextLen < TLS_RECORD_HEADER_SIZE + tagLen)
		{ BTLS_DEBUG("Ciphertext too short"); return (0); }

	/* Extract record header */
	ft_memcpy(header, ciphertext, TLS_RECORD_HEADER_SIZE);
	encryptedLen = ((size_t)header[3] << 8) | header[4];

	if (ciphertextLen != TLS_RECORD_HEADER_SIZE + encryptedLen)
		{ BTLS_DEBUG("Length mismatch"); return (0); }
	if (encryptedLen < tagLen + 1)
		{ BTLS_DEBUG("Encrypted length too short"); return (0); }

	encrypted = ciphertext + TLS_RECORD_HEADER_SIZE;
	innerPlainLen = encryptedLen - tagLen;
	tag = encrypted + innerPlainLen;

	innerPlain = ft_calloc(1, innerPlainLen);
	if (!innerPlain)
		{ BTLS_DEBUG("Memory allocation failed"); return (0); }

	/* Determine sequence number */
	if (isClient)
		seqNum = ctx->seqNumServer;   /* client reads server's messages */
	else
		seqNum = ctx->seqNumClient;

	adLen = TLS_RECORD_HEADER_SIZE;
	ft_memcpy(additionalData, header, adLen);

	/* Per-record nonce from the cipher's IV */
	buildNonce(ctx->cipher.iv, aead->ivSize, seqNum, nonce);

	/* AEAD decryption using the unified cipher (nonce is mandatory:
	 * it is recomputed per-record above via buildNonce()) */
	ret = tlsCipherOpen(&ctx->cipher,
						nonce, aead->ivSize,
						additionalData, adLen,
						encrypted, innerPlainLen,
						tag, tagLen,
						innerPlain);
	if (!ret)
	{
		secureZeroMemory(innerPlain, innerPlainLen);
		free(innerPlain);
		{ BTLS_DEBUG("AEAD decryption failed"); return (0); }
	}

	realLen = innerPlainLen;
	while (realLen > 0 && innerPlain[realLen - 1] == 0x00) /* Remove padding */
		realLen--;

	if (realLen == 0)
	{
		secureZeroMemory(innerPlain, innerPlainLen);
		free(innerPlain);
		{ BTLS_DEBUG("Inner plaintext is only padding"); return (0); }
	}

	*innerType = innerPlain[realLen - 1];
	*fragmentLen = realLen - 1;
	ft_memcpy(fragment, innerPlain, *fragmentLen);

	secureZeroMemory(innerPlain, innerPlainLen);
	free(innerPlain);

	/* Update sequence number */
	if (isClient)
		ctx->seqNumServer++;
	else
		ctx->seqNumClient++;

	return (1);
}

int	tlsRecordBuild(uint8_t contentType, const uint8_t *data, size_t dataLen, t_tlsRecord *record)
{
	if (!record || dataLen > TLS_MAX_FRAGMENT_LEN)
		return (0);

	record->header.contentType = contentType;
	record->header.legacyVersion = TLS_LEGACY_VERSION;
	record->header.length = dataLen;
	record->fragmentLen = dataLen;
	record->fragment = ft_calloc(1, dataLen ? dataLen : 1);
	if (!record->fragment && dataLen > 0)
		return (0);
	if (data && dataLen > 0)
		ft_memcpy(record->fragment, data, dataLen);
	return (1);
}

void	tlsRecordFree(t_tlsRecord *record)
{
	if (!record)
		return;
	free(record->fragment);
	record->fragment = NULL;
	record->fragmentLen = 0;
	ft_bzero(&record->header, sizeof(record->header));
}
