#include <stdlib.h>

#include "../../hajlib/include/hmemory.h"
#include "../../includes/utils/utils.h"
#include "../includes/hkdf.h"

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

int	tlsRecordCtxInit(t_tlsRecordCtx		*ctx,
					 t_tlsCipherType	cipherType,
					 const uint8_t		*secret,
					 size_t				secretLen,
					 const t_hash		*hash,
					 int				isEncrypt)
{
	uint8_t	key[32];
	uint8_t	iv[12];
	size_t	keyLen;
	size_t	ivLen;
	size_t	tagLen;

	if (!ctx || !secret || !hash)
		return (0);

	if (!tlsAeadGetParams(cipherType, &keyLen, &ivLen, &tagLen))
		return (0);

	if (!tlsHkdfExpandLabel(secret, secretLen,
							TLS13_LABEL_TRAFFIC_KEY, NULL, 0,
							key, keyLen, hash))
		return (0);

	if (!tlsHkdfExpandLabel(secret, secretLen,
							TLS13_LABEL_TRAFFIC_IV, NULL, 0,
							iv, ivLen, hash))
		return (0);

	ft_bzero(ctx, sizeof(t_tlsRecordCtx));
	if (!tlsAeadCipherInit(&ctx->aeadCtx, cipherType,
						   key, keyLen, iv, ivLen,
						   isEncrypt ? CIPHER_ENCRYPT : CIPHER_DECRYPT))
	{
		secureZeroMemory(key, sizeof(key));
		secureZeroMemory(iv, sizeof(iv));
		return (0);
	}

	ctx->seqNumClient = 0;
	ctx->seqNumServer = 0;
	ctx->isEncrypt = isEncrypt;

	secureZeroMemory(key, sizeof(key));
	secureZeroMemory(iv, sizeof(iv));
	return (1);
}

void	tlsRecordCtxFree(t_tlsRecordCtx *ctx)
{
	if (!ctx)
		return;
	tlsAeadCipherFree(&ctx->aeadCtx);
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
	uint64_t	seqNum;
	uint8_t		additionalData[13];
	size_t		adLen;
	uint8_t		nonce[12];
	uint8_t		*innerPlaintext;
	size_t		innerPlainLen;
	uint8_t		*encrypted;
	uint8_t		*tag;
	size_t		encryptedLen;
	int			ret;

	if (!ctx || !output || !outputLen)
		return (0);
	if (fragmentLen > TLS_MAX_FRAGMENT_LEN - 1)  /* -1 for the type byte */
		return (0);

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
	encryptedLen = innerPlainLen + ctx->aeadCtx.tagLen;

	/* Build Additional Data (AAD) using the outer content type (0x17) */
	buildAdditionalData(TLS_RT_APPLICATION_DATA, TLS_LEGACY_VERSION, encryptedLen, additionalData, &adLen);

	/* Build per-record nonce */
	buildNonce(ctx->aeadCtx.iv, ctx->aeadCtx.ivLen, seqNum, nonce);

	/* Allocate buffer for ciphertext + tag */
	encrypted = ft_calloc(1, encryptedLen);
	if (!encrypted)
	{
		secureZeroMemory(innerPlaintext, innerPlainLen);
		free(innerPlaintext);
		return (0);
	}
	tag = encrypted + innerPlainLen;

	/* AEAD encryption */
	ret = tlsAeadSeal(ctx->aeadCtx.type,
					  ctx->aeadCtx.key, ctx->aeadCtx.keyLen,
					  nonce, ctx->aeadCtx.ivLen,
					  additionalData, adLen,
					  innerPlaintext, innerPlainLen,
					  encrypted, tag);

	secureZeroMemory(innerPlaintext, innerPlainLen);
	free(innerPlaintext);

	if (!ret)
	{
		secureZeroMemory(encrypted, encryptedLen);
		free(encrypted);
		return (0);
	}

	/* Build output record header: outer type = 0x17, version = 0x0303, length = encryptedLen */
	output[0] = TLS_RT_APPLICATION_DATA;
	output[1] = (TLS_LEGACY_VERSION >> 8) & 0xFF;
	output[2] = TLS_LEGACY_VERSION & 0xFF;
	output[3] = (encryptedLen >> 8) & 0xFF;
	output[4] = encryptedLen & 0xFF;

	ft_memcpy(output + TLS_RECORD_HEADER_SIZE, encrypted, encryptedLen);
	*outputLen = TLS_RECORD_HEADER_SIZE + encryptedLen;

	/* Update sequence number */
	if (isClient)
		ctx->seqNumClient++;
	else
		ctx->seqNumServer++;

	secureZeroMemory(nonce, sizeof(nonce));
	secureZeroMemory(additionalData, sizeof(additionalData));
	secureZeroMemory(encrypted, encryptedLen);
	free(encrypted);

	return (1);
}

#include "../../hajlib/include/hprintf.h" /* IWYU pragma: keep */

int tlsRecordDecrypt(t_tlsRecordCtx	*ctx,
					 const uint8_t	*ciphertext,	size_t	ciphertextLen,
					 int			isClient,
					 uint8_t		*fragment,		size_t	*fragmentLen,
					 uint8_t		*innerType)
{
	uint64_t		seqNum;
	uint8_t			header[5];
	uint8_t			additionalData[13];
	size_t			adLen;
	uint8_t			nonce[12];
	const uint8_t	*encrypted;
	const uint8_t	*tag;
	size_t			encryptedLen;
	size_t			innerPlainLen;
	size_t			realLen;
	uint8_t			*innerPlain;
	int				ret;

	if (!ctx || !ciphertext || !fragment || !fragmentLen || !innerType)
		{ BTLS_DEBUG("Missing decrypt parameters"); return (0); }
	if (ciphertextLen < TLS_RECORD_HEADER_SIZE + ctx->aeadCtx.tagLen)
		{ BTLS_DEBUG("Ciphertext too short"); return (0); }

	/* Extract record header */
	ft_memcpy(header, ciphertext, TLS_RECORD_HEADER_SIZE);
	encryptedLen = ((size_t)header[3] << 8) | header[4];
	
	if (ciphertextLen != TLS_RECORD_HEADER_SIZE + encryptedLen)
		{ BTLS_DEBUG("Length mismatch"); return (0); }
	if (encryptedLen < ctx->aeadCtx.tagLen + 1)
		{ BTLS_DEBUG("Encrypted length too short"); return (0); }

	encrypted = ciphertext + TLS_RECORD_HEADER_SIZE;
	innerPlainLen = encryptedLen - ctx->aeadCtx.tagLen;
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

	/* Per-record nonce */
	buildNonce(ctx->aeadCtx.iv, ctx->aeadCtx.ivLen, seqNum, nonce);

	/* AEAD decryption */
	ret = tlsAeadOpen(ctx->aeadCtx.type,
					  ctx->aeadCtx.key, ctx->aeadCtx.keyLen,
					  nonce, ctx->aeadCtx.ivLen,
					  additionalData, adLen,
					  encrypted, innerPlainLen,
					  innerPlain, tag);
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
