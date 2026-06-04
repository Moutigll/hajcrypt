#include <stdlib.h>

#include "../../hajlib/include/hmemory.h"
#include "../../includes/utils/utils.h"

#include "../includes/hkdf.h"

#include "../includes/record.h"

/**
 * Additional data for AEAD: seq_num (8) || content_type (1) || legacy_version (2) || length (2)
 * Total: 13 bytes (RFC 8446 Section 5.2)
 */
static void	buildAdditionalData(uint64_t	seqNum,
							   uint8_t		contentType,
							   uint16_t		legacyVersion,
							   uint16_t		length,
							   uint8_t		*additionalData,
							   size_t		*adLen)
{
	uint8_t	*ptr = additionalData;
	int		i;

	/* Sequence number (8 bytes, big endian) */
	for (i = 0; i < 8; i++)
		ptr[7 - i] = (seqNum >> (i * 8)) & 0xFF;
	ptr += 8;

	/* Content type */
	*ptr++ = contentType;

	/* Legacy version (0x0303) */
	*ptr++ = (legacyVersion >> 8) & 0xFF;
	*ptr++ = legacyVersion & 0xFF;

	/* Length */
	*ptr++ = (length >> 8) & 0xFF;
	*ptr++ = length & 0xFF;

	*adLen = 13;
}

/**
 * Build explicit nonce: implicit_iv XOR seq_num (left-padded to ivLen)
 * RFC 8446 Section 5.3: nonce = client_iv XOR sequence_number
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
					 const t_hashAlgo	*hash)
{
	uint8_t	key[32];
	uint8_t	iv[12];
	size_t	keyLen;
	size_t	ivLen;
	size_t	tagLen;

	if (!ctx || !secret || !hash)
		return (0);

	/* Get cipher parameters */
	if (!tlsAeadGetParams(cipherType, &keyLen, &ivLen, &tagLen))
		return (0);

	/* Derive key: HKDF-Expand-Label(secret, "key", "", keyLen) */
	if (!tlsHkdfExpandLabel(secret, secretLen,
							TLS13_LABEL_TRAFFIC_KEY, NULL, 0,
							key, keyLen, hash))
		return (0);

	/* Derive IV: HKDF-Expand-Label(secret, "iv", "", ivLen) */
	if (!tlsHkdfExpandLabel(secret, secretLen,
							TLS13_LABEL_TRAFFIC_IV, NULL, 0,
							iv, ivLen, hash))
		return (0);

	/* Initialize AEAD cipher context */
	ft_bzero(ctx, sizeof(t_tlsRecordCtx));
	if (!tlsAeadCipherInit(&ctx->aeadCtx, cipherType,
						   key, keyLen, iv, ivLen, CIPHER_ENCRYPT))
	{
		secureZeroMemory(key, sizeof(key));
		secureZeroMemory(iv, sizeof(iv));
		return (0);
	}

	ctx->seqNumClient = 0;
	ctx->seqNumServer = 0;

	secureZeroMemory(key, sizeof(key));
	secureZeroMemory(iv, sizeof(iv));

	return (1);
}

void	tlsRecordCtxFree(t_tlsRecordCtx *ctx)
{
	if (!ctx)
		return ;

	tlsAeadCipherFree(&ctx->aeadCtx);
	ft_bzero(ctx, sizeof(t_tlsRecordCtx));
}

void	tlsRecordResetSeqNum(t_tlsRecordCtx *ctx)
{
	if (!ctx)
		return ;
	ctx->seqNumClient = 0;
	ctx->seqNumServer = 0;
}

int	tlsRecordEncrypt(t_tlsRecordCtx		*ctx,
					 const t_tlsRecord	*record,
					 int				isClient,
					 uint8_t			*output,
					 size_t				*outputLen)
{
	uint64_t		seqNum;
	uint8_t			additionalData[13];
	size_t			adLen;
	uint8_t			nonce[12];
	uint8_t			*encrypted;
	uint8_t			*tag;
	size_t			encryptedLen;
	int				ret;

	if (!ctx || !record || !output || !outputLen)
		return (0);
	if (record->fragmentLen > TLS_MAX_FRAGMENT_LEN)
		return (0);

	/* Select sequence number based on direction */
	if (isClient)
		seqNum = ctx->seqNumClient;
	else
		seqNum = ctx->seqNumServer;

	/* Build additional data */
	buildAdditionalData(seqNum,
						record->header.contentType,
						record->header.legacyVersion,
						record->fragmentLen,
						additionalData, &adLen);

	/* Build nonce (implicit_iv XOR seq_num) */
	buildNonce(ctx->aeadCtx.iv, ctx->aeadCtx.ivLen, seqNum, nonce);

	/* Output buffer size = fragment_len + tag_len */
	encryptedLen = record->fragmentLen + ctx->aeadCtx.tagLen;
	encrypted = ft_calloc(1, encryptedLen);
	if (!encrypted)
		return (0);
	tag = encrypted + record->fragmentLen;

	/* Perform AEAD encryption using one-shot seal */
	ret = tlsAeadSeal(ctx->aeadCtx.type,
					  ctx->aeadCtx.key, ctx->aeadCtx.keyLen,
					  nonce, ctx->aeadCtx.ivLen,
					  additionalData, adLen,
					  record->fragment, record->fragmentLen,
					  encrypted, tag);

	if (!ret)
	{
		secureZeroMemory(encrypted, encryptedLen);
		free(encrypted);
		return (0);
	}

	/* Build output record: header + encrypted data + tag */
	output[0] = record->header.contentType;
	output[1] = (record->header.legacyVersion >> 8) & 0xFF;
	output[2] = record->header.legacyVersion & 0xFF;
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

int	tlsRecordDecrypt(t_tlsRecordCtx	*ctx,
					 const uint8_t	*ciphertext,
					 size_t			ciphertextLen,
					 int			isClient,
					 uint8_t		*output,
					 size_t			*outputLen)
{
	uint64_t		seqNum;
	uint8_t			header[5];
	uint8_t			additionalData[13];
	size_t			adLen;
	uint8_t			nonce[12];
	const uint8_t	*encrypted;
	const uint8_t	*tag;
	size_t			encryptedLen;
	size_t			plaintextLen;
	int				ret;

	if (!ctx || !ciphertext || !output || !outputLen)
		return (0);
	if (ciphertextLen < TLS_RECORD_HEADER_SIZE + ctx->aeadCtx.tagLen)
		return (0);

	/* Extract header */
	ft_memcpy(header, ciphertext, TLS_RECORD_HEADER_SIZE);

	encryptedLen = ((size_t)header[3] << 8) | header[4];
	if (ciphertextLen != TLS_RECORD_HEADER_SIZE + encryptedLen)
		return (0);
	if (encryptedLen < ctx->aeadCtx.tagLen)
		return (0);

	encrypted = ciphertext + TLS_RECORD_HEADER_SIZE;
	plaintextLen = encryptedLen - ctx->aeadCtx.tagLen;
	tag = encrypted + plaintextLen;

	/* Select sequence number based on direction */
	if (isClient)
		seqNum = ctx->seqNumServer;
	else
		seqNum = ctx->seqNumClient;

	/* Build additional data */
	buildAdditionalData(seqNum,
						header[0],
						((uint16_t)header[1] << 8) | header[2],
						plaintextLen,
						additionalData, &adLen);

	/* Build nonce */
	buildNonce(ctx->aeadCtx.iv, ctx->aeadCtx.ivLen, seqNum, nonce);

	/* Perform AEAD decryption using one-shot open */
	ret = tlsAeadOpen(ctx->aeadCtx.type,
					  ctx->aeadCtx.key, ctx->aeadCtx.keyLen,
					  nonce, ctx->aeadCtx.ivLen,
					  additionalData, adLen,
					  encrypted, plaintextLen,
					  output, tag);

	if (!ret)
		return (0);

	*outputLen = plaintextLen;

	/* Update sequence number */
	if (isClient)
		ctx->seqNumServer++;
	else
		ctx->seqNumClient++;

	secureZeroMemory(nonce, sizeof(nonce));
	secureZeroMemory(additionalData, sizeof(additionalData));

	return (1);
}

int	tlsRecordBuild(uint8_t			contentType,
				   const uint8_t	*data,
				   size_t			dataLen,
				   t_tlsRecord		*record)
{
	if (!record)
		return (0);
	if (dataLen > TLS_MAX_FRAGMENT_LEN)
		return (0);

	record->header.contentType = contentType;
	record->header.legacyVersion = TLS_LEGACY_VERSION;
	record->header.length = dataLen;

	record->fragmentLen = dataLen;
	record->fragment = ft_calloc(1, dataLen);
	if (!record->fragment && dataLen > 0)
		return (0);

	if (data && dataLen > 0)
		ft_memcpy(record->fragment, data, dataLen);

	return (1);
}

void	tlsRecordFree(t_tlsRecord *record)
{
	if (!record)
		return ;

	if (record->fragment)
	{
		secureZeroMemory(record->fragment, record->fragmentLen);
		free(record->fragment);
		record->fragment = NULL;
	}

	record->fragmentLen = 0;
	record->header.contentType = 0;
	record->header.legacyVersion = 0;
	record->header.length = 0;
}
