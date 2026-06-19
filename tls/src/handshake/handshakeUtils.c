#include "../../../hajlib/include/hstring.h"
#include "../../../includes/utils/utils.h"

#include "../../includes/handshake.h"

void tlsHandshakeFree(t_tlsHandshakeCtx *ctx)
{
	if (!ctx)
		return;

	/* Free key exchange context */
	if (ctx->keyExchangeCtx)
	{
		kexFree(ctx->keyExchangeCtx);
		free(ctx->keyExchangeCtx);
		ctx->keyExchangeCtx = NULL;
	}

	/* Free ephemeral key shares */
	if (ctx->keyExchangeCtx)
	{
		kexFree(ctx->keyExchangeCtx);
		free(ctx->keyExchangeCtx);
		ctx->keyExchangeCtx = NULL;
	}

	/* Free record protection contexts */
	tlsRecordCtxFree(&ctx->handshakeSendCtx);
	tlsRecordCtxFree(&ctx->handshakeRecvCtx);
	tlsRecordCtxFree(&ctx->appSendCtx);
	tlsRecordCtxFree(&ctx->appRecvCtx);

	/* Securely zero all secrets */
	secureZeroMemory(&ctx->secrets, sizeof(ctx->secrets));
	secureZeroMemory(ctx->sharedSecret, sizeof(ctx->sharedSecret));
	secureZeroMemory(ctx->transcript, sizeof(ctx->transcript));

	ctx->sharedSecretLen = 0;
	ctx->state = TLS_HS_STATE_IDLE;
}

int transcriptUpdateRaw(t_tlsHandshakeCtx *ctx, const uint8_t *fullHandshakeMsg, size_t fullLen)
{
	if (!ctx || !fullHandshakeMsg || !ctx->transcriptHash.update)
		return (0);
	ctx->transcriptHash.update(ctx->transcript, fullHandshakeMsg, fullLen);
	return (1);
}

int transcriptUpdate(t_tlsHandshakeCtx *ctx, uint8_t msgType, const uint8_t *body, size_t bodyLen)
{
	uint8_t	*encoded;
	size_t	encodedLen;

	if (!ctx || !ctx->transcriptHash.update)
		return (0);

	encoded = malloc(4 + bodyLen);
	if (!encoded)
		return (0);

	if (!handshakeEncode(msgType, body, bodyLen, encoded, &encodedLen)) {
		free(encoded);
		return (0);
	}

	ctx->transcriptHash.update(ctx->transcript, encoded, encodedLen);
	
	free(encoded);
	return (1);
}

void transcriptGetHash(t_tlsHandshakeCtx *ctx, uint8_t *out)
{
	uint8_t tmpCtx[HASH_MAX_CTX_SIZE];
	size_t hashLen;

	if (!ctx || !out || !ctx->transcriptHash.final)
		return;

	hashLen = ctx->transcriptHash.digestSize;

	/*
	 * Clone the current hash state, finalize the clone to get the digest,
	 * leaving the original state intact for future transcriptUpdate() calls.
	 */
	ft_memcpy(tmpCtx, ctx->transcript, ctx->transcriptHash.ctxSize);
	ctx->transcriptHash.final(out, tmpCtx);

	/* Ensure the rest of the output buffer is zeroed */
	if (hashLen < 64)
		ft_bzero(out + hashLen, 64 - hashLen);
}


int handshakeEncode(uint8_t msgType, const uint8_t *body, size_t bodyLen, uint8_t *out, size_t *outLen)
{
	if (!out || !outLen || bodyLen > 0xFFFFFF)
		return (0);

	out[0] = msgType;
	out[1] = (bodyLen >> 16) & 0xFF;
	out[2] = (bodyLen >> 8) & 0xFF;
	out[3] = bodyLen & 0xFF;

	if (body && bodyLen)
		ft_memcpy(out + 4, body, bodyLen);

	*outLen = 4 + bodyLen;
	return (1);
}

int handshakeDecode(const uint8_t *data, size_t dataLen, uint8_t *msgType, const uint8_t **body, size_t *bodyLen)
{
	if (!data || dataLen < 4)
		return (0);

	*msgType = data[0];
	*bodyLen = ((size_t)data[1] << 16) | ((size_t)data[2] << 8) | data[3];

	if (4 + *bodyLen > dataLen)
		return (0);

	*body = data + 4;
	return (1);
}

int tlsReadHandshakeMessage(t_tlsCtx *ctx, uint8_t *msg, size_t *msgLen, int encrypted)
{
	uint8_t rawData[TLS_MAX_FRAGMENT_LEN + TLS_RECORD_HEADER_SIZE + 256];
	size_t  rawLen = sizeof(rawData);

	int ret = tlsIoReadRecord(&ctx->io, rawData, &rawLen);
	if (ret <= 0) return (ret);

	uint8_t	contentType = rawData[0];
	uint8_t	*payload = rawData + TLS_RECORD_HEADER_SIZE;
	size_t	payloadLen = rawLen - TLS_RECORD_HEADER_SIZE;

	if (contentType == TLS_RT_ALERT)
		return (tlsHandleAlert(ctx, payload, payloadLen) < 0 ? TLS_ERR_PROTOCOL : 0);

	if (contentType == TLS_RT_CHANGE_CIPHER_SPEC)
		return (tlsReadHandshakeMessage(ctx, msg, msgLen, encrypted)); /* Ignore CCS and read the next record */

	if (contentType != TLS_RT_HANDSHAKE) {
		tlsSetError(ctx, TLS_ERR_PROTOCOL, "Expected handshake record");
		return (TLS_ERR_PROTOCOL);
	}

	if (encrypted) {
		uint8_t	plaintext[TLS_MAX_FRAGMENT_LEN + 1];
		size_t	plainLen = sizeof(plaintext);
		uint8_t	innerType = 0;

		if (!tlsRecordDecrypt(&ctx->handshake.handshakeRecvCtx,
							  rawData, rawLen, 1, 
							  plaintext, &plainLen, &innerType)) {
			return (TLS_ERR_DECRYPT);
		}
		ft_memcpy(msg, plaintext, plainLen);
		*msgLen = plainLen;
	} else {
		ft_memcpy(msg, payload, payloadLen);
		*msgLen = payloadLen;
	}
	return (1);
}

int tls13SendEncryptedMessage(t_tlsCtx *ctx, const uint8_t *msg, size_t msgLen, uint8_t contentType)
{
	if (!ctx || !msg || !msgLen)
		return (TLS_ERR_INTERNAL);

	uint8_t	encrypted[TLS_MAX_FRAGMENT_LEN + 256];
	size_t	encryptedLen = sizeof(encrypted);

	if (!tlsRecordEncrypt(&ctx->handshake.handshakeSendCtx, msg, msgLen, contentType, 0,
						  encrypted, &encryptedLen)) {
		tlsSetError(ctx, TLS_ERR_INTERNAL, "Encryption failed");
		return (TLS_ERR_INTERNAL);
	}

	
	int ret = tlsIoWriteRecord(&ctx->io, 0, encrypted, encryptedLen);
	if (ret != 1) {
		if (ctx->io.ioError == TLS_ERR_WANT_WRITE)
			return (TLS_ERR_WANT_WRITE);
		tlsSetError(ctx, TLS_ERR_IO, "Failed to send encrypted handshake message");
		return (TLS_ERR_IO);
	}
	return (1);
}

int negotiateVersion(const uint16_t *clientVersions, size_t numVersions, t_tlsVersionPref serverPref, uint16_t *selected)
{
	if (!clientVersions || !numVersions || !selected)
		return (0);

	int clientSupports13 = 0;
	int clientSupports12 = 0;

	for (size_t i = 0; i < numVersions; i++)
	{
		if (clientVersions[i] == TLS_VERSION_1_3)
			clientSupports13 = 1;
		if (clientVersions[i] == TLS_VERSION_1_2)
			clientSupports12 = 1;
	}

	switch (serverPref)
	{
		case TLS_VERSION_PREF_TLS13_ONLY:
			if (clientSupports13) { *selected = TLS_VERSION_1_3; return 1; }
			return (0);
		case TLS_VERSION_PREF_TLS12_ONLY:
			if (clientSupports12) { *selected = TLS_VERSION_1_2; return 1; }
			return (0);
		case TLS_VERSION_PREF_TLS13_WITH_FALLBACK:
			if (clientSupports13) { *selected = TLS_VERSION_1_3; return 1; }
			if (clientSupports12) { *selected = TLS_VERSION_1_2; return 1; }
			return (0);
		case TLS_VERSION_PREF_TLS13_AND_12:
			if (clientSupports13) { *selected = TLS_VERSION_1_3; return 1; }
			if (clientSupports12) { *selected = TLS_VERSION_1_2; return 1; }
			return (0);
		default:
			return (0);
	}
}

int negotiateAlpn(const char **clientProtocols, size_t numClientProtocols,
				  const char **serverProtocols, size_t numServerProtocols,
				  const char **selected)
{
	if (!clientProtocols || !serverProtocols || !selected)
		return (0);

	for (size_t i = 0; i < numClientProtocols; i++)
		for (size_t j = 0; j < numServerProtocols; j++)
			if (ft_strcmp(clientProtocols[i], serverProtocols[j]) == 0)
			{
				*selected = clientProtocols[i];
				return (1);
			}
	return (0);
}
