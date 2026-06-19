#include <stdlib.h>

#include "../../../../hajlib/include/hmemory.h"
#include "../../../../includes/utils/random.h"
#include "../../../../hajlib/include/hprintf.h" /* IWYU pragma: keep */

#include "../../../includes/handshake.h"

static int generateServerKeyShare(const t_tlsGroup *group, t_tlsKeyShareEntry *ks, t_kexCtx **outKexCtx)
{
	uint8_t		pubKey[128];
	size_t		pubLen = sizeof(pubKey);
	t_kexCtx	*kexCtx;

	kexCtx = malloc(sizeof(t_kexCtx));
	if (!kexCtx)
		return (0);

	if (!kexInit(kexCtx, group->kexType, group->groupId) ||
		!kexGenerateKeypair(kexCtx) ||
		!kexGetPublicBytes(kexCtx, pubKey, &pubLen))
	{
		kexFree(kexCtx);
		free(kexCtx);
		return (0);
	}

	ks->group = group->wireValue;
	ks->key = malloc(pubLen);
	if (!ks->key) {
		kexFree(kexCtx);
		free(kexCtx);
		return (0);
	}
	ft_memcpy(ks->key, pubKey, pubLen);
	ks->keyLen = pubLen;
	*outKexCtx = kexCtx;
	return (1);
}

int tls13ServerSendFlight(t_tlsCtx *ctx)
{
	int	ret;

	if (!ctx->handshake.flightBuffered)
	{
		const t_tlsCipherSuite	*cipherSuite;
		uint16_t				selectedGroupWire;
		int						kexType, groupId;
		const t_tlsGroup		*group;
		t_tlsKeyShareEntry		*clientKeyShare = NULL;
		t_tlsHello				serverHello;
		uint8_t					sharedSecret[128];
		size_t					sharedSecretLen;
		uint8_t					transcriptHash[64];
		size_t					hashLen;
		uint8_t					msg[TLS_MAX_FRAGMENT_LEN];
		size_t					msgLen;

		/* ----- Choose cipher suite ----- */
		cipherSuite = negotiateCipherSuite(
					ctx->handshake.peerHello.cipherSuites,
					ctx->handshake.peerHello.numCipherSuites);
		if (!cipherSuite) {
			tlsSetError(ctx, TLS_ERR_HANDSHAKE, "No common cipher suite");
			return (TLS_ERR_HANDSHAKE);
		}
		ctx->handshake.cipherSuite = cipherSuite->wireValue;
		ctx->handshake.transcriptHash = *cipherSuite->hash;
		ctx->handshake.transcriptHash.init(ctx->handshake.transcript);

		/* Update transcript with ClientHello */
		transcriptUpdateRaw(&ctx->handshake,
					(const uint8_t *)ctx->handshake.peerHelloMsg,
					ctx->handshake.peerHelloMsgLen);

		/* ----- Negotiate key exchange group ----- */
		if (!negotiateGroup(
			ctx->handshake.peerHello.extensions.supportedGroups,
			ctx->handshake.peerHello.extensions.numSupportedGroups,
			&selectedGroupWire, &kexType, &groupId)) {
			tlsSetError(ctx, TLS_ERR_HANDSHAKE, "No common key exchange group");
			return (TLS_ERR_HANDSHAKE);
		}
		group = getGroup(selectedGroupWire);

		/* ----- Extract client key share ----- */
		for (size_t i = 0;
			 i < ctx->handshake.peerHello.extensions.numKeyShares; i++)
		{
			if (ctx->handshake.peerHello.extensions.keyShares[i].group
				== selectedGroupWire) {
				clientKeyShare =
					&ctx->handshake.peerHello.extensions.keyShares[i];
				break;
			}
		}
		if (!clientKeyShare) {
			tlsSetError(ctx, TLS_ERR_HANDSHAKE,
					"Client did not provide key share");
			return (TLS_ERR_HANDSHAKE);
		}

		/* ---- Build ServerHello ---- */
		tlsHelloInit(&serverHello);
		serverHello.legacyVersion = 0x0303;
		if (hajSecRandBytes(serverHello.random, 32) != 0) {
			tlsSetError(ctx, TLS_ERR_INTERNAL,
					"Failed to generate ServerHello random");
			tlsHelloFree(&serverHello);
			return (TLS_ERR_INTERNAL);
		}
		ft_memcpy(ctx->handshake.serverRandom, serverHello.random, 32);

		serverHello.selectedCipherSuite = cipherSuite->wireValue;
		serverHello.selectedCompression = 0;
		serverHello.extensions.negotiatedVersion = TLS_VERSION_1_3;
		serverHello.extensions.numSupportedVersions = 1;
		serverHello.extensions.supportedVersions[0] = TLS_VERSION_1_3;
		serverHello.extensions.selectedGroup = selectedGroupWire;
		serverHello.extensions.numKeyShares = 1;
		serverHello.extensions.keyShares =
			calloc(1, sizeof(t_tlsKeyShareEntry));
		if (!serverHello.extensions.keyShares) {
			tlsSetError(ctx, TLS_ERR_INTERNAL, "Memory allocation failed");
			tlsHelloFree(&serverHello);
			return (TLS_ERR_INTERNAL);
		}

		if (!generateServerKeyShare(group,
						&serverHello.extensions.keyShares[0],
						&ctx->handshake.keyExchangeCtx)) {
			tlsSetError(ctx, TLS_ERR_INTERNAL,
					"Failed to generate server key share");
			tlsHelloFree(&serverHello);
			return (TLS_ERR_INTERNAL);
		}

		/* ---- Compute shared secret ---- */
		sharedSecretLen = sizeof(sharedSecret);
		if (!kexComputeShared(ctx->handshake.keyExchangeCtx,
					  clientKeyShare->key,
					  clientKeyShare->keyLen,
					  sharedSecret, &sharedSecretLen)) {
			tlsSetError(ctx, TLS_ERR_HANDSHAKE,
					"Failed to compute shared secret");
			tlsHelloFree(&serverHello);
			return (TLS_ERR_HANDSHAKE);
		}
		ctx->handshake.sharedSecretLen = sharedSecretLen;
		ft_memcpy(ctx->handshake.sharedSecret, sharedSecret,
			  sharedSecretLen);

		/* ---- Build and buffer ServerHello ---- */
		{
			uint8_t	shMsg[TLS_MAX_FRAGMENT_LEN];
			size_t	shLen = sizeof(shMsg);

			if (!tlsBuildServerHello(&serverHello,
						 &ctx->handshake.peerHello,
						 TLS_VERSION_1_3, shMsg, &shLen) ||
				tlsIoWriteRecord(&ctx->io, TLS_RT_HANDSHAKE,
						 shMsg, shLen) != 1)
			{
				tlsHelloFree(&serverHello);
				tlsSetError(ctx, TLS_ERR_INTERNAL,
						"Failed to buffer ServerHello");
				return (TLS_ERR_INTERNAL);
			}
			transcriptUpdateRaw(&ctx->handshake, shMsg, shLen);
		}
		tlsHelloFree(&serverHello);

		/* ---- Middlebox compat (CCS) ---- */
		if (ctx->shared->params.middleboxCompat) {
			uint8_t ccsBody = 0x01;
			if (tlsIoWriteRecord(&ctx->io, TLS_RT_CHANGE_CIPHER_SPEC,
						 &ccsBody, 1) != 1)
			{
				tlsSetError(ctx, TLS_ERR_INTERNAL,
						"Failed to buffer CCS");
				return (TLS_ERR_INTERNAL);
			}
		}

		/* ---- Key schedule ---- */
		tls13KeyScheduleInit(&ctx->handshake.secrets,
					 &ctx->handshake.transcriptHash);
		if (!tls13KeyScheduleExtractHandshake(
			&ctx->handshake.secrets, NULL, 0,
			ctx->handshake.sharedSecret,
			ctx->handshake.sharedSecretLen)) {
			tlsSetError(ctx, TLS_ERR_INTERNAL,
					"Key schedule extraction failed");
			return (TLS_ERR_INTERNAL);
		}

		hashLen = ctx->handshake.transcriptHash.digestSize;
		transcriptGetHash(&ctx->handshake, transcriptHash);
		if (!tls13KeyScheduleDeriveHandshakeSecrets(
			&ctx->handshake.secrets,
			transcriptHash, hashLen)) {
			tlsSetError(ctx, TLS_ERR_INTERNAL,
					"Failed to derive handshake secrets");
			return (TLS_ERR_INTERNAL);
		}

		/* ---- Init handshake record contexts ---- */
		if (!tlsRecordCtxInit(&ctx->handshake.handshakeSendCtx,
					  cipherSuite->cipher,
					  ctx->handshake.secrets
					  .serverHandshakeTrafficSecret,
					  hashLen, &ctx->handshake.transcriptHash, 1) ||
			!tlsRecordCtxInit(&ctx->handshake.handshakeRecvCtx,
					  cipherSuite->cipher,
					  ctx->handshake.secrets
					  .clientHandshakeTrafficSecret,
					  hashLen, &ctx->handshake.transcriptHash, 0))
		{
			tlsSetError(ctx, TLS_ERR_INTERNAL,
					"Failed to init handshake record contexts");
			return (TLS_ERR_INTERNAL);
		}

		/* ---- Build and buffer handshake messages ---- */
		/* EncryptedExtensions */
		if (!tls13BuildEncryptedExtensions(&ctx->handshake, msg, &msgLen))
		{
			tlsSetError(ctx, TLS_ERR_INTERNAL,
					"Failed to build EncryptedExtensions");
			return (TLS_ERR_INTERNAL);
		}
		if (!tls13SendEncryptedMessage(ctx, msg, msgLen, TLS_RT_HANDSHAKE))
		{
			tlsSetError(ctx, TLS_ERR_INTERNAL,
					"Failed to buffer EncryptedExtensions");
			return (TLS_ERR_INTERNAL);
		}

		/* Certificate */
		if (!tls13BuildCertificate(&ctx->handshake, msg, &msgLen))
		{
			tlsSetError(ctx, TLS_ERR_INTERNAL,
					"Failed to build Certificate");
			return (TLS_ERR_INTERNAL);
		}

		if (!tls13SendEncryptedMessage(ctx, msg, msgLen, TLS_RT_HANDSHAKE))
		{
			tlsSetError(ctx, TLS_ERR_INTERNAL,
					"Failed to buffer Certificate");
			return (TLS_ERR_INTERNAL);
		}

		/* CertificateVerify */
		if (!tls13BuildCertificateVerify(ctx, msg, &msgLen))
		{
			tlsSetError(ctx, TLS_ERR_INTERNAL,
					"Failed to build CertificateVerify");
			return (TLS_ERR_INTERNAL);
		}

		if (!tls13SendEncryptedMessage(ctx, msg, msgLen, TLS_RT_HANDSHAKE))
		{
			tlsSetError(ctx, TLS_ERR_INTERNAL,
					"Failed to buffer CertificateVerify");
			return (TLS_ERR_INTERNAL);
		}

		/* Finished */
		if (!tls13BuildFinished(&ctx->handshake,
					ctx->handshake.secrets
						.serverHandshakeTrafficSecret,
					hashLen, msg, &msgLen))
		{
			tlsSetError(ctx, TLS_ERR_INTERNAL,
					"Failed to build Finished");
			return (TLS_ERR_INTERNAL);
		}
		if (!tls13SendEncryptedMessage(ctx, msg, msgLen, TLS_RT_HANDSHAKE))
		{
			tlsSetError(ctx, TLS_ERR_INTERNAL,
					"Failed to buffer Finished");
			return (TLS_ERR_INTERNAL);
		}

		ctx->handshake.flightBuffered = 1;


		/* ----- Derive application secrets and init record contexts ----- */
		ft_bzero(transcriptHash, sizeof(transcriptHash));
		hashLen = ctx->handshake.transcriptHash.digestSize;
		transcriptGetHash(&ctx->handshake, transcriptHash);
		if (!tls13KeyScheduleDeriveAppSecrets(&ctx->handshake.secrets,
							   transcriptHash, hashLen)) {
			tlsSetError(ctx, TLS_ERR_INTERNAL, "Failed to derive application secrets");
			return (TLS_ERR_INTERNAL);
		}

		const t_tlsCipherSuite *cs = getCipherSuite(ctx->handshake.cipherSuite);
		if (!tlsRecordCtxInit(&ctx->handshake.appSendCtx, cs->cipher,
					  ctx->handshake.secrets.serverAppTrafficSecret,
					  hashLen, &ctx->handshake.transcriptHash, 1) ||
			!tlsRecordCtxInit(&ctx->handshake.appRecvCtx, cs->cipher,
					  ctx->handshake.secrets.clientAppTrafficSecret,
					  hashLen, &ctx->handshake.transcriptHash, 0)) {
			tlsSetError(ctx, TLS_ERR_INTERNAL, "Failed to init application record contexts");
			return (TLS_ERR_INTERNAL);
		}
	}
	/* ---------- Building completed ---------- */

	/* ----- Flush flight ---- */
	ret = tlsIoFlush(&ctx->io);
	if (ret < 0) {
		tlsSetError(ctx, TLS_ERR_IO, "Flush failed during flight send");
		return (TLS_ERR_IO);
	}

	if (tlsIoHasPending(&ctx->io)) {
		tlsSetError(ctx, TLS_ERR_WANT_WRITE, "Flight partially sent");
		return (TLS_ERR_WANT_WRITE);
	}

	ctx->handshake.flightBuffered = 0;
	return (1);
}

int tls13ServerWaitClientFinished(t_tlsCtx *ctx)
{
	uint8_t	recordType;
	uint8_t	rawData[TLS_MAX_FRAGMENT_LEN + TLS_RECORD_HEADER_SIZE + 256];
	size_t	rawLen;
	int		ret;

	while (1) {
		rawLen = sizeof(rawData);
		ret = tlsIoReadRecord(&ctx->io, rawData, &rawLen);
		if (ret <= 0) {
			if (ctx->io.ioError == TLS_ERR_WANT_READ)
				return (TLS_ERR_WANT_READ);
			if (ctx->io.ioError == TLS_ERR_EOF) {
				tlsSetError(ctx, TLS_ERR_EOF, "Connection closed while waiting for Finished");
				return (TLS_ERR_EOF);
			}
			tlsSetError(ctx, TLS_ERR_IO, "Failed to read record");
			return (TLS_ERR_IO);
		}

		recordType = rawData[0];

		/* Middlebox compat : Ignore CCS from client */
		if (recordType == TLS_RT_CHANGE_CIPHER_SPEC) {
			if (rawLen == TLS_RECORD_HEADER_SIZE + 1 && rawData[TLS_RECORD_HEADER_SIZE] == 0x01) {
				BTLS_DEBUG("Ignoring CCS from client");
				continue;
			}
			tlsSetError(ctx, TLS_ERR_PROTOCOL, "Malformed ChangeCipherSpec");
			return (TLS_ERR_PROTOCOL);
		}

		if (recordType == TLS_RT_ALERT) { /* Plaintext alert from client */
			if (tlsHandleAlert(ctx, rawData + TLS_RECORD_HEADER_SIZE, rawLen - TLS_RECORD_HEADER_SIZE) < 0)
				return (TLS_ERR_PROTOCOL);
			continue;
		}

		if (recordType != TLS_RT_APPLICATION_DATA) {
			tlsSetError(ctx, TLS_ERR_PROTOCOL, "Expected ApplicationData record");
			return (TLS_ERR_PROTOCOL);
		}

		uint8_t	plaintext[TLS_MAX_FRAGMENT_LEN + 1];
		size_t	plainLen = sizeof(plaintext);
		uint8_t	innerType = 0;

		if (!tlsRecordDecrypt(&ctx->handshake.handshakeRecvCtx,
					  rawData, rawLen, 0,
					  plaintext, &plainLen, &innerType)) {
			tlsSetError(ctx, TLS_ERR_DECRYPT, "Failed to decrypt client record");
			return (TLS_ERR_DECRYPT);
		}

		if (innerType == TLS_RT_ALERT) {
			if (tlsHandleAlert(ctx, plaintext, plainLen) < 0)
				return (TLS_ERR_PROTOCOL);
			tlsSetError(ctx, TLS_ERR_HANDSHAKE, "Client sent alert during handshake");
			return (TLS_ERR_HANDSHAKE);
		}

		if (innerType != TLS_RT_HANDSHAKE) {
			tlsSetError(ctx, TLS_ERR_PROTOCOL, "Unexpected inner content type");
			return (TLS_ERR_PROTOCOL);
		}

		uint8_t			msgType;
		const uint8_t	*body;
		size_t			bodyLen;
		if (!handshakeDecode(plaintext, plainLen, &msgType, &body, &bodyLen)) {
			tlsSetError(ctx, TLS_ERR_PROTOCOL, "Invalid handshake message format");
			return (TLS_ERR_PROTOCOL);
		}
		if (msgType != TLS_HT_FINISHED) {
			tlsSetError(ctx, TLS_ERR_PROTOCOL, "Expected Finished message");
			return (TLS_ERR_PROTOCOL);
		}

		if (!tls13VerifyFinished(&ctx->handshake,
					 ctx->handshake.secrets.clientHandshakeTrafficSecret,
					 ctx->handshake.transcriptHash.digestSize,
					 body, bodyLen)) {
			tlsSetError(ctx, TLS_ERR_HANDSHAKE, "Client Finished verification failed");
			return (TLS_ERR_HANDSHAKE);
		}

		BTLS_DEBUG("TLS 1.3 handshake complete, application keys derived");
		return (1);
	}
}
