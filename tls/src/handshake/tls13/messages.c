
#include <stdlib.h>

#include "../../../../hajlib/include/hmemory.h"
#include "../../../../includes/hash/hmac.h"
#include "../../../../includes/asymmetric/pkey.h"
#include "../../../../includes/asymmetric/ecdsa.h"
#include "../../../../includes/utils/utils.h"

#include "../../../includes/constants.h"
#include "../../../includes/hkdf.h"

#include "../../../includes/handshake.h"

int tls13BuildEncryptedExtensions(t_tlsHandshakeCtx *ctx, uint8_t *out, size_t *outLen)
{
	uint8_t	body[2];

	if (!ctx || !out || !outLen)
		return (0);

	body[0] = 0;
	body[1] = 0;

	if (!handshakeEncode(TLS_HT_ENCRYPTED_EXTENSIONS, body, 2, out, outLen))
		return (0);

	transcriptUpdate(ctx, TLS_HT_ENCRYPTED_EXTENSIONS, out + 4, *outLen - 4);
	return (1);
}

int tls13BuildCertificate(t_tlsCtx *ctx, uint8_t *out, size_t *outLen)
{
	uint8_t	*body;
	size_t	bodyLen;
	size_t	offset;
	size_t	totalListLen;
	size_t	i;

	if (!ctx || !ctx->config->certChain || ctx->config->certChain->count == 0 || !out || !outLen)
		return (0);


	totalListLen = 0;
	for (i = 0; i < ctx->config->certChain->count; i++) {
		totalListLen += 3 + ctx->config->certChain->certs[i]->derLen + 2;
	}

	bodyLen = 1 + 3 + totalListLen;
	body = ft_calloc(1, bodyLen);
	if (!body)
		return (0);

	offset = 0;

	/* 1. request_context (empty for server Certificate, zero length) */
	body[offset++] = 0x00;

	/* 2. certificate_list_length (3 octets big-endian) */
	body[offset++] = (totalListLen >> 16) & 0xFF;
	body[offset++] = (totalListLen >> 8)  & 0xFF;
	body[offset++] =  totalListLen		& 0xFF;

	/* 3. CertificateEntry for each certificate */
	for (i = 0; i < ctx->config->certChain->count; i++) {
		t_x509Cert *cert = ctx->config->certChain->certs[i];
		size_t	  certLen = cert->derLen;

		/* cert_data_length (3 octets big-endian) */
		body[offset++] = (certLen >> 16) & 0xFF;
		body[offset++] = (certLen >> 8)  & 0xFF;
		body[offset++] =  certLen		& 0xFF;

		/* cert_data */
		if (certLen > 0 && cert->der)
			ft_memcpy(body + offset, cert->der, certLen);
		offset += certLen;

		/* extensions_length (2 octets, 0 car pas d'extensions pour l'instant) */
		body[offset++] = 0x00;
		body[offset++] = 0x00;

		/* TODO: certificat extensions (OCSP stapling, SCT, etc.) */
	}

	if (!handshakeEncode(TLS_HT_CERTIFICATE, body, bodyLen, out, outLen)) {
		free(body);
		return (0);
	}

	free(body);

	transcriptUpdate(&ctx->handshake, TLS_HT_CERTIFICATE, out + 4, *outLen - 4);
	return (1);
}

static int setSigSchemBytes(t_tlsCtx *ctx, uint8_t *body)
{
	switch (ctx->config->privateKey->def->type) {
		case PKEY_TYPE_RSA:
			if (oidEqual(&ctx->handshake.transcriptHash.oid, &g_sha256Hash.oid)) {
				body[0] = 0x08; /* rsa_pss_rsae_sha256 */
				body[1] = 0x04;
			}
			else if (oidEqual(&ctx->handshake.transcriptHash.oid, &g_sha384Hash.oid)) {
				body[0] = 0x08; /* rsa_pss_rsae_sha384 */
				body[1] = 0x05;
			}
			else if (oidEqual(&ctx->handshake.transcriptHash.oid, &g_sha512Hash.oid)) {
				body[0] = 0x08; /* rsa_pss_rsae_sha512 */
				body[1] = 0x06;
			}
			else {
				tlsSetError(ctx, TLS_ERR_INTERNAL, "Unsupported hash algorithm for RSA signature in CertificateVerify");
				return (0);
			}
			break;
		case PKEY_TYPE_ECDSA:
		{
			t_ecdsaKey *ecdsaKey = (t_ecdsaKey *)ctx->config->privateKey->key;
			if (ecdsaKey->curveId == ECDH_GROUP_SECP256R1) {
				body[0] = 0x04; /* ecdsa_secp256r1_sha256 */
				body[1] = 0x03;
			}
			else if (ecdsaKey->curveId == ECDH_GROUP_SECP384R1) {
				body[0] = 0x05; /* ecdsa_secp384r1_sha384 */
				body[1] = 0x03;
			}
			else {
				tlsSetError(ctx, TLS_ERR_INTERNAL, "Unsupported curve for ECDSA signature in CertificateVerify");
				return (0);
			}
			break;
		}
		default:
			tlsSetError(ctx, TLS_ERR_INTERNAL, "Unsupported key type for CertificateVerify");
			return (0);
	}
	return (1);
}

int tls13BuildCertificateVerify(t_tlsCtx *ctx, uint8_t *out, size_t *outLen)
{
	uint8_t	transcriptHash[64];
	uint8_t	msgToSign[64 + 33 + 1 + 64];
	uint8_t	digest[64];
	size_t	msgLen;
	uint8_t	signature[512];
	size_t	signatureLen;
	uint8_t	*body;
	size_t	bodyLen;
	size_t	hashLen;

	if (!ctx || !out || !outLen)
		return (0);
	if (!ctx->config->privateKey)
		return (0);

	hashLen = ctx->handshake.transcriptHash.digestSize;

	/* 1. Build message to sign:
	 *	pad(64) + "TLS 1.3, server CertificateVerify" + 0x00 + transcriptHash */
	msgLen = 0;
	ft_memset(msgToSign, 0x20, 64);
	msgLen += 64;
	ft_memcpy(msgToSign + msgLen, "TLS 1.3, server CertificateVerify", 33);
	msgLen += 33;
	msgToSign[msgLen++] = 0x00;
	transcriptGetHash(&ctx->handshake, transcriptHash);
	ft_memcpy(msgToSign + msgLen, transcriptHash, hashLen);
	msgLen += hashLen;

	/* 2. Hash the message to sign */
	{
		uint8_t hashCtx[HASH_MAX_CTX_SIZE];
		ctx->handshake.transcriptHash.init(hashCtx);
		ctx->handshake.transcriptHash.update(hashCtx, msgToSign, msgLen);
		ctx->handshake.transcriptHash.final(digest, hashCtx);
	}

	/* 3. Sign the digest */
	signatureLen = sizeof(signature);
	if (!pkeySign(ctx->config->privateKey,
				  digest, hashLen,
				  &ctx->handshake.transcriptHash.oid,
				  signature, &signatureLen,
				  PKEY_PADDING_PSS))
		return (0);

	/* 4. Build body: signature_scheme (2) + signature_len (2) + signature */
	bodyLen = 2 + 2 + signatureLen;
	body = malloc(bodyLen);
	if (!body)
		return (0);

	/* Signature scheme */
	if (!setSigSchemBytes(ctx, body)) {
		free(body);
		return (0);
	}

	/* Signature length (2 bytes big-endian) */
	body[2] = (signatureLen >> 8) & 0xFF;
	body[3] = signatureLen & 0xFF;

	/* Signature data */
	ft_memcpy(body + 4, signature, signatureLen);

	if (!handshakeEncode(TLS_HT_CERTIFICATE_VERIFY, body, bodyLen, out, outLen))
	{
		free(body);
		return (0);
	}

	free(body);
	transcriptUpdate(&ctx->handshake, TLS_HT_CERTIFICATE_VERIFY, out + 4, *outLen - 4);
	return (1);
}

int tls13BuildFinished(t_tlsHandshakeCtx	*ctx,
					   const uint8_t		*trafficSecret,	size_t	secretLen,
					   uint8_t				*out,			size_t	*outLen)
{
	uint8_t		finishedKey[64];
	uint8_t		verifyData[64];
	uint8_t		transcriptHash[64];
	t_hmacCtx	hmacCtx;
	size_t		hashLen;

	if (!ctx || !trafficSecret || !out || !outLen)
		return (0);

	hashLen = ctx->transcriptHash.digestSize;

	/* 1. Derive finished_key = HKDF-Expand-Label(secret, "finished", "", hashLen) */
	if (!tlsHkdfExpandLabel(trafficSecret, secretLen,
							TLS13_LABEL_FINISHED, NULL, 0,
							finishedKey, hashLen, &ctx->transcriptHash))
		return (0);

	/* 2. Get transcript hash */
	transcriptGetHash(ctx, transcriptHash);

	/* 3. HMAC(finished_key, transcript_hash) */
	hmacInit(&hmacCtx, &ctx->transcriptHash, finishedKey, hashLen);
	hmacCtx.algo->update(hmacCtx.innerCtx, transcriptHash, hashLen);
	hmacFinal(&hmacCtx, verifyData);

	/* 4. Encode the Finished message */
	if (!handshakeEncode(TLS_HT_FINISHED, verifyData, hashLen, out, outLen))
	{
		secureZeroMemory(finishedKey, sizeof(finishedKey));
		secureZeroMemory(verifyData, sizeof(verifyData));
		return (0);
	}

	secureZeroMemory(finishedKey, sizeof(finishedKey));
	secureZeroMemory(verifyData, sizeof(verifyData));

	transcriptUpdate(ctx, TLS_HT_FINISHED, out + 4, *outLen - 4);
	return (1);
}

int tls13VerifyFinished(t_tlsHandshakeCtx	*ctx,
						const uint8_t		*trafficSecret,	size_t	secretLen,
						const uint8_t		*verifyData,	size_t	verifyDataLen)
{
	uint8_t		computedVerify[64];
	uint8_t		transcriptHash[64];
	uint8_t		finishedKey[64];
	t_hmacCtx	hmacCtx;
	size_t		hashLen;
	int			ret;

	if (!ctx || !trafficSecret || !verifyData)
		return (0);

	hashLen = ctx->transcriptHash.digestSize;
	if (verifyDataLen != hashLen)
		return (0);

	/* 1. Derive finished_key */
	if (!tlsHkdfExpandLabel(trafficSecret, secretLen,
							TLS13_LABEL_FINISHED, NULL, 0,
							finishedKey, hashLen, &ctx->transcriptHash))
		return (0);

	/* 2. Get transcript hash (before adding the Finished message) */
	transcriptGetHash(ctx, transcriptHash);

	/* 3. HMAC(finished_key, transcript_hash) */
	hmacInit(&hmacCtx, &ctx->transcriptHash, finishedKey, hashLen);
	hmacCtx.algo->update(hmacCtx.innerCtx, transcriptHash, hashLen);
	hmacFinal(&hmacCtx, computedVerify);

	/* 4. Compare */
	ret = ft_cmemcmp(computedVerify, verifyData, hashLen);

	secureZeroMemory(finishedKey, sizeof(finishedKey));
	secureZeroMemory(computedVerify, sizeof(computedVerify));

	if (ret)
		if (!transcriptUpdate(ctx, TLS_HT_FINISHED, verifyData, verifyDataLen))
			return (0);

	return (ret);
}

int tls13SendAlert(t_tlsCtx *ctx, uint8_t level, uint8_t description)
{
	uint8_t	alert[2];
	size_t	alertLen;

	if (!ctx)
		return (0);

	alert[0] = level;
	alert[1] = description;
	alertLen = 2;

	return (tls13SendEncryptedMessage(ctx, alert, alertLen, TLS_RT_ALERT));
}
