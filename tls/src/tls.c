
#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"
#include "../../includes/utils/utils.h"
#include "../../includes/x509/pem.h"
#include "../includes/handshake.h"

#ifdef _WIN32
	#include <winsock2.h>
#endif

#include "../includes/btls.h"

void tlsSetError(t_tlsCtx *ctx, int errCode, const char *errMsg)
{
	if (!ctx)
		return;
	ctx->lastError = errCode;

	if (errMsg && errMsg[0]) {
		free(ctx->errorMsg);
		ctx->errorMsg = ft_strdup(errMsg);
	} else if (!ctx->errorMsg)
		ctx->errorMsg = ft_strdup("Unknown error");

	BTLS_DEBUG("TLS error set: code=%d, message=%s", errCode,
		   ctx->errorMsg ? ctx->errorMsg : "null");
}

int tlsHandleAlert(t_tlsCtx *ctx, const uint8_t *data, size_t dataLen)
{
	if (dataLen < 2) {
		tlsSetError(ctx, TLS_ERR_PROTOCOL, "Malformed alert");
		return (-1);
	}

	uint8_t		level = data[0];
	uint8_t		desc  = data[1];
	const char	*descStr = "unknown";

	switch (desc) {
		case TLS_ALERT_CLOSE_NOTIFY:
			descStr = "close_notify";
			BTLS_DEBUG("Connection closed by peer (close_notify)");
			ctx->isConnected = 0;
			return (0);
		case TLS_ALERT_UNEXPECTED_MESSAGE:		descStr = "unexpected_message"; break;
		case TLS_ALERT_BAD_RECORD_MAC:			descStr = "bad_record_mac"; break;
		case TLS_ALERT_DECRYPTION_FAILED:		descStr = "decryption_failed"; break;
		case TLS_ALERT_RECORD_OVERFLOW:			descStr = "record_overflow"; break;
		case TLS_ALERT_HANDSHAKE_FAILURE:		descStr = "handshake_failure"; break;
		case TLS_ALERT_NO_CERTIFICATE:			descStr = "no_certificate"; break;
		case TLS_ALERT_BAD_CERTIFICATE:			descStr = "bad_certificate"; break;
		case TLS_ALERT_UNSUPPORTED_CERTIFICATE:	descStr = "unsupported_certificate"; break;
		case TLS_ALERT_CERTIFICATE_REVOKED:		descStr = "certificate_revoked"; break;
		case TLS_ALERT_CERTIFICATE_EXPIRED:		descStr = "certificate_expired"; break;
		case TLS_ALERT_CERTIFICATE_UNKNOWN:		descStr = "certificate_unknown"; break;
		case TLS_ALERT_ILLEGAL_PARAMETER:		descStr = "illegal_parameter"; break;
		case TLS_ALERT_UNKNOWN_CA:				descStr = "unknown_ca"; break;
		case TLS_ALERT_ACCESS_DENIED:			descStr = "access_denied"; break;
		case TLS_ALERT_DECODE_ERROR:			descStr = "decode_error"; break;
		case TLS_ALERT_DECRYPT_ERROR:			descStr = "decrypt_error"; break;
		case TLS_ALERT_CERTIFICATE_REQUIRED:	descStr = "certificate_required"; break;
		case TLS_ALERT_PROTOCOL_VERSION:		descStr = "protocol_version"; break;
		case TLS_ALERT_INSUFFICIENT_SECURITY:	descStr = "insufficient_security"; break;
		case TLS_ALERT_INTERNAL_ERROR:			descStr = "internal_error"; break;
		case TLS_ALERT_USER_CANCELED:			descStr = "user_canceled"; break;
		case TLS_ALERT_MISSING_EXTENSION:		descStr = "missing_extension"; break;
		case TLS_ALERT_UNSUPPORTED_EXTENSION:	descStr = "unsupported_extension"; break;
		case TLS_ALERT_NO_RENEGOTIATION:		descStr = "no_renegotiation"; break;
		case TLS_ALERT_NO_APPLICATION_PROTOCOL:	descStr = "no_application_protocol"; break;
		case TLS_ALERT_ECH_REQUIRED:			descStr = "ech_required"; break;
		case TLS_ALERT_RECORD_LIMIT_EXCEEDED:	descStr = "record_limit_exceeded"; break;
		default: break;
	}

	BTLS_DEBUG("Received alert: level=%s (%d), description=%s (0x%02x)",
		   (level == 1) ? "warning" : "fatal", level, descStr, desc);

	if (level == TLS_ALERT_LEVEL_FATAL) {
		tlsSetError(ctx, TLS_ERR_PROTOCOL, descStr);
		return (-1);
	}
	return (0);
}

static int loadPemKey(const char *keyFile, const char *password, t_pkey *out)
{
	uint8_t	*rawData;
	size_t	rawLen;
	char	*keyPem = NULL;

	if (readBinaryFile(keyFile, &rawData, &rawLen)) {
		ft_dprintf(STDERR_FILENO, "btls: cannot read key file '%s'\n", keyFile);
		return (0);
	}
	keyPem = ft_strndup((const char *)rawData, rawLen);
	free(rawData);
	if (pkeyFromPem(keyPem, out, 1, password) != 1) {
		ft_dprintf(STDERR_FILENO, "btls: failed to parse private key from '%s'\n", keyFile);
		free(keyPem);
		return (0);
	}
	free(keyPem);
	return (1);
}

static t_certChain *loadCertChain(const char *certFile)
{
	uint8_t	*rawData;
	size_t	rawLen;
	char	*pemText;

	if (readBinaryFile(certFile, &rawData, &rawLen))
		return (NULL);

	t_certChain *chain = certChainNew();
	if (!chain) {
		free(rawData);
		return (NULL);
	}

	if (rawLen > 0 && rawData[0] == '-') {
		pemText = ft_strndup((const char *)rawData, rawLen);
		const char *ptr = pemText;
		while (1) {
			const char *begin = ft_strstr(ptr, "-----BEGIN CERTIFICATE-----");
			if (!begin) break;
			const char *end = ft_strstr(begin, "-----END CERTIFICATE-----");
			if (!end) break;
			end += 25;

			size_t blockLen = (size_t)(end - begin);
			char *block = ft_strndup(begin, blockLen);
			t_pemBlock pb;
			if (pemDecode(block, &pb)) {
				if (!certChainAddDER(chain, pb.der, pb.derLen))
					ft_dprintf(STDERR_FILENO, "btls: warning: failed to parse certificate in chain\n");
				free(pb.der);
				free(pb.header);
			}
			free(block);
			ptr = end;
		}
		free(pemText);
		free(rawData);
	} else {
		if (!certChainAddDER(chain, rawData, rawLen)) {
			certChainFree(chain);
			free(rawData);
			return (NULL);
		}
		free(rawData);
	}

	if (chain->count == 0) {
		certChainFree(chain);
		return (NULL);
	}
	return (chain);
}

int tlsConfigInit(t_tlsConfig *cfg)
{
	if (!cfg)
		return (0);
	ft_bzero(cfg, sizeof(t_tlsConfig));

	cfg->middleboxCompat	= 1;
	cfg->versionPref		= TLS_VERSION_PREF_TLS13_ONLY;
	cfg->isBlocking			= 0;
	cfg->sendGrease			= 1;
	cfg->verifyPeer			= 1;
	cfg->allowSelfSigned	= 1;
	cfg->verifyDepth		= 9;

	return (1);
}

void tlsConfigFree(t_tlsConfig *cfg)
{
	if (!cfg)
		return;
	if (cfg->certChain) {
		certChainFree(cfg->certChain);
		cfg->certChain = NULL;
	}
	if (cfg->privateKey) {
		pkeyFree(cfg->privateKey);
		free(cfg->privateKey);
		cfg->privateKey = NULL;
	}
}

static int pkeyMatchesCert(const t_pkey *pk, const t_x509Cert *cert)
{
	uint8_t	*keyPubDer;
	size_t	keyPubDerLen;
	int		match;

	if (!pk || !pk->def || !pk->key)
		return (1);
	if (!cert || !cert->pubKeyRaw || !cert->pubKeyRawLen)
		return (1);

	if (!pk->def->encodePubKeySpki)
		return (1); /* no way to encode the public key */

	keyPubDer = pk->def->encodePubKeySpki(pk->key, &keyPubDerLen);
	if (!keyPubDer)
		return (1); /* encoding failed, assume ok */

	match = (keyPubDerLen == cert->pubKeyRawLen
		 && ft_memcmp(keyPubDer, cert->pubKeyRaw, keyPubDerLen) == 0);

	free(keyPubDer);
	return (match);
}

static int certIsSelfSigned(const t_x509Cert *cert)
{
	if (!cert || !cert->issuer || !cert->subject)
		return (0);
	if (cert->issuerLen != cert->subjectLen)
		return (0);
	return (ft_memcmp(cert->issuer, cert->subject, cert->issuerLen) == 0);
}

int tlsConfigLoadCertKey(t_tlsConfig *cfg, const char *certFile, const char *keyFile, const char *keyPassword)
{
	t_pkey				*pk;
	t_certChain			*chain;
	const t_x509Cert	*leaf;

	if (!cfg || !certFile || !keyFile)
		return (0);

	/* Free any previously loaded material */
	if (cfg->privateKey) {
		pkeyFree(cfg->privateKey);
		free(cfg->privateKey);
		cfg->privateKey = NULL;
	}
	if (cfg->certChain) {
		certChainFree(cfg->certChain);
		cfg->certChain = NULL;
	}

	pk = malloc(sizeof(t_pkey));
	if (!pk)
		return (0);
	ft_bzero(pk, sizeof(t_pkey));
	if (!loadPemKey(keyFile, keyPassword, pk)) {
		free(pk);
		return (0);
	}

	chain = loadCertChain(certFile);
	if (!chain) {
		pkeyFree(pk);
		free(pk);
		return (0);
	}

	/* Verify key matches the leaf certificate */
	if (chain->count > 0 && chain->certs[0]) {
		leaf = chain->certs[0];

		if (!pkeyMatchesCert(pk, leaf)) {
			BTLS_DEBUG("[Config] Private key does not match the leaf certificate");
			pkeyFree(pk);
			free(pk);
			certChainFree(chain);
			return (0);
		}

		if (certIsSelfSigned(leaf))
			ft_dprintf(STDERR_FILENO,
				"btls: WARNING: certificate is self-signed\n");
	} else
		ft_dprintf(STDERR_FILENO,
			"btls: WARNING: empty certificate chain, cannot verify key\n");

	cfg->privateKey = pk;
	cfg->certChain  = chain;
	BTLS_DEBUG("[Config] Certificate and key loaded successfully");
	return (1);
}


static void initConnectionCtx(t_tlsCtx *ctx, const t_tlsConfig *cfg, int socket, int isServer)
{
	ctx->config			= cfg;
	ctx->isServer		= isServer;
	ctx->isConnected	= 0;

	tlsIoInit(&ctx->io, socket, cfg->isBlocking);

	if (isServer)
		ctx->handshake.isClient = 0;
	else
		ctx->handshake.isClient = 1;
	ctx->handshake.state = TLS_HS_STATE_IDLE;
}

void tlsFreeConnection(t_tlsCtx *ctx)
{
	if (!ctx)
		return;

	tlsHelloFree(&ctx->handshake.peerHello);
	tlsHandshakeFree(&ctx->handshake);
	free(ctx->errorMsg);
	if (ctx->io.socket >= 0)
#ifdef _WIN32
		closesocket(ctx->io.socket);
#else
		close(ctx->io.socket);
#endif
	ctx->io.socket = -1;
	ft_bzero(ctx, sizeof(t_tlsCtx));
}

int tlsIsConnected(const t_tlsCtx *ctx)
{
	return (ctx ? ctx->isConnected : 0);
}

static int serverHandshake(t_tlsCtx *ctx)
{
	int ret = 0;

	switch (ctx->handshake.state) {
		case TLS_HS_STATE_IDLE:
		case TLS_HS_STATE_SERVER_WAIT_CLIENT_HELLO:
		{
			uint8_t		chMsg[TLS_MAX_FRAGMENT_LEN];
			size_t		chLen = sizeof(chMsg);
			t_tlsHello	clientHello;

			ret = tlsReadHandshakeMessage(ctx, chMsg, &chLen, 0);
			if (ret == TLS_ERR_WANT_READ) {
				ctx->handshake.state = TLS_HS_STATE_SERVER_WAIT_CLIENT_HELLO;
				tlsSetError(ctx, TLS_ERR_WANT_READ, "Waiting for ClientHello");
				return (TLS_ERR_WANT_READ);
			}
			if (ret != 1) {
				tlsSetError(ctx, TLS_ERR_HANDSHAKE, "Failed to read ClientHello");
				ctx->handshake.state = TLS_HS_STATE_ERROR;
				return (TLS_ERR_HANDSHAKE);
			}

			tlsHelloInit(&clientHello);
			if (!tlsDecodeHello(chMsg, chLen, &clientHello, 0)) {
				tlsHelloFree(&clientHello);
				tlsSetError(ctx, TLS_ERR_HANDSHAKE, "Failed to decode ClientHello");
				ctx->handshake.state = TLS_HS_STATE_ERROR;
				return (TLS_ERR_HANDSHAKE);
			}

			ft_memcpy(ctx->handshake.clientRandom, clientHello.random, 32);

			if (!negotiateVersion(clientHello.extensions.supportedVersions,
						  clientHello.extensions.numSupportedVersions,
						  ctx->config->versionPref,
						  &ctx->handshake.version)) {
				tlsHelloFree(&clientHello);
				tlsSetError(ctx, TLS_ERR_HANDSHAKE, "No common TLS version");
				ctx->handshake.state = TLS_HS_STATE_ERROR;
				return (TLS_ERR_HANDSHAKE);
			}

			ft_memcpy(ctx->handshake.peerHelloMsg, chMsg, chLen);
			ctx->handshake.peerHelloMsgLen = chLen;
			ctx->handshake.peerHello = clientHello;

			BTLS_DEBUG("Tls Client Hello successfully processed");
			tlsPrintHello(&clientHello);

			if (ctx->handshake.version == TLS_VERSION_1_3)
				ctx->handshake.state = TLS_HS_STATE_13_SERVER_SEND_FLIGHT;
			else {
				tlsSetError(ctx, TLS_ERR_HANDSHAKE, "Unsupported TLS version");
				ctx->handshake.state = TLS_HS_STATE_ERROR;
				return (TLS_ERR_HANDSHAKE);
			}
		}
		__attribute__((fallthrough));

		case TLS_HS_STATE_13_SERVER_SEND_FLIGHT:
		{
			ret = tls13ServerSendFlight(ctx);
			if (ret == TLS_ERR_WANT_WRITE)
				return (TLS_ERR_WANT_WRITE);
			if (ret != 1) {
				ctx->handshake.state = TLS_HS_STATE_ERROR;
				return (TLS_ERR_HANDSHAKE);
			}
			ctx->handshake.state = TLS_HS_STATE_13_SERVER_WAIT_CLIENT_FINISHED;
			BTLS_DEBUG("[HSK] TLS 1.3 Server flight sent, waiting for Client Finished");
			__attribute__((fallthrough));
		}
		case TLS_HS_STATE_13_SERVER_WAIT_CLIENT_FINISHED:
		{
			ret = tls13ServerWaitClientFinished(ctx);
			if (ret == TLS_ERR_WANT_READ)
				return (TLS_ERR_WANT_READ);
			if (ret != 1) {
				ctx->handshake.state = TLS_HS_STATE_ERROR;
				return (TLS_ERR_HANDSHAKE);
			}

			ctx->handshake.state = TLS_HS_STATE_13_CONNECTED;
			ctx->isConnected = 1;
			tlsHelloFree(&ctx->handshake.peerHello);
			BTLS_DEBUG("[HSK] TLS 1.3 handshake complete");
			return (TLS_SUCCESS);
		}

		default:
			tlsSetError(ctx, TLS_ERR_HANDSHAKE, "Invalid handshake state");
			ctx->handshake.state = TLS_HS_STATE_ERROR;
			return (TLS_ERR_HANDSHAKE);
	}
}

int tlsAccept(t_tlsCtx *ctx, const t_tlsConfig *cfg, int socket)
{
	if (!ctx || !cfg) {
		if (ctx)
			tlsSetError(ctx, TLS_ERR_PROTOCOL, "Invalid arguments");
		return (TLS_ERR_PROTOCOL);
	}

	/* Auto‑initialise the context if it is in the IDLE state */
	if (ctx->handshake.state == TLS_HS_STATE_IDLE && !ctx->config)
		initConnectionCtx(ctx, cfg, socket, 1);

	if (ctx->isServer != 1) {
		tlsSetError(ctx, TLS_ERR_PROTOCOL, "Context is not a server");
		return (TLS_ERR_PROTOCOL);
	}

	return (serverHandshake(ctx));
}

static int clientHandshake(t_tlsCtx *ctx)
{
	(void)ctx;
	tlsSetError(ctx, TLS_ERR_INTERNAL, "Client handshake not implemented");
	return (TLS_ERR_INTERNAL);
}

int tlsConnect(t_tlsCtx *ctx, const t_tlsConfig *cfg, int socket)
{
	if (!ctx || !cfg) {
		if (ctx)
			tlsSetError(ctx, TLS_ERR_PROTOCOL, "Invalid arguments");
		return (TLS_ERR_PROTOCOL);
	}

	/* Auto‑initialise the context if it is in the IDLE state */
	if (ctx->handshake.state == TLS_HS_STATE_IDLE && !ctx->config)
		initConnectionCtx(ctx, cfg, socket, 0);

	if (ctx->isServer != 0) {
		tlsSetError(ctx, TLS_ERR_PROTOCOL, "Context is not a client");
		return (TLS_ERR_PROTOCOL);
	}

	return (clientHandshake(ctx));
}

ssize_t tlsRead(t_tlsCtx *ctx, uint8_t *buf, size_t len)
{
	uint8_t	contentType;
	uint8_t	rawData[TLS_MAX_FRAGMENT_LEN + 256];
	size_t	rawLen;
	uint8_t	plain[TLS_MAX_FRAGMENT_LEN];
	size_t	plainLen;
	uint8_t	innerType;
	int		ret;

	if (!ctx || !ctx->isConnected) {
		tlsSetError(ctx, TLS_ERR_PROTOCOL, "Not connected");
		return (-1);
	}

	if (ctx->appDataLen > 0) {
		size_t toCopy = (len < ctx->appDataLen) ? len : ctx->appDataLen;
		ft_memcpy(buf, ctx->appDataBuf, toCopy);
		if (toCopy < ctx->appDataLen)
			ft_memmove(ctx->appDataBuf, ctx->appDataBuf + toCopy,
				   ctx->appDataLen - toCopy);
		ctx->appDataLen -= toCopy;
		return ((ssize_t)toCopy);
	}

	while (1) {
		rawLen = sizeof(rawData);
		ret = tlsIoReadRecord(&ctx->io, rawData, &rawLen);
		if (ret <= 0) {
			int ioErr = ctx->io.ioError;
			if (ioErr == TLS_ERR_WANT_READ) {
				tlsSetError(ctx, TLS_ERR_WANT_READ, "Read would block");
				return (TLS_ERR_WANT_READ);
			}
			if (ioErr == TLS_ERR_EOF) {
				tlsSetError(ctx, TLS_ERR_EOF, "Connection closed");
				return (0);
			}
			tlsSetError(ctx, TLS_ERR_IO, "Failed to read TLS record");
			return (-1);
		}

		contentType = rawData[0];

		if (contentType == TLS_RT_APPLICATION_DATA) {
			plainLen = sizeof(plain);

			if (!tlsRecordDecrypt(&ctx->handshake.appRecvCtx,
						  rawData, rawLen, 0,
						  plain, &plainLen, &innerType)) {
				tlsSetError(ctx, TLS_ERR_DECRYPT,
						"Application data decryption failed");
				return (-1);
			}

			if (innerType == TLS_RT_ALERT) {
				if (tlsHandleAlert(ctx, plain, plainLen) < 0)
					return (-1);
				continue;
			}
			if (innerType != TLS_RT_APPLICATION_DATA) {
				tlsSetError(ctx, TLS_ERR_PROTOCOL,
						"Unexpected inner content type");
				return (-1);
			}

			size_t copyLen = (len < plainLen) ? len : plainLen;
			ft_memcpy(buf, plain, copyLen);
			if (copyLen < plainLen) {
				ft_memcpy(ctx->appDataBuf, plain + copyLen,
					  plainLen - copyLen);
				ctx->appDataLen = plainLen - copyLen;
			}
			return ((ssize_t)copyLen);
		}
		else if (contentType == TLS_RT_ALERT) {
			if (tlsHandleAlert(ctx, rawData + TLS_RECORD_HEADER_SIZE,
					   rawLen - TLS_RECORD_HEADER_SIZE) < 0)
				return (-1);
			continue;
		}
		else {
			tlsSetError(ctx, TLS_ERR_PROTOCOL,
					"Unexpected content type during read");
			return (-1);
		}
	}
}

ssize_t tlsWrite(t_tlsCtx *ctx, const uint8_t *buf, size_t len)
{
	if (!ctx || !ctx->isConnected) {
		tlsSetError(ctx, TLS_ERR_PROTOCOL, "Not connected");
		return (-1);
	}

	size_t sent = 0;
	while (sent < len) {
		size_t chunkLen = len - sent;
		if (chunkLen > TLS_MAX_FRAGMENT_LEN - 1)
			chunkLen = TLS_MAX_FRAGMENT_LEN - 1;

		t_tlsRecord record;
		if (!tlsRecordBuild(TLS_RT_APPLICATION_DATA, buf + sent, chunkLen, &record)) {
			tlsSetError(ctx, TLS_ERR_INTERNAL, "Failed to build record");
			return (-1);
		}

		uint8_t encrypted[TLS_WRITE_BUFFER_SIZE];
		size_t encryptedLen = sizeof(encrypted);
		if (!tlsRecordEncrypt(&ctx->handshake.appSendCtx,
							  record.fragment, record.fragmentLen,
							  TLS_RT_APPLICATION_DATA, 0,
							  encrypted, &encryptedLen)) {
			tlsRecordFree(&record);
			tlsSetError(ctx, TLS_ERR_INTERNAL, "Failed to encrypt application data");
			return (-1);
		}
		tlsRecordFree(&record);

		int write_ret = tlsIoWriteRecord(&ctx->io, TLS_RT_APPLICATION_DATA,
										 encrypted + TLS_RECORD_HEADER_SIZE,
										 encryptedLen - TLS_RECORD_HEADER_SIZE);
		if (write_ret < 0) {
			tlsSetError(ctx, TLS_ERR_IO, "Failed to queue record");
			return (-1);
		} else if (write_ret == 0) {
			tlsSetError(ctx, TLS_ERR_WANT_WRITE, "Write would block");
			return (sent > 0 ? (ssize_t)sent : TLS_ERR_WANT_WRITE);
		}

		sent += chunkLen;

		int flush_ret = tlsIoFlush(&ctx->io);
		if (flush_ret < 0) {
			tlsSetError(ctx, TLS_ERR_IO, "Failed to flush");
			return (-1);
		}
		if (flush_ret == 0) {
			tlsSetError(ctx, TLS_ERR_WANT_WRITE, "Write would block");
			return (sent);
		}
	}
	return ((ssize_t)sent);
}

int tlsShutdown(t_tlsCtx *ctx)
{
	if (!ctx || !ctx->isConnected) {
		tlsSetError(ctx, TLS_ERR_PROTOCOL, "Not connected");
		return (-1);
	}

	if (!tls13SendAlert(ctx, TLS_ALERT_LEVEL_WARNING, TLS_ALERT_CLOSE_NOTIFY)) {
		tlsSetError(ctx, TLS_ERR_INTERNAL, "Failed to send close_notify");
		return (-1);
	}

	tlsIoFlush(&ctx->io);
	ctx->isConnected = 0;

	return (TLS_SUCCESS);
}
