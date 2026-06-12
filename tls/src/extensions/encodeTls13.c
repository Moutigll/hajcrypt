#include "../../../hajlib/include/hprintf.h" /* IWYU pragma: keep */
#include "../../../includes/utils/bitopts.h"
#include "../../includes/extensions.h"
#include "../../includes/constants.h"

void encCompressCert(uint8_t *out, size_t *pos, const t_tlsExtensions *e)
{
	if (e->certCompression.enabled && e->certCompression.numAlgorithms)
		ENC_U16_LIST(out, pos, TLS_EXT_COMPRESS_CERTIFICATE, e->certCompression.algorithms, e->certCompression.numAlgorithms);
}

void encDelegatedCredential(uint8_t *out, size_t *pos, const t_tlsExtensions *e)
{
	if (e->delegatedCredential.credentialLen && e->delegatedCredential.credential)
		putExt(out, pos, TLS_EXT_DELEGATED_CREDENTIAL, e->delegatedCredential.credential, e->delegatedCredential.credentialLen);
}

void encPreSharedKey(uint8_t *out, size_t *pos, const t_tlsExtensions *e, int isServer)
{
	if (!e->numPsks || !e->psks) return;
	if (isServer) {
		uint8_t d[2]; wU16(d, 0, 0);
		putExt(out, pos, TLS_EXT_PRE_SHARED_KEY, d, 2);
		return;
	}
	size_t identLen = 0, bindLen = 0;
	for (size_t i = 0; i < e->numPsks; i++) {
		if (e->psks[i].identity) identLen += 2 + e->psks[i].identityLen + 4;
		if (e->psks[i].binder)   bindLen  += 1 + e->psks[i].binderLen;
	}
	size_t dlen = 2 + identLen + 2 + bindLen;
	wU16(out, *pos, TLS_EXT_PRE_SHARED_KEY);
	wU16(out, *pos + 2, (uint16_t)dlen);
	wU16(out, *pos + 4, (uint16_t)identLen);
	size_t off = *pos + 6;
	for (size_t i = 0; i < e->numPsks; i++) {
		if (!e->psks[i].identity) continue;
		wU16(out, off, (uint16_t)e->psks[i].identityLen);
		wBytes(out, off + 2, e->psks[i].identity, e->psks[i].identityLen);
		wU32(out, off + 2 + e->psks[i].identityLen, 0);
		off += 2 + e->psks[i].identityLen + 4;
	}
	wU16(out, off, (uint16_t)bindLen); off += 2;
	for (size_t i = 0; i < e->numPsks; i++) {
		if (!e->psks[i].binder) continue;
		wU8(out, off, (uint8_t)e->psks[i].binderLen);
		wBytes(out, off + 1, e->psks[i].binder, e->psks[i].binderLen);
		off += 1 + e->psks[i].binderLen;
	}
	*pos += 4 + dlen;
}

void encEarlyData(uint8_t *out, size_t *pos, const t_tlsExtensions *e)
{
	if (e->earlyData && e->earlyDataLen)
		putExt(out, pos, TLS_EXT_EARLY_DATA, e->earlyData, e->earlyDataLen);
	else if (e->earlyDataLen) {
		uint8_t d[4]; wU32(d, 0, (uint32_t)e->earlyDataLen);
		putExt(out, pos, TLS_EXT_EARLY_DATA, d, 4);
	}
}

void encSupportedVersions(uint8_t *out, size_t *pos, const t_tlsExtensions *e, int isServer)
{
	if (isServer) {
		if (!e->negotiatedVersion) return;
		uint8_t d[2]; wU16(d, 0, e->negotiatedVersion);
		putExt(out, pos, TLS_EXT_SUPPORTED_VERSIONS, d, 2);
		return;
	}
	if (!e->numSupportedVersions) return;
	size_t versLen = e->numSupportedVersions * 2;
	wU16(out, *pos, TLS_EXT_SUPPORTED_VERSIONS);
	wU16(out, *pos + 2, (uint16_t)(1 + versLen));
	wU8 (out, *pos + 4, (uint8_t)versLen);
	for (size_t i = 0; i < e->numSupportedVersions; i++)
		wU16(out, *pos + 5 + i * 2, e->supportedVersions[i]);
	*pos += 4 + 1 + versLen;
}

void encCookie(uint8_t *out, size_t *pos, const t_tlsExtensions *e)
{
	if (!e->cookie.cookieLen || !e->cookie.cookie) return;
	size_t dlen = 2 + e->cookie.cookieLen;
	wU16(out, *pos, TLS_EXT_COOKIE);
	wU16(out, *pos + 2, (uint16_t)dlen);
	wU16(out, *pos + 4, (uint16_t)e->cookie.cookieLen);
	wBytes(out, *pos + 6, e->cookie.cookie, e->cookie.cookieLen);
	*pos += 4 + dlen;
}

void encPskKeyExchangeModes(uint8_t *out, size_t *pos, const t_tlsExtensions *e)
{
	if (!e->pskKe && !e->pskDheKe) return;
	uint8_t modes[2], cnt = 0;
	if (e->pskKe)	modes[cnt++] = 0;
	if (e->pskDheKe) modes[cnt++] = 1;
	size_t dlen = 1 + cnt;
	wU16(out, *pos, TLS_EXT_PSK_KEY_EXCHANGE_MODES);
	wU16(out, *pos + 2, (uint16_t)dlen);
	wU8 (out, *pos + 4, cnt);
	wBytes(out, *pos + 5, modes, cnt);
	*pos += 4 + dlen;
}

void encCertAuthorities(uint8_t *out, size_t *pos, const t_tlsExtensions *e)
{
	if (!e->certAuthorities.numNames) return;
	size_t listLen = 0;
	for (size_t i = 0; i < e->certAuthorities.numNames; i++)
		listLen += 2 + e->certAuthorities.nameLens[i];
	wU16(out, *pos, TLS_EXT_CERTIFICATE_AUTHORITIES);
	wU16(out, *pos + 2, (uint16_t)(2 + listLen));
	wU16(out, *pos + 4, (uint16_t)listLen);
	size_t off = *pos + 6;
	for (size_t i = 0; i < e->certAuthorities.numNames; i++) {
		wU16(out, off, (uint16_t)e->certAuthorities.nameLens[i]);
		wBytes(out, off + 2, e->certAuthorities.distinguishedNames[i], e->certAuthorities.nameLens[i]);
		off += 2 + e->certAuthorities.nameLens[i];
	}
	*pos += 4 + 2 + listLen;
}

void encOidFilters(uint8_t *out, size_t *pos, const t_tlsExtensions *e)
{
	if (!e->oidFilters.numOids) return;
	size_t listLen = 0;
	for (size_t i = 0; i < e->oidFilters.numOids; i++)
		listLen += 2 + e->oidFilters.oidLengths[i];
	wU16(out, *pos, TLS_EXT_OID_FILTERS);
	wU16(out, *pos + 2, (uint16_t)(2 + listLen));
	wU16(out, *pos + 4, (uint16_t)listLen);
	size_t off = *pos + 6;
	for (size_t i = 0; i < e->oidFilters.numOids; i++) {
		wU16(out, off, (uint16_t)e->oidFilters.oidLengths[i]);
		wBytes(out, off + 2, e->oidFilters.oidValues[i], e->oidFilters.oidLengths[i]);
		off += 2 + e->oidFilters.oidLengths[i];
	}
	*pos += 4 + 2 + listLen;
}

void encPostHandshakeAuth(uint8_t *out, size_t *pos, const t_tlsExtensions *e)
{
	if (e->postHandshakeAuth) putExt(out, pos, TLS_EXT_POST_HANDSHAKE_AUTH, NULL, 0);
}

void encSigAlgsCert(uint8_t *out, size_t *pos, const t_tlsExtensions *e)
{
	if (e->numSignatureAlgsCert && e->signatureAlgsCert)
		ENC_U16_LIST(out, pos, TLS_EXT_SIGNATURE_ALGORITHMS_CERT, e->signatureAlgsCert, e->numSignatureAlgsCert);
}

void encKeyShare(uint8_t *out, size_t *pos, const t_tlsExtensions *e, int isServer)
{
	if (!e->numKeyShares || !e->keyShares) return;
	if (isServer) {
		for (size_t i = 0; i < e->numKeyShares; i++) {
			if (e->keyShares[i].group != e->selectedGroup) continue;
			size_t dlen = 2 + 2 + e->keyShares[i].keyLen;
			wU16(out, *pos, TLS_EXT_KEY_SHARE);
			wU16(out, *pos + 2, (uint16_t)dlen);
			wU16(out, *pos + 4, e->keyShares[i].group);
			wU16(out, *pos + 6, (uint16_t)e->keyShares[i].keyLen);
			wBytes(out, *pos + 8, e->keyShares[i].key, e->keyShares[i].keyLen);
			*pos += 4 + dlen;
			return;
		}
		return;
	}
	size_t sharesLen = 0;
	for (size_t i = 0; i < e->numKeyShares; i++)
		sharesLen += 2 + 2 + e->keyShares[i].keyLen;
	wU16(out, *pos, TLS_EXT_KEY_SHARE);
	wU16(out, *pos + 2, (uint16_t)(2 + sharesLen));
	wU16(out, *pos + 4, (uint16_t)sharesLen);
	size_t off = *pos + 6;
	for (size_t i = 0; i < e->numKeyShares; i++) {
		wU16(out, off, e->keyShares[i].group);
		wU16(out, off + 2, (uint16_t)e->keyShares[i].keyLen);
		wBytes(out, off + 4, e->keyShares[i].key, e->keyShares[i].keyLen);
		off += 4 + e->keyShares[i].keyLen;
	}
	*pos += 4 + 2 + sharesLen;
}

void encTransparencyInfo(uint8_t *out, size_t *pos, const t_tlsExtensions *e)
{
	(void)out; (void)pos; (void)e;
	BTLS_DEBUG("Encoding transparency_info: not implemented");
}

void encConnectionId(uint8_t *out, size_t *pos, const t_tlsExtensions *e)
{
	if (!e->connectionId.cidLen || !e->connectionId.cid) return;
	size_t dlen = 2 + e->connectionId.cidLen;
	wU16(out, *pos, TLS_EXT_CONNECTION_ID);
	wU16(out, *pos + 2, (uint16_t)dlen);
	wU16(out, *pos + 4, (uint16_t)e->connectionId.cidLen);
	wBytes(out, *pos + 6, e->connectionId.cid, e->connectionId.cidLen);
	*pos += 4 + dlen;
}

void encConnectionIdDepr(uint8_t *out, size_t *pos, const t_tlsExtensions *e)
{
	encConnectionId(out, pos, e);   /* reuse the real encoder */
}

void encExternalIdHash(uint8_t *out, size_t *pos, const t_tlsExtensions *e)
{
	if (e->externalIdHash.hashLen && e->externalIdHash.hash)
		putExt(out, pos, TLS_EXT_EXTERNAL_ID_HASH, e->externalIdHash.hash, e->externalIdHash.hashLen);
}

void encExternalSessionId(uint8_t *out, size_t *pos, const t_tlsExtensions *e)
{
	if (e->externalSessionId.idLen && e->externalSessionId.sessionId)
		putExt(out, pos, TLS_EXT_EXTERNAL_SESSION_ID, e->externalSessionId.sessionId, e->externalSessionId.idLen);
}

void encQuicTransportParams(uint8_t *out, size_t *pos, const t_tlsExtensions *e)
{
	if (e->quicParams.paramsLen && e->quicParams.params)
		putExt(out, pos, TLS_EXT_QUIC_TRANSPORT_PARAMS, e->quicParams.params, e->quicParams.paramsLen);
}

void encTicketRequest(uint8_t *out, size_t *pos, const t_tlsExtensions *e)
{
	if (e->ticketRequest.request) putExt(out, pos, TLS_EXT_TICKET_REQUEST, NULL, 0);
}

void encDnssecChain(uint8_t *out, size_t *pos, const t_tlsExtensions *e)
{
	(void)out; (void)pos; (void)e;
	BTLS_DEBUG("Encoding dnssec_chain: not implemented");
}

void encSeqNumEncryptionAlgs(uint8_t *out, size_t *pos, const t_tlsExtensions *e)
{
	(void)out; (void)pos; (void)e;
	BTLS_DEBUG("Encoding sequence_number_encryption_algorithms: not implemented");
}

void encRrc(uint8_t *out, size_t *pos, const t_tlsExtensions *e)
{
	if (!e->rrc.challengeLen || !e->rrc.challenge) return;
	size_t dlen = 2 + e->rrc.challengeLen;
	wU16(out, *pos, TLS_EXT_RRC);
	wU16(out, *pos + 2, (uint16_t)dlen);
	wU16(out, *pos + 4, (uint16_t)e->rrc.challengeLen);
	wBytes(out, *pos + 6, e->rrc.challenge, e->rrc.challengeLen);
	*pos += 4 + dlen;
}

void encTlsFlags(uint8_t *out, size_t *pos, const t_tlsExtensions *e)
{
	if (!e->tlsFlags.flags) return;
	uint8_t d[8];
	for (int i = 0; i < 8; i++)
		d[i] = (e->tlsFlags.flags >> (56 - i * 8)) & 0xFF;
	putExt(out, pos, TLS_EXT_TLS_FLAGS, d, 8);
}

void encEchOuterExtensions(uint8_t *out, size_t *pos, const t_tlsExtensions *e)
{
	if (e->echOuterExtensions.numTypes && e->echOuterExtensions.extensionTypes)
		ENC_U16_LIST(out, pos, TLS_EXT_ECH_OUTER_EXTENSIONS, e->echOuterExtensions.extensionTypes, e->echOuterExtensions.numTypes);
}

void encEch(uint8_t *out, size_t *pos, const t_tlsExtensions *e)
{
	if (e->ech.enabled && e->ech.encLen && e->ech.enc)
		putExt(out, pos, TLS_EXT_ENCRYPTED_CLIENT_HELLO, e->ech.enc, e->ech.encLen);
}
