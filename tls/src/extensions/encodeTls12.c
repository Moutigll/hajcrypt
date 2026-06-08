
#include "../../../hajlib/include/hmemory.h"
#include "../../../hajlib/include/hprintf.h" /* IWYU pragma: keep */
#include "../../../hajlib/include/hstring.h"
#include "../../../includes/utils/bitopts.h"
#include "../../includes/constants.h"

#include "../../includes/extensions.h"

void encSni(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e, int isServer)
{
	if (!e->sni.hostname) return;
	if (isServer) { putExt(out, pos, TLS_EXT_SERVER_NAME, NULL, 0); return; }
	size_t hlen = ft_strlen(e->sni.hostname);
	size_t dlen = 2 + 1 + 2 + hlen;
	wU16(out, *pos, TLS_EXT_SERVER_NAME);
	wU16(out, *pos + 2, (uint16_t)dlen);
	wU16(out, *pos + 4, (uint16_t)(3 + hlen));
	wU8 (out, *pos + 6, 0);
	wU16(out, *pos + 7, (uint16_t)hlen);
	wBytes(out, *pos + 9, e->sni.hostname, hlen);
	*pos += 4 + dlen;
}

void encMaxFragLen(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	uint8_t code;
	switch (e->maxFragmentLength.length) {
		case  512: code = 1; break;
		case 1024: code = 2; break;
		case 2048: code = 3; break;
		case 4096: code = 4; break;
		default:   return;
	}
	putExt(out, pos, TLS_EXT_MAX_FRAGMENT_LENGTH, &code, 1);
}

void encTrustedCaKeys(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	(void)out; (void)pos; (void)e;
	BTLS_DEBUG("Encoding trusted_ca_keys: not implemented");
}

void encTruncatedHmac(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	(void)out; (void)pos; (void)e;
	BTLS_DEBUG("Encoding truncated_hmac: not implemented");
}

void encStatusRequest(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e, int isServer)
{
	if (!e->ocsp.requested) return;
	if (isServer) { putExt(out, pos, TLS_EXT_STATUS_REQUEST, NULL, 0); return; }
	static const uint8_t d[5] = { 1, 0, 0, 0, 0 };
	putExt(out, pos, TLS_EXT_STATUS_REQUEST, d, sizeof(d));
}

void encUserMapping(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	(void)out; (void)pos; (void)e;
	BTLS_DEBUG("Encoding user_mapping: not implemented");
}

void encClientAuthz(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	(void)out; (void)pos; (void)e;
	BTLS_DEBUG("Encoding client_authz: not implemented");
}

void encServerAuthz(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	(void)out; (void)pos; (void)e;
	BTLS_DEBUG("Encoding server_authz: not implemented");
}

void encCertType(uint8_t *out, size_t *pos, uint16_t extType, const uint8_t *types, size_t numTypes)
{
	if (numTypes && types) putExt(out, pos, extType, types, numTypes);
}

void encSupportedGroups(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	if (e->numSupportedGroups && e->supportedGroups)
		ENC_U16_LIST(out, pos, TLS_EXT_SUPPORTED_GROUPS, e->supportedGroups, e->numSupportedGroups);
}

void encEcPointFormats(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	if (!e->numEcPointFormats || !e->ecPointFormats) return;
	size_t dlen = 1 + e->numEcPointFormats;
	wU16(out, *pos, TLS_EXT_EC_POINT_FORMATS);
	wU16(out, *pos + 2, (uint16_t)dlen);
	wU8 (out, *pos + 4, (uint8_t)e->numEcPointFormats);
	wBytes(out, *pos + 5, e->ecPointFormats, e->numEcPointFormats);
	*pos += 4 + dlen;
}

void encSrp(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	(void)out; (void)pos; (void)e;
	BTLS_DEBUG("Encoding srp: not implemented");
}

void encSigAlgs(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	if (e->numSignatureAlgs && e->signatureAlgs)
		ENC_U16_LIST(out, pos, TLS_EXT_SIGNATURE_ALGORITHMS, e->signatureAlgs, e->numSignatureAlgs);
}

void encUseSrtp(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	if (!e->srtp.numProfiles || !e->srtp.profiles) return;
	size_t profLen = e->srtp.numProfiles * 2;
	size_t dlen = 2 + profLen + 1 + e->srtp.mkiLen;
	wU16(out, *pos, TLS_EXT_USE_SRTP);
	wU16(out, *pos + 2, (uint16_t)dlen);
	wU16(out, *pos + 4, (uint16_t)profLen);
	for (size_t i = 0; i < e->srtp.numProfiles; i++)
		wU16(out, *pos + 6 + i * 2, e->srtp.profiles[i]);
	wU8 (out, *pos + 6 + profLen, (uint8_t)e->srtp.mkiLen);
	wBytes(out, *pos + 7 + profLen, e->srtp.mki, e->srtp.mkiLen);
	*pos += 4 + dlen;
}

void encHeartbeat(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	if (e->heartbeat.supported) putExt(out, pos, TLS_EXT_HEARTBEAT, &e->heartbeat.mode, 1);
}

void encAlpn(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e, int isServer)
{
	if (isServer) {
		if (!e->alpn.selected) return;
		size_t plen = ft_strlen(e->alpn.selected);
		size_t dlen = 2 + 1 + plen;
		wU16(out, *pos, TLS_EXT_ALPN);
		wU16(out, *pos + 2, (uint16_t)dlen);
		wU16(out, *pos + 4, (uint16_t)(1 + plen));
		wU8 (out, *pos + 6, (uint8_t)plen);
		wBytes(out, *pos + 7, e->alpn.selected, plen);
		*pos += 4 + dlen;
		return;
	}
	if (!e->alpn.numProtocols || !e->alpn.protocols) return;
	size_t listLen = 0;
	for (size_t i = 0; i < e->alpn.numProtocols; i++)
		if (e->alpn.protocols[i]) listLen += 1 + ft_strlen(e->alpn.protocols[i]);
	wU16(out, *pos, TLS_EXT_ALPN);
	wU16(out, *pos + 2, (uint16_t)(2 + listLen));
	wU16(out, *pos + 4, (uint16_t)listLen);
	size_t off = *pos + 6;
	for (size_t i = 0; i < e->alpn.numProtocols; i++) {
		if (!e->alpn.protocols[i]) continue;
		size_t plen = ft_strlen(e->alpn.protocols[i]);
		wU8(out, off, (uint8_t)plen);
		wBytes(out, off + 1, e->alpn.protocols[i], plen);
		off += 1 + plen;
	}
	*pos += 4 + 2 + listLen;
}

void encStatusRequestV2(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e, int isServer)
{
	if (!e->ocspV2.requested) return;
	if (isServer || !e->ocspV2.numResponses) { putExt(out, pos, TLS_EXT_STATUS_REQUEST_V2, NULL, 0); return; }
	size_t listLen = 0;
	for (size_t i = 0; i < e->ocspV2.numResponses; i++)
		listLen += 1 + 2 + e->ocspV2.responses[i].responseLen;
	size_t dlen = 2 + listLen;
	wU16(out, *pos, TLS_EXT_STATUS_REQUEST_V2);
	wU16(out, *pos + 2, (uint16_t)dlen);
	wU16(out, *pos + 4, (uint16_t)listLen);
	size_t off = *pos + 6;
	for (size_t i = 0; i < e->ocspV2.numResponses; i++) {
		wU8 (out, off, 1);
		wU16(out, off + 1, (uint16_t)e->ocspV2.responses[i].responseLen);
		wBytes(out, off + 3, e->ocspV2.responses[i].response, e->ocspV2.responses[i].responseLen);
		off += 3 + e->ocspV2.responses[i].responseLen;
	}
	*pos += 4 + dlen;
}

void encSct(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	if (!e->sct.numScts || !e->sct.scts) return;
	size_t listLen = 0;
	for (size_t i = 0; i < e->sct.numScts; i++)
		listLen += 2 + e->sct.scts[i].timestampLen;
	wU16(out, *pos, TLS_EXT_SIGNED_CERT_TIMESTAMP);
	wU16(out, *pos + 2, (uint16_t)(2 + listLen));
	wU16(out, *pos + 4, (uint16_t)listLen);
	size_t off = *pos + 6;
	for (size_t i = 0; i < e->sct.numScts; i++) {
		wU16(out, off, (uint16_t)e->sct.scts[i].timestampLen);
		wBytes(out, off + 2, e->sct.scts[i].timestamp, e->sct.scts[i].timestampLen);
		off += 2 + e->sct.scts[i].timestampLen;
	}
	*pos += 4 + 2 + listLen;
}

void encPadding(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	if (!e->padding.length) return;
	wU16(out, *pos, TLS_EXT_PADDING);
	wU16(out, *pos + 2, (uint16_t)e->padding.length);
	if (out) ft_bzero(out + *pos + 4, e->padding.length);
	*pos += 4 + e->padding.length;
}

void encEncryptThenMac(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	if (e->encryptThenMac.supported) putExt(out, pos, TLS_EXT_ENCRYPT_THEN_MAC, NULL, 0);
}

void encExtendedMasterSecret(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	if (e->extendedMasterSecret.supported) putExt(out, pos, TLS_EXT_EXTENDED_MASTER_SECRET, NULL, 0);
}

void encTokenBinding(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	if (e->tokenBinding.paramsLen && e->tokenBinding.params)
		putExt(out, pos, TLS_EXT_TOKEN_BINDING, e->tokenBinding.params, e->tokenBinding.paramsLen);
}

void encCachedInfo(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	if (!e->cachedInfo.cachedInfoLen || !e->cachedInfo.cachedInfo) return;
	size_t dlen = 2 + e->cachedInfo.cachedInfoLen;
	wU16(out, *pos, TLS_EXT_CACHED_INFO);
	wU16(out, *pos + 2, (uint16_t)dlen);
	wU16(out, *pos + 4, (uint16_t)e->cachedInfo.cachedInfoLen);
	wBytes(out, *pos + 6, e->cachedInfo.cachedInfo, e->cachedInfo.cachedInfoLen);
	*pos += 4 + dlen;
}

void encTlsLts(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	(void)out; (void)pos; (void)e;
	BTLS_DEBUG("Encoding tls_lts: not implemented");
}

void encRecordSizeLimit(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	if (e->recordSizeLimit.enabled) {
		uint8_t d[2]; wU16(d, 0, e->recordSizeLimit.limit);
		putExt(out, pos, TLS_EXT_RECORD_SIZE_LIMIT, d, 2);
	}
}

void encPwdProtect(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	(void)out; (void)pos; (void)e;
	BTLS_DEBUG("Encoding pwd_protect: not implemented");
}

void encPwdClear(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	(void)out; (void)pos; (void)e;
	BTLS_DEBUG("Encoding pwd_clear: not implemented");
}

void encPasswordSalt(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	(void)out; (void)pos; (void)e;
	BTLS_DEBUG("Encoding password_salt: not implemented");
}

void encTicketPinning(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	if (!e->ticketPinning.pinLen || !e->ticketPinning.ticket_pin) return;
	size_t dlen = 2 + e->ticketPinning.pinLen;
	wU16(out, *pos, TLS_EXT_TICKET_PINNING);
	wU16(out, *pos + 2, (uint16_t)dlen);
	wU16(out, *pos + 4, (uint16_t)e->ticketPinning.pinLen);
	wBytes(out, *pos + 6, e->ticketPinning.ticket_pin, e->ticketPinning.pinLen);
	*pos += 4 + dlen;
}

void encTlsCertWithExternPsk(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	(void)out; (void)pos; (void)e;
	BTLS_DEBUG("Encoding tls_cert_with_extern_psk: not implemented");
}

void encSessionTicket(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e, int isServer)
{
	(void)isServer;
	if (e->sessionTicket || e->sessionTicketLen)
		putExt(out, pos, TLS_EXT_SESSION_TICKET, e->sessionTicket, e->sessionTicketLen);
}

void encTlsp(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	(void)out; (void)pos; (void)e;
	BTLS_DEBUG("Encoding tlsp: not implemented");
}

void encTlspProxying(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	(void)out; (void)pos; (void)e;
	BTLS_DEBUG("Encoding tlsp_proxying: not implemented");
}

void encTlspDelegate(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	(void)out; (void)pos; (void)e;
	BTLS_DEBUG("Encoding tlsp_delegate: not implemented");
}

void encSupportedEktCiphers(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e)
{
	if (e->supportedEktCiphers.numCiphers && e->supportedEktCiphers.ciphers)
		ENC_U16_LIST(out, pos, TLS_EXT_SUPPORTED_EKT_CIPHERS, e->supportedEktCiphers.ciphers, e->supportedEktCiphers.numCiphers);
}
