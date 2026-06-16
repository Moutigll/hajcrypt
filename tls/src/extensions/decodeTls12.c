#include <stdlib.h>

#include "../../../hajlib/include/hmemory.h"
#include "../../../hajlib/include/hprintf.h" /* IWYU pragma: keep */
#include "../../../includes/utils/bitopts.h"
#include "../../includes/constants.h"

#include "../../includes/extensions.h"

/* 0 - server_name (SNI) */
int parseServerName(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 3) return (1);
	size_t listLen = readUint16(data);
	if (len < 2 + listLen) return (1);
	const uint8_t *ptr = data + 2;
	size_t remaining = listLen;
	while (remaining >= 3) {
		uint8_t		nameType = ptr[0];
		uint16_t	nameLen = readUint16(ptr + 1);
		if (remaining < 3 + (size_t)nameLen) break;
		if (nameType == 0) { /* host_name */
			out->sni.hostname = malloc(nameLen + 1);
			if (!out->sni.hostname) return (0);
			ft_memcpy(out->sni.hostname, ptr + 3, nameLen);
			out->sni.hostname[nameLen] = '\0';
			return (1);
		}
		ptr += 3 + nameLen;
		remaining -= 3 + nameLen;
	}
	return (1);
}

/* 1 - max_fragment_length */
int parseMaxFragmentLength(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 1) return (1);
	uint8_t code = data[0];
	switch (code) {
		case 1: out->maxFragmentLength.length = 512; break;
		case 2: out->maxFragmentLength.length = 1024; break;
		case 3: out->maxFragmentLength.length = 2048; break;
		case 4: out->maxFragmentLength.length = 4096; break;
		default: out->maxFragmentLength.length = 16384; break;
	}
	return (1);
}

/* 3 - trusted_ca_keys (deprecated) */
int parseTrustedCaKeys(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)data; (void)len; (void)out; (void)isServer;
	BTLS_DEBUG("Parsing trusted_ca_keys: Not implemented yet !!!");
	return (1);
}

/* 4 - truncated_hmac (deprecated) */
int parseTruncatedHmac(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)data; (void)len; (void)out; (void)isServer;
	BTLS_DEBUG("Parsing truncated_hmac: Not implemented yet !!!");
	return (1);
}

/* 5 - status_request (OCSP stapling) */
int parseStatusRequest(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 1) return (1);
	uint8_t statusType = data[0];
	if (statusType == 1) {
		out->ocsp.requested = 1;
	}
	return (1);
}

/* 6 - user_mapping (RFC 4681) */
int parseUserMapping(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)data; (void)len; (void)out; (void)isServer;
	BTLS_DEBUG("Parsing user_mapping: Not implemented yet !!!");
	return (1);
}

/* 7 - client_authz */
int parseClientAuthz(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)data; (void)len; (void)out; (void)isServer;
	BTLS_DEBUG("Parsing client_authz: Not implemented yet !!!");
	return (1);
}

/* 8 - server_authz */
int parseServerAuthz(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)data; (void)len; (void)out; (void)isServer;
	BTLS_DEBUG("Parsing server_authz: Not implemented yet !!!");
	return (1);
}

/* 9 - cert_type (RFC 6091) */
int parseCertType(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 1) return (1);
	out->clientCertType.numTypes = len;
	out->clientCertType.types = malloc(len);
	if (!out->clientCertType.types) return (0);
	ft_memcpy(out->clientCertType.types, data, len);
	return (1);
}

/* 10 - supported_groups */
int parseSupportedGroups(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 2) return (1);
	size_t listLen = readUint16(data);
	if (len < 2 + listLen) return (1);
	out->numSupportedGroups = listLen / 2;
	out->supportedGroups = malloc(out->numSupportedGroups * sizeof(uint16_t));
	if (!out->supportedGroups) return (0);
	for (size_t i = 0; i < out->numSupportedGroups; i++) {
		out->supportedGroups[i] = readUint16(data + 2 + i*2);
	}
	return (1);
}

/* 11 - ec_point_formats */
int parseEcPointFormats(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	size_t	numFormats;
	size_t	i;

	if (!data || !out)
		return (0);

	if (len < 1)
	{
		BTLS_DEBUG("ec_point_formats: data too short (%zu bytes)", len);
		return (0);
	}

	numFormats = data[0];
	if (numFormats == 0 || numFormats > 255)
	{
		BTLS_DEBUG("ec_point_formats: invalid format count (%zu)", numFormats);
		return (0);
	}

	if (len < 1 + numFormats)
	{
		BTLS_DEBUG("ec_point_formats: truncated data (expected %zu, got %zu)", 1 + numFormats, len);
		return (0);
	}

	out->ecPointFormats = malloc(numFormats * sizeof(uint8_t));
	if (!out->ecPointFormats)
		return (0);

	out->numEcPointFormats = numFormats;

	for (i = 0; i < numFormats; i++)
	{
		uint8_t fmt = data[1 + i];
		
		switch (fmt)
		{
			case 0:  /* uncompressed */
			case 1:  /* ansiX962_compressed_prime (obsolete) */
			case 2:  /* ansiX962_compressed_char2 (obsolete) */
				out->ecPointFormats[i] = fmt;
				break;
			default:
				BTLS_DEBUG("ec_point_formats: unknown format %u at index %zu", fmt, i);
				break;
		}
	}
	return (1);
}

/* 12 - srp */
int parseSrp(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)data; (void)len; (void)out; (void)isServer;
	BTLS_DEBUG("Parsing srp: Not implemented yet !!!");
	return (1);
}

/* 13 - signature_algorithms */
int parseSignatureAlgorithms(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 2) return (1);
	size_t listLen = readUint16(data);
	if (len < 2 + listLen || listLen == 0) return (1);
	out->numSignatureAlgs = listLen / 2;
	out->signatureAlgs = malloc(out->numSignatureAlgs * sizeof(uint16_t));
	if (!out->signatureAlgs) return (0);
	for (size_t i = 0; i < out->numSignatureAlgs; i++) {
		out->signatureAlgs[i] = readUint16(data + 2 + i*2);
	}
	return (1);
}

/* 14 - use_srtp */
int parseUseSrtp(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 4) return (1);
	size_t profLen = readUint16(data);
	if (len < 2 + profLen + 2) return (1);
	out->srtp.numProfiles = profLen / 2;
	out->srtp.profiles = malloc(out->srtp.numProfiles * sizeof(uint16_t));
	if (!out->srtp.profiles) return (0);
	for (size_t i = 0; i < out->srtp.numProfiles; i++) {
		out->srtp.profiles[i] = readUint16(data + 2 + i*2);
	}
	uint8_t mkiLen = data[2 + profLen];
	if (len >= 3 + profLen + mkiLen) {
		out->srtp.mkiLen = mkiLen;
		if (mkiLen) {
			out->srtp.mki = malloc(mkiLen);
			if (!out->srtp.mki) return (0);
			ft_memcpy(out->srtp.mki, data + 3 + profLen, mkiLen);
		}
	}
	return (1);
}

/* 15 - heartbeat */
int parseHeartbeat(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 1) return (1);
	out->heartbeat.supported = 1;
	out->heartbeat.mode = data[0];
	return (1);
}

/* 16 - alpn */
int parseAlpn(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 2) return (1);
	size_t listLen = readUint16(data);
	if (len < 2 + listLen) return (1);
	const uint8_t	*ptr = data + 2;
	size_t			remaining = listLen;
	size_t			count = 0;
	while (remaining >= 1) {
		uint8_t plen = ptr[0];
		if (remaining < 1 + (size_t)plen) break;
		ptr += 1 + plen;
		remaining -= 1 + plen;
		count++;
	}
	out->alpn.numProtocols = count;
	out->alpn.protocols = calloc(count, sizeof(char *));
	if (!out->alpn.protocols) return (0);
	ptr = data + 2;
	remaining = listLen;
	for (size_t i = 0; i < count; i++) {
		uint8_t plen = ptr[0];
		out->alpn.protocols[i] = malloc(plen + 1);
		if (!out->alpn.protocols[i]) return (0);
		ft_memcpy(out->alpn.protocols[i], ptr + 1, plen);
		out->alpn.protocols[i][plen] = '\0';
		ptr += 1 + plen;
	}
	return (1);
}

/* 17 - status_request_v2 */
int parseStatusRequestV2(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 2) return (1);
	size_t listLen = readUint16(data);
	if (len < 2 + listLen) return (1);
	out->ocspV2.requested = 1;
	out->ocspV2.numResponses = 0;
	const uint8_t *ptr = data + 2;
	size_t remaining = listLen;
	while (remaining >= 3) {
		uint8_t statusType = ptr[0];
		uint16_t respLen = readUint16(ptr + 1);
		if (remaining < 3 + (size_t)respLen) break;
		if (statusType == 1) { /* OCSP */
			t_tlsOcspResponseEntry *new_resp = realloc(out->ocspV2.responses,
				(out->ocspV2.numResponses + 1) * sizeof(t_tlsOcspResponseEntry));
			if (!new_resp) return (0);
			out->ocspV2.responses = new_resp;
			out->ocspV2.responses[out->ocspV2.numResponses].response = malloc(respLen);
			if (!out->ocspV2.responses[out->ocspV2.numResponses].response) return (0);
			ft_memcpy(out->ocspV2.responses[out->ocspV2.numResponses].response, ptr + 3, respLen);
			out->ocspV2.responses[out->ocspV2.numResponses].responseLen = respLen;
			out->ocspV2.numResponses++;
		}
		ptr += 3 + respLen;
		remaining -= 3 + respLen;
	}
	return (1);
}

/* 18 - signed_certificate_timestamp (SCT) */
int parseSct(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 2) return (1);
	size_t listLen = readUint16(data);
	if (len < 2 + listLen) return (1);
	out->sct.numScts = 0;
	const uint8_t *ptr = data + 2;
	size_t remaining = listLen;
	while (remaining >= 2) {
		uint16_t sctLen = readUint16(ptr);
		if (remaining < 2 + (size_t)sctLen) break;
		t_tlsSct *new_sct = realloc(out->sct.scts, (out->sct.numScts + 1) * sizeof(t_tlsSct));
		if (!new_sct) return (0);
		out->sct.scts = new_sct;
		out->sct.scts[out->sct.numScts].timestamp = malloc(sctLen);
		if (!out->sct.scts[out->sct.numScts].timestamp) return (0);
		ft_memcpy(out->sct.scts[out->sct.numScts].timestamp, ptr + 2, sctLen);
		out->sct.scts[out->sct.numScts].timestampLen = sctLen;
		out->sct.scts[out->sct.numScts].type = 2; /* TLS SCT */
		out->sct.numScts++;
		ptr += 2 + sctLen;
		remaining -= 2 + sctLen;
	}
	return (1);
}

/* 19 - client_certificate_type */
int parseClientCertType(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 1) return (1);
	out->clientCertType.numTypes = len;
	out->clientCertType.types = malloc(len);
	if (!out->clientCertType.types) return (0);
	ft_memcpy(out->clientCertType.types, data, len);
	return (1);
}

/* 20 - server_certificate_type */
int parseServerCertType(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 1) return (1);
	out->serverCertType.numTypes = len;
	out->serverCertType.types = malloc(len);
	if (!out->serverCertType.types) return (0);
	ft_memcpy(out->serverCertType.types, data, len);
	return (1);
}

/* 21 - padding */
int parsePadding(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)data; (void)isServer;
	out->padding.length = len;
	return (1);
}

/* 22 - encrypt_then_mac (TLS 1.2 only) */
int parseEncryptThenMac(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)data; (void)len; (void)isServer;
	out->encryptThenMac.supported = 1;
	return (1);
}

/* 23 - extended_master_secret */
int parseExtendedMasterSecret(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)data; (void)len; (void)isServer;
	out->extendedMasterSecret.supported = 1;
	return (1);
}

/* 24 - token_binding */
int parseTokenBinding(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 2) return (1);
	out->tokenBinding.paramsLen = len;
	out->tokenBinding.params = malloc(len);
	if (!out->tokenBinding.params) return (0);
	ft_memcpy(out->tokenBinding.params, data, len);
	return (1);
}

/* 25 - cachedInfo */
int parseCachedInfo(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 2) return (1);
	size_t listLen = readUint16(data);
	if (len < 2 + listLen) return (1);
	out->cachedInfo.cachedInfoLen = listLen;
	out->cachedInfo.cachedInfo = malloc(listLen);
	if (!out->cachedInfo.cachedInfo) return (0);
	ft_memcpy(out->cachedInfo.cachedInfo, data + 2, listLen);
	return (1);
}

/* 26 - tls_lts (draft) */
int parseTlsLts(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)data; (void)len; (void)out; (void)isServer;
	BTLS_DEBUG("Parsing tls_lts: Not implemented yet !!!");
	return (1);
}

/* 28 - record_size_limit (shared) */
int parseRecordSizeLimit(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 2) return (1);
	out->recordSizeLimit.enabled = 1;
	out->recordSizeLimit.limit = readUint16(data);
	return (1);
}

/* 29 - pwd_protect */
int parsePwdProtect(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)data; (void)len; (void)out; (void)isServer;
	BTLS_DEBUG("Parsing pwd_protect: Not implemented yet !!!");
	return (1);
}

/* 30 - pwd_clear */
int parsePwdClear(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)data; (void)len; (void)out; (void)isServer;
	BTLS_DEBUG("Parsing pwd_clear: Not implemented yet !!!");
	return (1);
}

/* 31 - password_salt */
int parsePasswordSalt(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)data; (void)len; (void)out; (void)isServer;
	BTLS_DEBUG("Parsing password_salt: Not implemented yet !!!");
	return (1);
}

/* 32 - ticket_pinning */
int parseTicketPinning(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 2) return (1);
	size_t pin_len = readUint16(data);
	if (len < 2 + pin_len) return (1);
	out->ticketPinning.pinLen = pin_len;
	out->ticketPinning.ticket_pin = malloc(pin_len);
	if (!out->ticketPinning.ticket_pin) return (0);
	ft_memcpy(out->ticketPinning.ticket_pin, data + 2, pin_len);
	return (1);
}

/* 33 - tls_cert_with_extern_psk (shared) */
int parseTlsCertWithExternPsk(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)data; (void)len; (void)out; (void)isServer;
	BTLS_DEBUG("Parsing tls_cert_with_extern_psk: Not implemented yet !!!");
	return (1);
}

/* 35 - session_ticket (RFC 5077) */
int parseSessionTicket(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	if (!isServer && len > 0) {
		out->sessionTicketLen = len;
		out->sessionTicket = malloc(len);
		if (!out->sessionTicket) return (0);
		ft_memcpy(out->sessionTicket, data, len);
	}
	return (1);
}

/* 36,37,38 - TLMSP */
int parseTlmsp(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)data; (void)len; (void)out; (void)isServer;
	BTLS_DEBUG("Parsing TLMSP: Not implemented yet !!!");
	return (1);
}
int parseTlmspProxying(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer) { return parseTlmsp(data, len, out, isServer); }
int parseTlmspDelegate(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer) { return parseTlmsp(data, len, out, isServer); }

/* 39 - supported_ekt_ciphers */
int parseSupportedEktCiphers(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 2) return (1);
	size_t listLen = readUint16(data);
	if (len < 2 + listLen) return (1);
	out->supportedEktCiphers.numCiphers = listLen / 2;
	out->supportedEktCiphers.ciphers = malloc(out->supportedEktCiphers.numCiphers * sizeof(uint16_t));
	if (!out->supportedEktCiphers.ciphers) return (0);
	for (size_t i = 0; i < out->supportedEktCiphers.numCiphers; i++) {
		out->supportedEktCiphers.ciphers[i] = readUint16(data + 2 + i*2);
	}
	return (1);
}

/* 52 - transparency_info (ignore) */
int parseTransparencyInfo(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)data; (void)len; (void)out; (void)isServer;
	BTLS_DEBUG("Parsing transparency_info: Not implemented yet !!!");
	return (1);
}

/* 54 - connection_id */
int parseConnectionId(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 2) return (1);
	size_t cid_len = readUint16(data);
	if (len < 2 + cid_len) return (1);
	out->connectionId.cidLen = cid_len;
	out->connectionId.cid = malloc(cid_len);
	if (!out->connectionId.cid) return (0);
	ft_memcpy(out->connectionId.cid, data + 2, cid_len);
	return (1);
}

/* 53 - connection_id (deprecated) */
int parseConnectionIdDeprecated(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	return (parseConnectionId(data, len, out, isServer));
}


/* 55 - external_id_hash */
int parseExternalIdHash(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	out->externalIdHash.hashLen = len;
	out->externalIdHash.hash = malloc(len);
	if (!out->externalIdHash.hash) return (0);
	ft_memcpy(out->externalIdHash.hash, data, len);
	return (1);
}

/* 56 - external_session_id */
int parseExternalSessionId(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	out->externalSessionId.idLen = len;
	out->externalSessionId.sessionId = malloc(len);
	if (!out->externalSessionId.sessionId) return (0);
	ft_memcpy(out->externalSessionId.sessionId, data, len);
	return (1);
}

/* 58 - ticket_request */
int parseTicketRequest(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)data; (void)len; (void)isServer;
	out->ticketRequest.request = 1;
	return (1);
}

/* 59 - dnssec_chain (ignore) */
int parseDnssecChain(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)data; (void)len; (void)out; (void)isServer;
	BTLS_DEBUG("Parsing dnssec_chain: Not implemented yet !!!");
	return (1);
}

/* 60 - seq_num_encryption_algs (ignore) */
int parseSeqNumEncryptionAlgs(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)data; (void)len; (void)out; (void)isServer;
	BTLS_DEBUG("Parsing seq_num_encryption_algs: Not implemented yet !!!");
	return (1);
}

/* 61 - rrc */
int parseRrc(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 2) return (1);
	size_t challenge_len = readUint16(data);
	if (len < 2 + challenge_len) return (1);
	out->rrc.challengeLen = challenge_len;
	out->rrc.challenge = malloc(challenge_len);
	if (!out->rrc.challenge) return (0);
	ft_memcpy(out->rrc.challenge, data + 2, challenge_len);
	return (1);
}

/* 62 - tls_flags */
int parseTlsFlags(const uint8_t *data, size_t len, t_tlsExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 8) return (1);
	out->tlsFlags.flags = 0;
	for (size_t i = 0; i < 8; i++) {
		out->tlsFlags.flags = (out->tlsFlags.flags << 8) | data[i];
	}
	return (1);
}
