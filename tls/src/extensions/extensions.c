

#include "../../../hajlib/include/hmemory.h"
#include "../../../hajlib/include/hprintf.h" /* IWYU pragma: keep */
#include "../../../includes/utils/bitopts.h"

#include "../../includes/extensions.h"
#include "../../includes/constants.h"
#include <stdlib.h>

/* --------------- GREASE detection (RFC 8701) --------------- */
static int isGrease(uint16_t value)
{
	uint8_t hi = value >> 8;
	uint8_t lo = value & 0xFF;
	return (hi == lo) && ((hi & 0x0F) == 0x0A);
}

/* --------------- External declarations of all parsers --------------- */
/* From extensions_tls12.c */
extern int parseServerName(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseMaxFragmentLength(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseTrustedCaKeys(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseTruncatedHmac(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseStatusRequest(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseUserMapping(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseClientAuthz(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseServerAuthz(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseCertType(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseSupportedGroups(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseEcPointFormats(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseSrp(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseSignatureAlgorithms(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseUseSrtp(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseHeartbeat(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseAlpn(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseStatusRequestV2(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseSct(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseClientCertType(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseServerCertType(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parsePadding(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseEncryptThenMac(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseExtendedMasterSecret(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseTokenBinding(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseCachedInfo(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseTlsLts(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseRecordSizeLimit(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parsePwdProtect(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parsePwdClear(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parsePasswordSalt(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseTicketPinning(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseTlsCertWithExternPsk(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseSessionTicket(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseTlmsp(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseTlmspProxying(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseTlmspDelegate(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseSupportedEktCiphers(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseTransparencyInfo(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseConnectionIdDeprecated(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseConnectionId(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseExternalIdHash(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseExternalSessionId(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseTicketRequest(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseDnssecChain(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseSeqNumEncryptionAlgs(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseRrc(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseTlsFlags(const uint8_t*, size_t, t_tlsParsedExtensions*, int);

/* From extensions_tls13.c */
extern int parseCompressCertificate(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseDelegatedCredential(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parsePreSharedKey(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseEarlyData(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseSupportedVersions(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseCookie(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parsePskKeyExchangeModes(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseCertificateAuthorities(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseOidFilters(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parsePostHandshakeAuth(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseSignatureAlgsCert(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseKeyShare(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseQuicTransportParams(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseEchOuterExtensions(const uint8_t*, size_t, t_tlsParsedExtensions*, int);
extern int parseEncryptedClientHello(const uint8_t*, size_t, t_tlsParsedExtensions*, int);

/* ============================================================================
 * Dispatch table (ordered by extension type)
 * ============================================================================ */
static const t_tlsExtension g_tlsExtensions[] = {
	{ TLS_EXT_SERVER_NAME,					"server_name",								parseServerName,				TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_MAX_FRAGMENT_LENGTH,			"max_fragment_length",						parseMaxFragmentLength,			TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_TRUSTED_CA_KEYS,				"trusted_ca_keys",							parseTrustedCaKeys,				TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_TRUNCATED_HMAC,				"truncated_hmac",							parseTruncatedHmac,				TLS_VERS_1_2 },
	{ TLS_EXT_STATUS_REQUEST,				"status_request",							parseStatusRequest,				TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_USER_MAPPING,					"user_mapping",								parseUserMapping,				TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_CLIENT_AUTHZ,					"client_authz",								parseClientAuthz,				TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_SERVER_AUTHZ,					"server_authz",								parseServerAuthz,				TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_CERT_TYPE,					"cert_type",								parseCertType,					TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_SUPPORTED_GROUPS,				"supported_groups",							parseSupportedGroups,			TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_EC_POINT_FORMATS,			"ec_point_formats",							parseEcPointFormats,			TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_SRP,							"srp",										parseSrp,						TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_SIGNATURE_ALGORITHMS,		"signature_algorithms",						parseSignatureAlgorithms,		TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_USE_SRTP,					"use_srtp",									parseUseSrtp,					TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_HEARTBEAT,					"heartbeat",								parseHeartbeat,					TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_ALPN,						"application_layer_protocol_negotiation",	parseAlpn,						TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_STATUS_REQUEST_V2,			"status_request_v2",						parseStatusRequestV2,			TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_SIGNED_CERT_TIMESTAMP,		"signed_certificate_timestamp",				parseSct,						TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_CLIENT_CERTIFICATE_TYPE,		"client_certificate_type",					parseClientCertType,			TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_SERVER_CERTIFICATE_TYPE,		"server_certificate_type",					parseServerCertType,			TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_PADDING,						"padding",									parsePadding,					TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_ENCRYPT_THEN_MAC,			"encrypt_then_mac",							parseEncryptThenMac,			TLS_VERS_1_2 },
	{ TLS_EXT_EXTENDED_MASTER_SECRET,		"extended_master_secret",					parseExtendedMasterSecret,		TLS_VERS_1_2 },
	{ TLS_EXT_TOKEN_BINDING,				"token_binding",							parseTokenBinding,				TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_CACHED_INFO,					"cached_info",								parseCachedInfo,				TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_TLS_LTS,						"tls_lts",									parseTlsLts,					TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_COMPRESS_CERTIFICATE,		"compress_certificate",						parseCompressCertificate,		TLS_VERS_1_3 },
	{ TLS_EXT_RECORD_SIZE_LIMIT,			"record_size_limit",						parseRecordSizeLimit,			TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_PWD_PROTECT,					"pwd_protect",								parsePwdProtect,				TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_PWD_CLEAR,					"pwd_clear",								parsePwdClear,					TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_PASSWORD_SALT,				"password_salt",							parsePasswordSalt,				TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_TICKET_PINNING,				"ticket_pinning",							parseTicketPinning,				TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_TLS_CERT_WITH_EXTERN_PSK,	"tls_cert_with_extern_psk",					parseTlsCertWithExternPsk,		TLS_VERS_1_3 },
	{ TLS_EXT_DELEGATED_CREDENTIAL,		"delegated_credential",						parseDelegatedCredential,		TLS_VERS_1_3 },
	{ TLS_EXT_SESSION_TICKET,				"session_ticket",							parseSessionTicket,				TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_TLSP,						"tlsp",										parseTlmsp,						TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_TLSP_PROXYING,				"tlsp_proxying",							parseTlmspProxying,				TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_TLSP_DELEGATE,				"tlsp_delegate",							parseTlmspDelegate,				TLS_VERS_1_2 | TLS_VERS_1_3 },
	{ TLS_EXT_SUPPORTED_EKT_CIPHERS,		"supported_ekt_ciphers",					parseSupportedEktCiphers,		TLS_VERS_1_2 | TLS_VERS_1_3 },
	/* 40 reserved */
	{ TLS_EXT_PRE_SHARED_KEY,				"pre_shared_key",							parsePreSharedKey,				TLS_VERS_1_3 },
	{ TLS_EXT_EARLY_DATA,					"early_data",								parseEarlyData,					TLS_VERS_1_3 },
	{ TLS_EXT_SUPPORTED_VERSIONS,			"supported_versions",						parseSupportedVersions,			TLS_VERS_1_3 },
	{ TLS_EXT_COOKIE,						"cookie",									parseCookie,					TLS_VERS_1_3 },
	{ TLS_EXT_PSK_KEY_EXCHANGE_MODES,		"psk_key_exchange_modes",					parsePskKeyExchangeModes,		TLS_VERS_1_3 },
	/* 46 reserved */
	{ TLS_EXT_CERTIFICATE_AUTHORITIES,		"certificate_authorities",					parseCertificateAuthorities,	TLS_VERS_1_3 },
	{ TLS_EXT_OID_FILTERS,					"oid_filters",								parseOidFilters,				TLS_VERS_1_3 },
	{ TLS_EXT_POST_HANDSHAKE_AUTH,			"post_handshake_auth",						parsePostHandshakeAuth,			TLS_VERS_1_3 },
	{ TLS_EXT_SIGNATURE_ALGORITHMS_CERT,	"signature_algorithms_cert",				parseSignatureAlgsCert,			TLS_VERS_1_3 },
	{ TLS_EXT_KEY_SHARE,					"key_share",								parseKeyShare,					TLS_VERS_1_3 },
	{ TLS_EXT_TRANSPARENCY_INFO,			"transparency_info",						parseTransparencyInfo,			TLS_VERS_1_3 },
	{ TLS_EXT_CONNECTION_ID_DEPRECATED,	"connection_id_deprecated",					parseConnectionIdDeprecated,	TLS_VERS_1_3 },
	{ TLS_EXT_CONNECTION_ID,				"connection_id",							parseConnectionId,				TLS_VERS_1_3 },
	{ TLS_EXT_EXTERNAL_ID_HASH,			"external_id_hash",							parseExternalIdHash,			TLS_VERS_1_3 },
	{ TLS_EXT_EXTERNAL_SESSION_ID,			"external_session_id",						parseExternalSessionId,			TLS_VERS_1_3 },
	{ TLS_EXT_QUIC_TRANSPORT_PARAMS,		"quic_transport_params",					parseQuicTransportParams,		TLS_VERS_1_3 },
	{ TLS_EXT_TICKET_REQUEST,				"ticket_request",							parseTicketRequest,				TLS_VERS_1_3 },
	{ TLS_EXT_DNSSEC_CHAIN,				"dnssec_chain",								parseDnssecChain,				TLS_VERS_1_3 },
	{ TLS_EXT_SNEA,						"sequence_number_encryption_algorithms",	parseSeqNumEncryptionAlgs,		TLS_VERS_1_3 },
	{ TLS_EXT_RRC,							"rrc",										parseRrc,						TLS_VERS_1_3 },
	{ TLS_EXT_TLS_FLAGS,					"tls_flags",								parseTlsFlags,					TLS_VERS_1_3 },
	{ TLS_EXT_ECH_OUTER_EXTENSIONS,		"ech_outer_extensions",						parseEchOuterExtensions,		TLS_VERS_1_3 },
	{ TLS_EXT_ENCRYPTED_CLIENT_HELLO,		"encrypted_client_hello",					parseEncryptedClientHello,		TLS_VERS_1_3 },
	{ 0,									NULL,										NULL,							0 }
};

#define NUM_EXTENSIONS (sizeof(g_tlsExtensions) / sizeof(g_tlsExtensions[0]) - 1) /* Exclude sentinel */



int tlsParseExtensions(const uint8_t *data, size_t dataLen, t_tlsParsedExtensions *out, int isServerHello)
{
	const uint8_t *ptr = data;
	size_t remaining = dataLen;
	if (!data || !out) return (0);
	ft_bzero(out, sizeof(t_tlsParsedExtensions));
	while (remaining >= 4) {
		uint16_t extType = readUint16(ptr);
		uint16_t extLen = readUint16(ptr + 2);
		if (remaining < 4 + (size_t)extLen) {
			BTLS_DEBUG("Extension truncated: remaining=%zu, need=%zu", remaining, 4 + extLen);
			break;
		}
		if (isGrease(extType))
			BTLS_DEBUG("GREASE extension type 0x%04x", extType);
		int found = 0;
		for (size_t i = 0; i < NUM_EXTENSIONS; i++) {
			if (g_tlsExtensions[i].type == extType) {
				found = 1;
				if (!g_tlsExtensions[i].parser(ptr + 4, extLen, out, isServerHello))
					BTLS_DEBUG("Failed to parse extension %s (0x%04x)", g_tlsExtensions[i].name, extType);
				break;
			}
		}
		if (!found && !isGrease(extType))
			BTLS_DEBUG("Unknown extension type 0x%04x (len=%u)", extType, extLen);
		ptr += 4 + extLen;
		remaining -= 4 + extLen;
	}
	return (1);
}

void tlsFreeParsedExtensions(t_tlsParsedExtensions *ext)
{
	if (!ext) return;
	free(ext->supportedGroups);
	free(ext->signatureAlgs);
	free(ext->signatureAlgsCert);
	free(ext->sessionTicket);
	free(ext->sni.hostname);
	for (size_t i = 0; i < ext->certAuthorities.numNames; i++)
		free(ext->certAuthorities.distinguishedNames[i]);
	free(ext->certAuthorities.distinguishedNames);
	free(ext->certAuthorities.nameLens);
	for (size_t i = 0; i < ext->alpn.numProtocols; i++)
		free(ext->alpn.protocols[i]);
	free(ext->alpn.protocols);
	free(ext->alpn.selected);
	if (ext->ecPointFormats)
	{
		free(ext->ecPointFormats);
		ext->ecPointFormats = NULL;
	}
	free(ext->ocsp.response);
	for (size_t i = 0; i < ext->ocspV2.numResponses; i++)
		free(ext->ocspV2.responses[i].response);
	free(ext->ocspV2.responses);
	for (size_t i = 0; i < ext->sct.numScts; i++)
		free(ext->sct.scts[i].timestamp);
	free(ext->sct.scts);
	free(ext->clientCertType.types);
	free(ext->serverCertType.types);
	free(ext->tokenBinding.params);
	free(ext->cachedInfo.cachedInfo);
	free(ext->ticketPinning.ticket_pin);
	free(ext->supportedEktCiphers.ciphers);
	free(ext->externalIdHash.hash);
	free(ext->externalSessionId.sessionId);
	free(ext->connectionId.cid);
	free(ext->connectionId.peerCid);
	free(ext->rrc.challenge);
	free(ext->ech.enc);
	free(ext->ech.config_id);
	free(ext->ech.payload);
	free(ext->echOuterExtensions.extensionTypes);
	free(ext->quicParams.params);
	free(ext->delegatedCredential.credential);
	free(ext->delegatedCredential.signature);
	free(ext->earlyData);
	free(ext->cookie.cookie);
	for (size_t i = 0; i < ext->oidFilters.numOids; i++)
		free(ext->oidFilters.oidValues[i]);
	free(ext->oidFilters.oidValues);
	free(ext->oidFilters.oidLengths);
	free(ext->renegotiationInfo.renegotiatedConnection);
	for (size_t i = 0; i < ext->numKeyShares; i++)
		free(ext->keyShares[i].key);
	free(ext->keyShares);
	for (size_t i = 0; i < ext->numPsks; i++) {
		free(ext->psks[i].identity);
		free(ext->psks[i].binder);
	}
	free(ext->psks);
	free(ext->srtp.profiles);
	free(ext->srtp.mki);
	ft_bzero(ext, sizeof(t_tlsParsedExtensions));
}
