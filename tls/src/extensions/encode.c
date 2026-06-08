#include "../../includes/extensions.h"

void putExt(uint8_t *out, size_t *pos, uint16_t type, const uint8_t *data, size_t dlen) {
	wU16(out, *pos, type);
	wU16(out, *pos + 2, (uint16_t)dlen);
	wBytes(out, *pos + 4, data, dlen);
	*pos += 4 + dlen;
}




/* ----- Forward declarations - encode_tls12.c ----- */

extern void encSni(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e, int isServer);
extern void encMaxFragLen(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encTrustedCaKeys(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encTruncatedHmac(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encStatusRequest(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e, int isServer);
extern void encUserMapping(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encClientAuthz(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encServerAuthz(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encCertType(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e, int isServer);
extern void encSupportedGroups(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encEcPointFormats(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encSrp(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encSigAlgs(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encUseSrtp(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encHeartbeat(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encAlpn(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e, int isServer);
extern void encStatusRequestV2(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e, int isServer);
extern void encSct(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encPadding(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encEncryptThenMac(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encExtendedMasterSecret(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encTokenBinding(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encCachedInfo(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encTlsLts(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encRecordSizeLimit(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encPwdProtect(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encPwdClear(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encPasswordSalt(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encTicketPinning(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encTlsCertWithExternPsk(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encSessionTicket(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e, int isServer);
extern void encTlsp(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encTlspProxying(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encTlspDelegate(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encSupportedEktCiphers(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);

/* ----- Forward declarations - encode_tls13.c ----- */

extern void encCompressCert(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encDelegatedCredential(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encPreSharedKey(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e, int isServer);
extern void encEarlyData(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encSupportedVersions(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e, int isServer);
extern void encCookie(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encPskKeyExchangeModes(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encCertAuthorities(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encOidFilters(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encPostHandshakeAuth(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encSigAlgsCert(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encKeyShare(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e, int isServer);
extern void encTransparencyInfo(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encConnectionIdDepr(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encConnectionId(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encExternalIdHash(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encExternalSessionId(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encQuicTransportParams(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encTicketRequest(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encDnssecChain(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encSeqNumEncryptionAlgs(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encRrc(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encTlsFlags(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encEchOuterExtensions(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);
extern void encEch(uint8_t *out, size_t *pos, const t_tlsParsedExtensions *e);



/* --------------- Public function to encode extensions into wire format --------------- */

int tlsEncodeExtensions(const t_tlsParsedExtensions *ext, uint8_t *out,
						size_t *outLen, int isServerHello)
{
	if (!ext || !outLen) return 0;
	size_t pos = 0;

	encSni					(out, &pos, ext, isServerHello);
	encMaxFragLen			(out, &pos, ext);
	encTrustedCaKeys		(out, &pos, ext);
	encTruncatedHmac		(out, &pos, ext);
	encStatusRequest		(out, &pos, ext, isServerHello);
	encUserMapping			(out, &pos, ext);
	encClientAuthz			(out, &pos, ext);
	encServerAuthz			(out, &pos, ext);
	encCertType				(out, &pos, ext, isServerHello);
	encSupportedGroups		(out, &pos, ext);
	encEcPointFormats		(out, &pos, ext);
	encSrp					(out, &pos, ext);
	encSigAlgs				(out, &pos, ext);
	encUseSrtp				(out, &pos, ext);
	encHeartbeat			(out, &pos, ext);
	encAlpn					(out, &pos, ext, isServerHello);
	encStatusRequestV2		(out, &pos, ext, isServerHello);
	encSct					(out, &pos, ext);
	encPadding				(out, &pos, ext);
	encEncryptThenMac		(out, &pos, ext);
	encExtendedMasterSecret	(out, &pos, ext);
	encTokenBinding			(out, &pos, ext);
	encCachedInfo			(out, &pos, ext);
	encTlsLts				(out, &pos, ext);
	encCompressCert			(out, &pos, ext);
	encRecordSizeLimit		(out, &pos, ext);
	encPwdProtect			(out, &pos, ext);
	encPwdClear				(out, &pos, ext);
	encPasswordSalt			(out, &pos, ext);
	encTicketPinning		(out, &pos, ext);
	encTlsCertWithExternPsk	(out, &pos, ext);
	encDelegatedCredential	(out, &pos, ext);
	encSessionTicket		(out, &pos, ext, isServerHello);
	encTlsp					(out, &pos, ext);
	encTlspProxying			(out, &pos, ext);
	encTlspDelegate			(out, &pos, ext);
	encSupportedEktCiphers	(out, &pos, ext);
	encPreSharedKey			(out, &pos, ext, isServerHello);
	encEarlyData			(out, &pos, ext);
	encSupportedVersions	(out, &pos, ext, isServerHello);
	encCookie				(out, &pos, ext);
	encPskKeyExchangeModes	(out, &pos, ext);
	encCertAuthorities		(out, &pos, ext);
	encOidFilters			(out, &pos, ext);
	encPostHandshakeAuth	(out, &pos, ext);
	encSigAlgsCert			(out, &pos, ext);
	encKeyShare				(out, &pos, ext, isServerHello);
	encTransparencyInfo		(out, &pos, ext);
	encConnectionIdDepr		(out, &pos, ext);
	encConnectionId			(out, &pos, ext);
	encExternalIdHash		(out, &pos, ext);
	encExternalSessionId	(out, &pos, ext);
	encQuicTransportParams	(out, &pos, ext);
	encTicketRequest		(out, &pos, ext);
	encDnssecChain			(out, &pos, ext);
	encSeqNumEncryptionAlgs	(out, &pos, ext);
	encRrc					(out, &pos, ext);
	encTlsFlags				(out, &pos, ext);
	encEchOuterExtensions	(out, &pos, ext);
	encEch					(out, &pos, ext);

	*outLen = pos;
	return 1;
}
