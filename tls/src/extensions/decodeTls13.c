#include <stdlib.h>
#include "../../../hajlib/include/hmemory.h"
#include "../../../hajlib/include/hprintf.h" /* IWYU pragma: keep */
#include "../../../includes/utils/bitopts.h"

#include "../../includes/extensions.h"
#include "../../includes/constants.h"

/* 27 - compress_certificate */
int parseCompressCertificate(const uint8_t *data, size_t len, t_tlsParsedExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 2) return (1);
	size_t listLen = readUint16(data);
	if (len < 2 + listLen) return (1);
	out->certCompression.numAlgorithms = listLen / 2;
	if (out->certCompression.numAlgorithms > 8)
		out->certCompression.numAlgorithms = 8;
	for (size_t i = 0; i < out->certCompression.numAlgorithms; i++) {
		out->certCompression.algorithms[i] = readUint16(data + 2 + i*2);
	}
	out->certCompression.enabled = 1;
	return (1);
}

/* 34 - delegated_credential */
int parseDelegatedCredential(const uint8_t *data, size_t len, t_tlsParsedExtensions *out, int isServer)
{
	(void)isServer;
	out->delegatedCredential.credentialLen = len;
	out->delegatedCredential.credential = malloc(len);
	if (!out->delegatedCredential.credential) return (0);
	ft_memcpy(out->delegatedCredential.credential, data, len);
	return (1);
}

/* 41 - pre_shared_key */
int parsePreSharedKey(const uint8_t *data, size_t len, t_tlsParsedExtensions *out, int isServer)
{
	(void)data; (void)len; (void)out; (void)isServer;
	BTLS_DEBUG("Parsing pre_shared_key: Not implemented yet !!!");
	return (1);
}

/* 42 - early_data */
int parseEarlyData(const uint8_t *data, size_t len, t_tlsParsedExtensions *out, int isServer)
{
	if (isServer)
		out->earlyDataLen = 0;
	else if (len >= 4)
		out->earlyDataLen = readUint32(data);
	return (1);
}

/* 43 - supported_versions */
int parseSupportedVersions(const uint8_t *data, size_t len, t_tlsParsedExtensions *out, int isServer)
{
	if (!isServer) {
		if (len < 1) return (1);
		size_t versionsLen = data[0];
		if (len < 1 + versionsLen) return (1);
		out->numSupportedVersions = versionsLen / 2;
		if (out->numSupportedVersions > 4) out->numSupportedVersions = 4;
		for (size_t i = 0; i < out->numSupportedVersions; i++) {
			out->supportedVersions[i] = readUint16(data + 1 + i*2);
		}
	} else
		if (len >= 2) out->negotiatedVersion = readUint16(data);
	return (1);
}

/* 44 - cookie */
int parseCookie(const uint8_t *data, size_t len, t_tlsParsedExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 2) return (1);
	size_t cookieLen = readUint16(data);
	if (len < 2 + cookieLen) return (1);
	out->cookie.cookieLen = cookieLen;
	out->cookie.cookie = malloc(cookieLen);
	if (!out->cookie.cookie) return (0);
	ft_memcpy(out->cookie.cookie, data + 2, cookieLen);
	return (1);
}

/* 45 - psk_key_exchange_modes */
int parsePskKeyExchangeModes(const uint8_t *data, size_t len, t_tlsParsedExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 2) return (1);
	size_t modesLen = readUint16(data);
	if (len < 2 + modesLen) return (1);
	for (size_t i = 0; i < modesLen; i++) {
		uint8_t mode = data[2 + i];
		if (mode == 0) out->pskKe = 1;
		if (mode == 1) out->pskDheKe = 1;
	}
	return (1);
}

/* 47 - certificate_authorities */
int parseCertificateAuthorities(const uint8_t *data, size_t len, t_tlsParsedExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 2) return (1);
	size_t listLen = readUint16(data);
	if (len < 2 + listLen) return (1);
	const uint8_t *ptr = data + 2;
	size_t remaining = listLen;
	out->certAuthorities.numNames = 0;
	while (remaining >= 2) {
		uint16_t dnLen = readUint16(ptr);
		if (remaining < 2 + (size_t)dnLen) break;
		uint8_t **newNames = realloc(out->certAuthorities.distinguishedNames,
			(out->certAuthorities.numNames + 1) * sizeof(uint8_t*));
		if (!newNames) return (0);
		out->certAuthorities.distinguishedNames = newNames;
		size_t *newLens = realloc(out->certAuthorities.nameLens,
			(out->certAuthorities.numNames + 1) * sizeof(size_t));
		if (!newLens) return (0);
		out->certAuthorities.nameLens = newLens;
		out->certAuthorities.distinguishedNames[out->certAuthorities.numNames] = malloc(dnLen);
		if (!out->certAuthorities.distinguishedNames[out->certAuthorities.numNames]) return (0);
		ft_memcpy(out->certAuthorities.distinguishedNames[out->certAuthorities.numNames], ptr + 2, dnLen);
		out->certAuthorities.nameLens[out->certAuthorities.numNames] = dnLen;
		out->certAuthorities.numNames++;
		ptr += 2 + dnLen;
		remaining -= 2 + dnLen;
	}
	return (1);
}

/* 48 - oid_filters */
int parseOidFilters(const uint8_t *data, size_t len, t_tlsParsedExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 2) return (1);
	size_t listLen = readUint16(data);
	if (len < 2 + listLen) return (1);
	const uint8_t *ptr = data + 2;
	size_t remaining = listLen;
	out->oidFilters.numOids = 0;
	while (remaining >= 2) {
		uint16_t oidLen = readUint16(ptr);
		if (remaining < 2 + (size_t)oidLen) break;
		uint8_t **newOids = realloc(out->oidFilters.oidValues,
			(out->oidFilters.numOids + 1) * sizeof(uint8_t*));
		if (!newOids) return (0);
		out->oidFilters.oidValues = newOids;
		size_t *newLens = realloc(out->oidFilters.oidLengths,
			(out->oidFilters.numOids + 1) * sizeof(size_t));
		if (!newLens) return (0);
		out->oidFilters.oidLengths = newLens;
		out->oidFilters.oidValues[out->oidFilters.numOids] = malloc(oidLen);
		if (!out->oidFilters.oidValues[out->oidFilters.numOids]) return (0);
		ft_memcpy(out->oidFilters.oidValues[out->oidFilters.numOids], ptr + 2, oidLen);
		out->oidFilters.oidLengths[out->oidFilters.numOids] = oidLen;
		out->oidFilters.numOids++;
		ptr += 2 + oidLen;
		remaining -= 2 + oidLen;
	}
	return (1);
}

/* 49 - post_handshake_auth */
int parsePostHandshakeAuth(const uint8_t *data, size_t len, t_tlsParsedExtensions *out, int isServer)
{
	(void)data; (void)len; (void)isServer;
	out->postHandshakeAuth = 1;
	return (1);
}

/* 50 - signature_algorithms_cert */
int parseSignatureAlgsCert(const uint8_t *data, size_t len, t_tlsParsedExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 2) return (1);
	size_t listLen = readUint16(data);
	if (len < 2 + listLen) return (1);
	out->numSignatureAlgsCert = listLen / 2;
	out->signatureAlgsCert = malloc(out->numSignatureAlgsCert * sizeof(uint16_t));
	if (!out->signatureAlgsCert) return (0);
	for (size_t i = 0; i < out->numSignatureAlgsCert; i++) {
		out->signatureAlgsCert[i] = readUint16(data + 2 + i*2);
	}
	return (1);
}

/* 51 - key_share */
int parseKeyShare(const uint8_t *data, size_t len, t_tlsParsedExtensions *out, int isServer)
{
	if (isServer) {
		if (len < 4) return (1);
		out->selectedGroup = readUint16(data);
		uint16_t keyLen = readUint16(data + 2);
		if (len < 4 + (size_t)keyLen) return (1);
		/* Server's public key can be stored if needed */
	} else {
		if (len < 2) return (1);
		size_t sharesLen = readUint16(data);
		if (len < 2 + sharesLen) return (1);
		const uint8_t *ptr = data + 2;
		size_t remaining = sharesLen;
		size_t count = 0;
		while (remaining >= 4) {
			uint16_t group = readUint16(ptr);
			(void)group;
			uint16_t keyLen = readUint16(ptr + 2);
			if (remaining < 4 + (size_t)keyLen) break;
			ptr += 4 + keyLen;
			remaining -= 4 + keyLen;
			count++;
		}
		out->numKeyShares = count;
		out->keyShares = calloc(count, sizeof(t_tlsKeyShareEntry));
		if (!out->keyShares) return (0);
		ptr = data + 2;
		remaining = sharesLen;
		for (size_t i = 0; i < count; i++) {
			out->keyShares[i].group = readUint16(ptr);
			uint16_t keyLen = readUint16(ptr + 2);
			out->keyShares[i].keyLen = keyLen;
			out->keyShares[i].key = malloc(keyLen);
			if (!out->keyShares[i].key) return (0);
			ft_memcpy(out->keyShares[i].key, ptr + 4, keyLen);
			ptr += 4 + keyLen;
		}
	}
	return (1);
}

/* 57 - quic_transport_parameters */
int parseQuicTransportParams(const uint8_t *data, size_t len, t_tlsParsedExtensions *out, int isServer)
{
	(void)isServer;
	out->quicParams.paramsLen = len;
	out->quicParams.params = malloc(len);
	if (!out->quicParams.params) return (0);
	ft_memcpy(out->quicParams.params, data, len);
	return (1);
}

/* 64768 - ech_outer_extensions */
int parseEchOuterExtensions(const uint8_t *data, size_t len, t_tlsParsedExtensions *out, int isServer)
{
	(void)isServer;
	if (len < 2) return (1);
	size_t listLen = readUint16(data);
	if (len < 2 + listLen) return (1);
	out->echOuterExtensions.numTypes = listLen / 2;
	out->echOuterExtensions.extensionTypes = malloc(out->echOuterExtensions.numTypes * sizeof(uint16_t));
	if (!out->echOuterExtensions.extensionTypes) return (0);
	for (size_t i = 0; i < out->echOuterExtensions.numTypes; i++) {
		out->echOuterExtensions.extensionTypes[i] = readUint16(data + 2 + i*2);
	}
	return (1);
}

/* 65037 - encrypted_client_hello (ECH) */
int parseEncryptedClientHello(const uint8_t *data, size_t len, t_tlsParsedExtensions *out, int isServer)
{
	(void)isServer;
	out->ech.enabled = 1;
	out->ech.encLen = len;
	out->ech.enc = malloc(len);
	if (!out->ech.enc) return (0);
	ft_memcpy(out->ech.enc, data, len);
	return (1);
}
