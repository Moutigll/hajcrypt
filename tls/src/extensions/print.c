#include "../../../hajlib/include/hprintf.h"
#include "../../includes/extensions.h"
#include "../../includes/hello.h"
#include "../../../hajlib/include/hprintf.h"
#include "../../includes/extensions.h"
#include "../../includes/hello.h"

static const char *colorPalette[] = {
	"\033[38;5;46m",
	"\033[38;5;27m",
	"\033[38;5;226m",
	"\033[38;5;201m",
	"\033[38;5;51m",
	"\033[38;5;208m",
	"\033[38;5;118m",
	"\033[38;5;93m",
	"\033[38;5;214m",
	"\033[38;5;33m",
	"\033[38;5;161m", 
	"\033[38;5;40m",
	"\033[38;5;135m",
	"\033[38;5;84m",
	"\033[38;5;202m",
	"\033[38;5;75m",
	"\033[38;5;129m",
	"\033[38;5;227m",
	"\033[38;5;49m",
	"\033[38;5;197m",
	"\033[38;5;34m",
	"\033[38;5;21m",
	"\033[38;5;179m",
	"\033[38;5;13m",
	"\033[38;5;28m",
	"\033[38;5;99m",
	"\033[38;5;203m",
	"\033[38;5;50m",
	"\033[38;5;141m",
};

#define COLOR_GREASE  "\033[38;5;124m\033[1m"
#define COLOR_UNKNOWN "\033[38;5;241m\033[1m"
#define COLOR_RESET   "\033[0m"

static int isGrease(uint16_t value)
{
	uint8_t hi = value >> 8;
	uint8_t lo = value & 0xFF;
	return (hi == lo) && ((hi & 0x0F) == 0x0A);
}

static void printValueWithGrease(uint16_t val, const char *suffix)
{
	if (isGrease(val))
		ft_printf("%s0x%04x%s%s", COLOR_GREASE, val, COLOR_RESET, suffix);
	else
		ft_printf("0x%04x%s", val, suffix);
}

static void	printHex(const uint8_t *data, size_t len, int maxLen)
{
	size_t	printLen = (len < (size_t)maxLen) ? len : (size_t)maxLen;
	for (size_t i = 0; i < printLen; i++)
		ft_printf("%02x", data[i]);
	if (len > (size_t)maxLen)
		ft_printf("... (%zu bytes total)", len);
}

static void	printGroupList(const uint16_t *groups, size_t count)
{
	for (size_t i = 0; i < count; i++)
	{
		const t_tlsGroup *group = getGroup(groups[i]);
		if (isGrease(groups[i]))
			ft_printf("%s0x%04x%s", COLOR_GREASE, groups[i], COLOR_RESET);
		else if (group && group->supportedVersions == 0)
			ft_printf("\033[38;5;196mDEPRECATED %s (0x%04x)%s", group->name ? group->name : "", groups[i], COLOR_RESET);
		else if (group && group->name)
			ft_printf("%s", group->name);
		else
			ft_printf("%s0x%04x%s", COLOR_UNKNOWN, groups[i], COLOR_RESET);
		if (i + 1 < count)
			ft_printf("%s", (i + 1) % 3 == 0 ? ",\n\t\t\t" : ", \t");
	}
}

static void	printSigAlgList(const uint16_t *algs, size_t count)
{
	for (size_t i = 0; i < count; i++)
	{
		const t_tlsSigAlgo *sigAlgo = getSigAlgo(algs[i]);
		if (sigAlgo && sigAlgo->supportedVersions == 0)
			ft_printf("\033[38;5;196mDEPRECATED %s (0x%04x)%s", sigAlgo->name ? sigAlgo->name : "", algs[i], COLOR_RESET);
		else if (sigAlgo && sigAlgo->name)
			ft_printf("%s", sigAlgo->name);
		else if (isGrease(algs[i]))
			ft_printf("%s0x%04x%s", COLOR_GREASE, algs[i], COLOR_RESET);
		else
			ft_printf("%s0x%04x%s", COLOR_UNKNOWN, algs[i], COLOR_RESET);
		if (i + 1 < count)
			ft_printf("%s", (i + 1) % 3 == 0 ? ",\n\t\t\t" : ", \t");
	}
}

static void	printCipherSuites(const uint16_t *algs, size_t count)
{
	for (size_t i = 0; i < count; i++)
	{
		const t_tlsCipherSuite *cipherSuite = getCipherSuite(algs[i]);
		if (cipherSuite && cipherSuite->supportedVersions == 0)
			ft_printf("\033[38;5;196mDEPRECATED %s (0x%04x)%s", cipherSuite->name ? cipherSuite->name : "", algs[i], COLOR_RESET);
		else if (cipherSuite && cipherSuite->name)
			ft_printf("%s", cipherSuite->name);
		else if (isGrease(algs[i]))
			ft_printf("%s0x%04x%s", COLOR_GREASE, algs[i], COLOR_RESET);
		else
			ft_printf("%s0x%04x%s", COLOR_UNKNOWN, algs[i], COLOR_RESET);
		if (i + 1 < count)
			ft_printf("%s", (i + 1) % 3 == 0 ? ",\n\t\t\t" : ", \t");
	}
}

int tlsPrintHello(const t_tlsHello *hello)
{
	if (!hello)
	{
		ft_printf("(null)\n");
		return (0);
	}

	ft_printf("\033[36m=== TLS %s Hello ===\033[0m\n",
	          hello->selectedCipherSuite == 0 ? "Client" : "Server");
	ft_printf("\033[35m\tlegacy_version:\033[0m 0x%04x\n", hello->legacyVersion);
	ft_printf("\033[33m\trandom:\033[0m ");
	for (int i = 0; i < 32; i++)
		ft_printf("%02x", hello->random[i]);
	ft_printf("\n");

	if (hello->sessionIdLen > 0)
	{
		ft_printf("\033[92m\tsession_id\033[0m (%zu bytes): ", hello->sessionIdLen);
		for (size_t i = 0; i < hello->sessionIdLen; i++)
			ft_printf("%02x", hello->sessionId[i]);
		ft_printf("\n");
	}
	else
		ft_printf("\033[92m\tsession_id:\033[0m (empty)\n");

	if (hello->numCipherSuites > 0)
	{
		ft_printf("\033[94m\tcipher_suites\033[0m (%zu): ", hello->numCipherSuites);
		printCipherSuites(hello->cipherSuites, hello->numCipherSuites);
		ft_printf("\n");
	}

	if (hello->numCompressionMethods > 0)
	{
		ft_printf("\033[96m\tcompression_methods\033[0m (%zu): ", hello->numCompressionMethods);
		for (size_t i = 0; i < hello->numCompressionMethods; i++)
		{
			ft_printf("0x%02x", hello->compressionMethods[i]);
			if (i + 1 < hello->numCompressionMethods)
				ft_printf(", \t");
		}
		ft_printf("\n");
	}

	if (hello->selectedCipherSuite != 0)
		ft_printf("\033[92m\tselected_cipher_suite:\033[0m %s (0x%04x)\n",
		          getCipherSuite(hello->selectedCipherSuite) ? getCipherSuite(hello->selectedCipherSuite)->name : "",
		          hello->selectedCipherSuite);
	if (hello->selectedCompression != 0)
		ft_printf("\033[93m\tselected_compression:\033[0m 0x%02x\n", hello->selectedCompression);

	if (hello->extensionsLen > 0)
	{
		ft_printf("\033[35m\textensions\033[0m (%zu bytes)\n", hello->extensionsLen);
		tlsPrintParsedExtensions(&hello->extensions);
	}
	else
		ft_printf("\033[35m\textensions:\033[0m (none)\n");

	ft_printf("\033[36m=================\033[0m\n");
	return (1);
}

void tlsPrintParsedExtensions(const t_tlsExtensions *ext)
{
	if (!ext) {
		ft_printf("\t\t(null)\n");
		return;
	}

	int color_idx = 0;
	const int num_colors = sizeof(colorPalette) / sizeof(colorPalette[0]);

	/* ----- supported_versions ----- */
	if (ext->numSupportedVersions > 0) {
		ft_printf("%s\t\tsupported_versions (Version Negotiation):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		for (size_t i = 0; i < ext->numSupportedVersions; i++) {
			ft_printf("\t\t\tversion %zu: ", i + 1);
			printValueWithGrease(ext->supportedVersions[i], "");
			if (ext->supportedVersions[i] == 0x0303) ft_printf(" (TLS 1.2)");
			else if (ext->supportedVersions[i] == 0x0304) ft_printf(" (TLS 1.3)");
			else if (ext->supportedVersions[i] == 0x0302) ft_printf(" (TLS 1.1)");
			else if (ext->supportedVersions[i] == 0x0301) ft_printf(" (TLS 1.0)");
			ft_printf("\n");
		}
		ft_printf("\n");
	}
	if (ext->negotiatedVersion != 0) {
		ft_printf("%s\t\tnegotiated_version:\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\t");
		printValueWithGrease(ext->negotiatedVersion, "");
		if (ext->negotiatedVersion == 0x0303) ft_printf(" (TLS 1.2)");
		else if (ext->negotiatedVersion == 0x0304) ft_printf(" (TLS 1.3)");
		ft_printf("\n\n");
	}

	/* ----- supported_groups ----- */
	if (ext->numSupportedGroups > 0) {
		ft_printf("%s\t\tsupported_groups (Key Exchange Groups):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\t");
		for (size_t i = 0; i < ext->numSupportedGroups; i++) {
			printGroupList(&ext->supportedGroups[i], 1);
			if (i + 1 < ext->numSupportedGroups)
				ft_printf("%s", (i + 1) % 3 == 0 ? ",\n\t\t\t" : ", ");
		}
		ft_printf("\n\n");
	}
	if (ext->selectedGroup != 0) {
		ft_printf("%s\t\tselected_group:\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\t");
		printGroupList(&ext->selectedGroup, 1);
		ft_printf("\n\n");
	}

	/* ----- ec_point_formats ----- */
	if (ext->numEcPointFormats > 0) {
		ft_printf("%s\t\tec_point_formats (Elliptic Curve Point Formats):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\t");
		for (size_t i = 0; i < ext->numEcPointFormats; i++) {
			uint8_t fmt = ext->ecPointFormats[i];
			if (fmt == 0) ft_printf("uncompressed (0x00)");
			else if (fmt == 1) ft_printf("ansiX962_compressed_prime (0x01)");
			else if (fmt == 2) ft_printf("ansiX962_compressed_char2 (0x02)");
			else if (isGrease(fmt)) ft_printf("%s0x%02x%s", COLOR_GREASE, fmt, COLOR_RESET);
			else ft_printf("%s0x%02x%s", COLOR_UNKNOWN, fmt, COLOR_RESET);
			if (i + 1 < ext->numEcPointFormats)
				ft_printf("%s", (i + 1) % 3 == 0 ? ",\n\t\t\t" : ", ");
		}
		ft_printf("\n\n");
	}

	/* ----- key_share ----- */
	if (ext->numKeyShares > 0) {
		ft_printf("%s\t\tkey_share (Ephemeral Public Keys):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		for (size_t i = 0; i < ext->numKeyShares; i++) {
			ft_printf("\t\t\tshare[%zu]:\n", i);
			ft_printf("\t\t\t\tgroup: ");
			printGroupList(&ext->keyShares[i].group, 1);
			ft_printf("\n\t\t\t\tkey_exchange (%zu bytes): ", ext->keyShares[i].keyLen);
			printHex(ext->keyShares[i].key, ext->keyShares[i].keyLen, 32);
			ft_printf("\n");
		}
		ft_printf("\n");
	}

	/* ----- signature_algorithms ----- */
	if (ext->numSignatureAlgs > 0) {
		ft_printf("%s\t\tsignature_algorithms (Signature Algorithms):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\t");
		for (size_t i = 0; i < ext->numSignatureAlgs; i++) {
			printSigAlgList(&ext->signatureAlgs[i], 1);
			if (i + 1 < ext->numSignatureAlgs)
				ft_printf("%s", (i + 1) % 3 == 0 ? ",\n\t\t\t" : ", ");
		}
		ft_printf("\n\n");
	}
	if (ext->numSignatureAlgsCert > 0) {
		ft_printf("%s\t\tsignature_algorithms_cert (Certificate Signatures):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\t");
		for (size_t i = 0; i < ext->numSignatureAlgsCert; i++) {
			printSigAlgList(&ext->signatureAlgsCert[i], ext->numSignatureAlgsCert);
			if (i + 1 < ext->numSignatureAlgsCert)
				ft_printf("%s", (i + 1) % 3 == 0 ? ",\n\t\t\t" : ", ");
		}
		ft_printf("\n\n");
	}

	/* ----- pre_shared_key ----- */
	if (ext->numPsks > 0) {
		ft_printf("%s\t\tpre_shared_key (PSK Identities):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		for (size_t i = 0; i < ext->numPsks; i++) {
			ft_printf("\t\t\tidentity[%zu]:\n", i);
			ft_printf("\t\t\t\tidentity: ");
			printHex(ext->psks[i].identity, ext->psks[i].identityLen, 32);
			ft_printf("\n\t\t\t\tobfuscated_ticket_age: %u\n",
			          ext->psks[i].obfuscatedTicketAge);
			ft_printf("\t\t\t\tbinder: ");
			printHex(ext->psks[i].binder, ext->psks[i].binderLen, 32);
			ft_printf("\n");
		}
		ft_printf("\n");
	}

	/* ----- psk_key_exchange_modes (valeurs 1 octet, pas de GREASE) ----- */
	if (ext->pskKe || ext->pskDheKe) {
		ft_printf("%s\t\tpsk_key_exchange_modes (PSK Modes):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		if (ext->pskKe) ft_printf("\t\t\tpsk_ke (PSK-only)\n");
		if (ext->pskDheKe) ft_printf("\t\t\tpsk_dhe_ke (PSK with DHE)\n");
		ft_printf("\n");
	}

	/* ----- session_ticket ----- */
	if (ext->sessionTicketLen > 0) {
		ft_printf("%s\t\tsession_ticket (Session Resumption):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tticket: ");
		printHex(ext->sessionTicket, ext->sessionTicketLen, 32);
		ft_printf("\n\n");
	}

	/* ----- SNI ----- */
	if (ext->sni.hostname) {
		ft_printf("%s\t\tserver_name (SNI - Server Name Indication):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\thostname: \"%s\"\n\n", ext->sni.hostname);
	}

	/* ----- certificate_authorities ----- */
	if (ext->certAuthorities.numNames > 0) {
		ft_printf("%s\t\tcertificate_authorities (Trusted CAs):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		for (size_t i = 0; i < ext->certAuthorities.numNames; i++) {
			ft_printf("\t\t\tCA[%zu]: ", i);
			printHex(ext->certAuthorities.distinguishedNames[i],
			         ext->certAuthorities.nameLens[i], 32);
			ft_printf("\n");
		}
		ft_printf("\n");
	}

	/* ----- oid_filters ----- */
	if (ext->oidFilters.numOids > 0) {
		ft_printf("%s\t\toid_filters (OID Filters):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		for (size_t i = 0; i < ext->oidFilters.numOids; i++) {
			ft_printf("\t\t\tOID[%zu]: ", i);
			printHex(ext->oidFilters.oidValues[i],
			         ext->oidFilters.oidLengths[i], 32);
			ft_printf("\n");
		}
		ft_printf("\n");
	}

	/* ----- ALPN ----- */
	if (ext->alpn.numProtocols > 0) {
		ft_printf("%s\t\tapplication_layer_protocol_negotiation (ALPN):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tprotocols: ");
		for (size_t i = 0; i < ext->alpn.numProtocols; i++) {
			ft_printf("\"%s\"", ext->alpn.protocols[i]);
			if (i + 1 < ext->alpn.numProtocols) ft_printf(", ");
		}
		ft_printf("\n");
		if (ext->alpn.selected)
			ft_printf("\t\t\tselected: \"%s\"\n", ext->alpn.selected);
		ft_printf("\n");
	}

	/* ----- max_fragment_length ----- */
	if (ext->maxFragmentLength.length != 0) {
		ft_printf("%s\t\tmax_fragment_length (Maximum Fragment Length):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tlength: %u bytes\n\n", ext->maxFragmentLength.length);
	}

	/* ----- record_size_limit ----- */
	if (ext->recordSizeLimit.enabled) {
		ft_printf("%s\t\trecord_size_limit (Record Size Limit):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tlimit: %u bytes\n\n", ext->recordSizeLimit.limit);
	}

	/* ----- compress_certificate ----- */
	if (ext->certCompression.enabled && ext->certCompression.numAlgorithms > 0) {
		ft_printf("%s\t\tcompress_certificate (Certificate Compression):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\talgorithms: ");
		for (size_t i = 0; i < ext->certCompression.numAlgorithms; i++) {
			switch (ext->certCompression.algorithms[i]) {
				case 0: ft_printf("brotli"); break;
				case 1: ft_printf("zlib"); break;
				case 2: ft_printf("zstd"); break;
				default:
					if (isGrease(ext->certCompression.algorithms[i]))
						ft_printf("%sGREASE (0x%04x)%s",
						          COLOR_GREASE, ext->certCompression.algorithms[i], COLOR_RESET);
					else
						ft_printf("unknown(0x%04x)", ext->certCompression.algorithms[i]);
			}
			if (i + 1 < ext->certCompression.numAlgorithms) ft_printf(", ");
		}
		ft_printf("\n");
		if (ext->certCompression.selected != 0) {
			ft_printf("\t\t\tselected: ");
			switch (ext->certCompression.selected) {
				case 0: ft_printf("brotli\n"); break;
				case 1: ft_printf("zlib\n"); break;
				case 2: ft_printf("zstd\n"); break;
				default: ft_printf("unknown(0x%04x)\n", ext->certCompression.selected);
			}
		}
		ft_printf("\n");
	}

	/* ----- status_request (OCSP) ----- */
	if (ext->ocsp.requested) {
		ft_printf("%s\t\tstatus_request (OCSP Stapling):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\trequested: yes\n");
		if (ext->ocsp.responseLen > 0) {
			ft_printf("\t\t\tresponse: ");
			printHex(ext->ocsp.response, ext->ocsp.responseLen, 32);
			ft_printf("\n");
		}
		ft_printf("\n");
	}

	/* ----- status_request_v2 ----- */
	if (ext->ocspV2.requested && ext->ocspV2.numResponses > 0) {
		ft_printf("%s\t\tstatus_request_v2 (OCSP Stapling v2):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		for (size_t i = 0; i < ext->ocspV2.numResponses; i++) {
			ft_printf("\t\t\tresponse[%zu]: ", i);
			printHex(ext->ocspV2.responses[i].response,
			         ext->ocspV2.responses[i].responseLen, 32);
			ft_printf("\n");
		}
		ft_printf("\n");
	}

	/* ----- signed_certificate_timestamp ----- */
	if (ext->sct.numScts > 0) {
		ft_printf("%s\t\tsigned_certificate_timestamp (SCT):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		for (size_t i = 0; i < ext->sct.numScts; i++) {
			ft_printf("\t\t\tSCT[%zu]: ", i);
			printHex(ext->sct.scts[i].timestamp,
			         ext->sct.scts[i].timestampLen, 32);
			ft_printf("\n");
		}
		ft_printf("\n");
	}

	/* ----- heartbeat ----- */
	if (ext->heartbeat.supported) {
		ft_printf("%s\t\theartbeat:\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tmode: %s\n",
		          ext->heartbeat.mode == 0 ? "peer_allowed_to_send" : "peer_not_allowed_to_send");
		ft_printf("\n");
	}

	/* ----- client_certificate_type / server_certificate_type ----- */
	if (ext->clientCertType.numTypes > 0) {
		ft_printf("%s\t\tclient_certificate_type:\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\ttypes: ");
		for (size_t i = 0; i < ext->clientCertType.numTypes; i++) {
			if (ext->clientCertType.types[i] == 0) ft_printf("X.509");
			else if (ext->clientCertType.types[i] == 1) ft_printf("RawPublicKey");
			else ft_printf("unknown(0x%02x)", ext->clientCertType.types[i]);
			if (i + 1 < ext->clientCertType.numTypes) ft_printf(", ");
		}
		ft_printf("\n\n");
	}
	if (ext->serverCertType.numTypes > 0) {
		ft_printf("%s\t\tserver_certificate_type:\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\ttypes: ");
		for (size_t i = 0; i < ext->serverCertType.numTypes; i++) {
			if (ext->serverCertType.types[i] == 0) ft_printf("X.509");
			else if (ext->serverCertType.types[i] == 1) ft_printf("RawPublicKey");
			else ft_printf("unknown(0x%02x)", ext->serverCertType.types[i]);
			if (i + 1 < ext->serverCertType.numTypes) ft_printf(", ");
		}
		ft_printf("\n\n");
	}

	/* ----- padding ----- */
	if (ext->padding.length > 0) {
		ft_printf("%s\t\tpadding (Padding Extension):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tlength: %zu bytes\n\n", ext->padding.length);
	}

	/* ----- encrypt_then_mac (TLS 1.2) ----- */
	if (ext->encryptThenMac.supported) {
		ft_printf("%s\t\tencrypt_then_mac (TLS 1.2 only):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tpresent\n\n");
	}

	/* ----- extended_master_secret (TLS 1.2) ----- */
	if (ext->extendedMasterSecret.supported) {
		ft_printf("%s\t\textended_master_secret (TLS 1.2 only):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tpresent\n\n");
	}

	/* ----- renegotiation_info ----- */
	if (ext->renegotiationInfo.len > 0) {
		ft_printf("%s\t\trenegotiation_info (DEPRECATED):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tdata: ");
		printHex(ext->renegotiationInfo.renegotiatedConnection,
		         ext->renegotiationInfo.len, 16);
		ft_printf("\n\n");
	}

	/* ----- token_binding ----- */
	if (ext->tokenBinding.paramsLen > 0) {
		ft_printf("%s\t\ttoken_binding:\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tparams: ");
		printHex(ext->tokenBinding.params, ext->tokenBinding.paramsLen, 16);
		ft_printf("\n\n");
	}

	/* ----- cached_info ----- */
	if (ext->cachedInfo.cachedInfoLen > 0) {
		ft_printf("%s\t\tcached_info:\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tdata: ");
		printHex(ext->cachedInfo.cachedInfo, ext->cachedInfo.cachedInfoLen, 32);
		ft_printf("\n\n");
	}

	/* ----- ticket_pinning ----- */
	if (ext->ticketPinning.pinLen > 0) {
		ft_printf("%s\t\tticket_pinning:\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tpin: ");
		printHex(ext->ticketPinning.ticket_pin, ext->ticketPinning.pinLen, 32);
		ft_printf("\n\n");
	}

	/* ----- supported_ekt_ciphers ----- */
	if (ext->supportedEktCiphers.numCiphers > 0) {
		ft_printf("%s\t\tsupported_ekt_ciphers:\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tciphers: ");
		for (size_t i = 0; i < ext->supportedEktCiphers.numCiphers; i++) {
			printCipherSuites(&ext->supportedEktCiphers.ciphers[i], 1);
			if (i + 1 < ext->supportedEktCiphers.numCiphers) ft_printf(", ");
		}
		ft_printf("\n\n");
	}

	/* ----- external_id_hash / external_session_id ----- */
	if (ext->externalIdHash.hashLen > 0) {
		ft_printf("%s\t\texternal_id_hash:\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\thash: ");
		printHex(ext->externalIdHash.hash, ext->externalIdHash.hashLen, 32);
		ft_printf("\n\n");
	}
	if (ext->externalSessionId.idLen > 0) {
		ft_printf("%s\t\texternal_session_id:\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tsession_id: ");
		printHex(ext->externalSessionId.sessionId, ext->externalSessionId.idLen, 32);
		ft_printf("\n\n");
	}

	/* ----- ticket_request ----- */
	if (ext->ticketRequest.request) {
		ft_printf("%s\t\tticket_request (Request New Ticket):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tpresent\n\n");
	}

	/* ----- post_handshake_auth ----- */
	if (ext->postHandshakeAuth) {
		ft_printf("%s\t\tpost_handshake_auth:\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tpresent\n\n");
	}

	/* ----- connection_id ----- */
	if (ext->connectionId.cidLen > 0) {
		ft_printf("%s\t\tconnection_id (DTLS Connection ID):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tcid: ");
		printHex(ext->connectionId.cid, ext->connectionId.cidLen, 16);
		ft_printf("\n");
		if (ext->connectionId.peerCidLen > 0) {
			ft_printf("\t\t\tpeer_cid: ");
			printHex(ext->connectionId.peerCid, ext->connectionId.peerCidLen, 16);
			ft_printf("\n");
		}
		ft_printf("\n");
	}

	/* ----- rrc ----- */
	if (ext->rrc.challengeLen > 0) {
		ft_printf("%s\t\trrc (Return Routability Check):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tchallenge: ");
		printHex(ext->rrc.challenge, ext->rrc.challengeLen, 32);
		ft_printf("\n\n");
	}

	/* ----- tls_flags ----- */
	if (ext->tlsFlags.flags != 0) {
		ft_printf("%s\t\ttls_flags:\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tflags: 0x%016llx\n\n", (unsigned long long)ext->tlsFlags.flags);
	}

	/* ----- early_data ----- */
	if (ext->earlyDataLen > 0 || ext->earlyData != NULL) {
		ft_printf("%s\t\tearly_data (0-RTT Early Data):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		if (ext->earlyDataLen > 0)
			ft_printf("\t\t\tmax_early_data: %zu bytes\n", ext->earlyDataLen);
		else
			ft_printf("\t\t\tpresent (client request)\n");
		ft_printf("\n");
	}

	/* ----- quic_transport_parameters ----- */
	if (ext->quicParams.paramsLen > 0) {
		ft_printf("%s\t\tquic_transport_parameters (QUIC Transport Params):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tdata: ");
		printHex(ext->quicParams.params, ext->quicParams.paramsLen, 32);
		ft_printf("\n\n");
	}

	/* ----- delegated_credential ----- */
	if (ext->delegatedCredential.credentialLen > 0) {
		ft_printf("%s\t\tdelegated_credential:\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tcredential: ");
		printHex(ext->delegatedCredential.credential,
		         ext->delegatedCredential.credentialLen, 32);
		ft_printf("\n");
		if (ext->delegatedCredential.signatureLen > 0) {
			ft_printf("\t\t\tsignature: ");
			printHex(ext->delegatedCredential.signature,
			         ext->delegatedCredential.signatureLen, 32);
			ft_printf("\n");
		}
		ft_printf("\n");
	}

	/* ----- ech / ech_outer_extensions ----- */
	if (ext->ech.enabled) {
		ft_printf("%s\t\tencrypted_client_hello (ECH):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tencrypted_data: ");
		printHex(ext->ech.enc, ext->ech.encLen, 32);
		ft_printf("\n\n");
	}
	if (ext->echOuterExtensions.numTypes > 0) {
		ft_printf("%s\t\tech_outer_extensions:\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\textension types: ");
		for (size_t i = 0; i < ext->echOuterExtensions.numTypes; i++) {
			printValueWithGrease(ext->echOuterExtensions.extensionTypes[i],
			                        (i + 1 < ext->echOuterExtensions.numTypes) ? ", " : "");
		}
		ft_printf("\n\n");
	}

	/* ----- cookie (DTLS) ----- */
	if (ext->cookie.cookieLen > 0) {
		ft_printf("%s\t\tcookie (DTLS Anti-DoS):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tcookie: ");
		printHex(ext->cookie.cookie, ext->cookie.cookieLen, 32);
		ft_printf("\n\n");
	}

	/* ----- SRTP ----- */
	if (ext->srtp.numProfiles > 0) {
		ft_printf("%s\t\tuse_srtp (SRTP Protection Profiles):\033[0m\n",
		          colorPalette[color_idx++ % num_colors]);
		ft_printf("\t\t\tprofiles: ");
		for (size_t i = 0; i < ext->srtp.numProfiles; i++) {
			uint16_t prof = ext->srtp.profiles[i];
			if (isGrease(prof))
				ft_printf("%s0x%04x%s", COLOR_GREASE, prof, COLOR_RESET);
			else
				ft_printf("0x%04x", prof);
			if (i + 1 < ext->srtp.numProfiles) ft_printf(", ");
		}
		ft_printf("\n");
		if (ext->srtp.selected != 0)
			ft_printf("\t\t\tselected: 0x%04x\n", ext->srtp.selected);
		if (ext->srtp.mkiLen > 0) {
			ft_printf("\t\t\tMKI: ");
			printHex(ext->srtp.mki, ext->srtp.mkiLen, 16);
			ft_printf("\n");
		}
		ft_printf("\n");
	}
}
