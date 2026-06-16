#include <stdlib.h>

#include "../../../../hajlib/include/hmemory.h"
#include "../../../../includes/utils/random.h"
#include "../../../../includes/utils/bitopts.h"

#include "../../../includes/handshake.h"
#include "../../../includes/hello.h"
#include "../../../includes/extensions.h"

static void encodeClientSpecific(uint8_t **ptr, const t_tlsHello *hello)
{
	size_t	cipherLen;

	cipherLen = hello->numCipherSuites * 2;
	writeUint16(*ptr, (uint16_t)cipherLen);
	*ptr += 2;
	for (size_t i = 0; i < hello->numCipherSuites; i++)
	{
		writeUint16(*ptr, hello->cipherSuites[i]);
		*ptr += 2;
	}

	*(*ptr)++ = (uint8_t)hello->numCompressionMethods;
	if (hello->numCompressionMethods > 0 && hello->compressionMethods)
	{
		ft_memcpy(*ptr, hello->compressionMethods, hello->numCompressionMethods);
		*ptr += hello->numCompressionMethods;
	}
}

static int tlsEncodeHello(const t_tlsHello *hello, uint8_t *out, size_t *outLen, int isServer)
{
	uint8_t	*body;
	size_t	bodyLen;
	size_t	extLen;
	uint8_t	*ptr;

	if (!hello || !out || !outLen)
		return (0);

	/* Encode extensions first (size probe) */
	tlsEncodeExtensions(&hello->extensions, NULL, &extLen, isServer);
	extLen = extLen; /* already set */

	/* Use pre-encoded extensions if available, otherwise encode from parsedExtensions */
	if (hello->rawExtensions && hello->extensionsLen)
		extLen = hello->extensionsLen;

	if (isServer)
		bodyLen = 2 + 32 + 1 + hello->sessionIdLen + 2 + 1 + 2 + extLen;
	else
		bodyLen = 2 + 32 + 1 + hello->sessionIdLen +
				  2 + (hello->numCipherSuites * 2) +
				  1 + hello->numCompressionMethods +
				  2 + extLen;

	body = malloc(bodyLen);
	if (!body)
		return (0);
	ptr = body;

	/* legacy_version */
	writeUint16(ptr, hello->legacyVersion);
	ptr += 2;

	/* random */
	ft_memcpy(ptr, hello->random, 32);
	ptr += 32;

	/* session_id */
	*ptr++ = (uint8_t)hello->sessionIdLen;
	if (hello->sessionIdLen > 0 && hello->sessionId)
	{
		ft_memcpy(ptr, hello->sessionId, hello->sessionIdLen);
		ptr += hello->sessionIdLen;
	}

	/* specific fields */
	if (isServer)
	{
		writeUint16(ptr, hello->selectedCipherSuite);
		ptr += 2;
		*ptr++ = hello->selectedCompression;
	}
	else
		encodeClientSpecific(&ptr, hello);

	/* extensions */
	writeUint16(ptr, (uint16_t)extLen);
	ptr += 2;
	if (extLen > 0)
	{
		if (hello->rawExtensions)
		{
			ft_memcpy(ptr, hello->rawExtensions, extLen);
			ptr += extLen;
		}
		else
		{
			size_t written;
			tlsEncodeExtensions(&hello->extensions, ptr, &written, isServer);
			ptr += written;
		}
	}

	if (!handshakeEncode(isServer ? TLS_HT_SERVER_HELLO : TLS_HT_CLIENT_HELLO,
						 body, bodyLen, out, outLen))
	{
		free(body);
		return (0);
	}
	free(body);
	return (1);
}

int tlsBuildServerHello(t_tlsHello			*serverHello,
						const t_tlsHello	*clientHello,
						uint16_t 			selectedVersion,
						uint8_t				*out,	size_t	*outLen)
{
	int	ret;

	if (!serverHello || !clientHello || !out || !outLen)
		return (0);

	if (selectedVersion == TLS_VERSION_1_3
		&& (serverHello->extensions.negotiatedVersion != TLS_VERSION_1_3
		||  serverHello->extensions.numKeyShares == 0 || !serverHello->extensions.keyShares))
		return (0);

	if (serverHello->legacyVersion == 0)
		serverHello->legacyVersion = 0x0303;

	{ /* Fill random if empty */
		int randomEmpty = 1;
		for (int i = 0; i < 32; i++)
		{
			if (serverHello->random[i] != 0)
			{
				randomEmpty = 0;
				break;
			}
		}
		if (randomEmpty)
		{
			if (hajSecRandBytes(serverHello->random, 32) != 0)
				return (0);
		}
	}

	if (serverHello->sessionIdLen == 0 && !serverHello->sessionId &&
		clientHello->sessionIdLen > 0 && clientHello->sessionId)
	{
		serverHello->sessionIdLen = clientHello->sessionIdLen;
		serverHello->sessionId = malloc(serverHello->sessionIdLen);
		if (!serverHello->sessionId)
			return (0);
		ft_memcpy(serverHello->sessionId, clientHello->sessionId,
				  serverHello->sessionIdLen);
	}

	if (selectedVersion == TLS_VERSION_1_3)
	{
		if (!serverHello->rawExtensions || serverHello->extensionsLen == 0)
		{
			size_t extLen;
			tlsEncodeExtensions(&serverHello->extensions, NULL, &extLen, 1);
			serverHello->rawExtensions = malloc(extLen);
			if (!serverHello->rawExtensions)
				return (0);
			tlsEncodeExtensions(&serverHello->extensions, serverHello->rawExtensions, &extLen, 1);
			serverHello->extensionsLen = extLen;
		}
	}
	else /* TLS 1.2 */
	{
		if (!serverHello->rawExtensions)
		{
			serverHello->rawExtensions = NULL;
			serverHello->extensionsLen = 0;
		}
	}

	ret = tlsEncodeHello(serverHello, out, outLen, 1);

	return (ret);
}

int tlsBuildClientHello(t_tlsHello	*clientHello,
						uint16_t	selectedVersion,
						uint8_t		*out,
						size_t		*outLen)
{
	int ret;

	if (!clientHello || !out || !outLen)
		return (0);

	/* Set legacy version to TLS 1.2 (0x0303) as per RFC */
	if (clientHello->legacyVersion == 0)
		clientHello->legacyVersion = 0x0303;

	/* Generate random if empty */
	{
		int randomEmpty = 1;
		for (int i = 0; i < 32; i++)
		{
			if (clientHello->random[i] != 0)
			{
				randomEmpty = 0;
				break;
			}
		}
		if (randomEmpty)
		{
			if (hajSecRandBytes(clientHello->random, 32) != 0)
				return (0);
		}
	}

	/* Generate session ID if empty */
	if (clientHello->sessionIdLen == 0 && !clientHello->sessionId)
	{
		clientHello->sessionIdLen = 32;
		clientHello->sessionId = malloc(32);
		if (!clientHello->sessionId)
			return (0);
		if (hajSecRandBytes(clientHello->sessionId, 32) != 0)
		{
			free(clientHello->sessionId);
			clientHello->sessionId = NULL;
			clientHello->sessionIdLen = 0;
			return (0);
		}
	}

	/* Set compression methods if empty (at least null compression) */
	if (clientHello->numCompressionMethods == 0 && !clientHello->compressionMethods)
	{
		static uint8_t nullCompression[] = {0x00};
		clientHello->compressionMethods = nullCompression;
		clientHello->numCompressionMethods = 1;
	}

	/* Encode extensions if not already raw-encoded */
	if (selectedVersion == TLS_VERSION_1_3)
	{
		if (!clientHello->rawExtensions || clientHello->extensionsLen == 0)
		{
			size_t extLen;
			tlsEncodeExtensions(&clientHello->extensions, NULL, &extLen, 0);
			clientHello->rawExtensions = malloc(extLen);
			if (!clientHello->rawExtensions)
				return (0);
			tlsEncodeExtensions(&clientHello->extensions, clientHello->rawExtensions, &extLen, 0);
			clientHello->extensionsLen = extLen;
		}
	}
	else /* TLS 1.2 */
	{
		if (!clientHello->rawExtensions)
		{
			clientHello->rawExtensions = NULL;
			clientHello->extensionsLen = 0;
		}
	}

	ret = tlsEncodeHello(clientHello, out, outLen, 0);

	return (ret);
}
