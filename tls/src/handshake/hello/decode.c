#include <stdlib.h>

#include "../../../../hajlib/include/hmemory.h"
#include "../../../../includes/utils/bitopts.h"

#include "../../../includes/handshake.h"
#include "../../../includes/hello.h"

static int parseClientSpecific(const uint8_t **ptr, size_t *remaining, t_tlsHello *hello)
{
	size_t	cipherLen;
	size_t	compLen;

	/* cipher_suites */
	if (*remaining < 2) return (0);
	cipherLen = readUint16(*ptr);
	*ptr += 2;
	*remaining -= 2;
	if (*remaining < cipherLen || cipherLen % 2 != 0) return (0);

	hello->numCipherSuites = cipherLen / 2;
	hello->cipherSuites = malloc(cipherLen);
	if (!hello->cipherSuites) return (0);

	for (size_t i = 0; i < hello->numCipherSuites; i++)
	{
		hello->cipherSuites[i] = readUint16(*ptr);
		*ptr += 2;
	}
	*remaining -= cipherLen;

	/* compression_methods */
	if (*remaining < 1) return (0);
	compLen = *(*ptr)++;
	(*remaining)--;
	if (*remaining < compLen) return (0);
	hello->numCompressionMethods = compLen;
	if (compLen > 0)
	{
		hello->compressionMethods = malloc(compLen);
		if (!hello->compressionMethods) return (0);
		ft_memcpy(hello->compressionMethods, *ptr, compLen);
		*ptr += compLen;
		*remaining -= compLen;
	}

	return (1);
}

static int parseServerSpecific(const uint8_t **ptr, size_t *remaining, t_tlsHello *hello)
{
	/* selected_cipher_suite */
	if (*remaining < 2) return (0);
	hello->selectedCipherSuite = readUint16(*ptr);
	*ptr += 2;
	*remaining -= 2;

	/* selected_compression_method */
	if (*remaining < 1) return (0);
	hello->selectedCompression = *(*ptr)++;
	(*remaining)--;

	return (1);
}

int tlsDecodeHello(const uint8_t *data, size_t dataLen, t_tlsHello *hello, int isServer)
{
	uint8_t			msgType;
	const uint8_t	*body;
	size_t			bodyLen;
	const uint8_t	*ptr;
	size_t			remaining;
	size_t			extLen;

	if (!data || !hello)
		return (0);

	tlsHelloInit(hello);

	if (!handshakeDecode(data, dataLen, &msgType, &body, &bodyLen) ||
		msgType != (isServer ? TLS_HT_SERVER_HELLO : TLS_HT_CLIENT_HELLO))
		return (0);

	ptr = body;
	remaining = bodyLen;

	/* legacy_version */
	if (remaining < 2) goto error;
	hello->legacyVersion = readUint16(ptr);
	ptr += 2;
	remaining -= 2;

	/* random */
	if (remaining < 32) goto error;
	ft_memcpy(hello->random, ptr, 32);
	ptr += 32;
	remaining -= 32;

	/* session_id */
	if (remaining < 1) goto error;
	hello->sessionIdLen = *ptr++;
	remaining--;
	if (hello->sessionIdLen > 0)
	{
		if (remaining < hello->sessionIdLen) goto error;
		hello->sessionId = malloc(hello->sessionIdLen);
		if (!hello->sessionId) goto error;
		ft_memcpy(hello->sessionId, ptr, hello->sessionIdLen);
		ptr += hello->sessionIdLen;
		remaining -= hello->sessionIdLen;
	}

	if (isServer)
	{
		if (!parseServerSpecific(&ptr, &remaining, hello))
			goto error;
	}
	else
	{
		if (!parseClientSpecific(&ptr, &remaining, hello))
			goto error;
	}

	if (remaining < 2) goto error;
	extLen = readUint16(ptr);
	ptr += 2;
	remaining -= 2;
	if (remaining < extLen) goto error;
	hello->extensionsLen = extLen;
	if (extLen > 0)
	{
		hello->rawExtensions = malloc(extLen);
		if (!hello->rawExtensions) goto error;
		ft_memcpy(hello->rawExtensions, ptr, extLen);
	}

	if (!tlsParseExtensions(hello->rawExtensions, hello->extensionsLen,
	                        &hello->extensions, isServer))
		goto error;

	return (1);

error:
	tlsHelloFree(hello);
	return (0);
}
