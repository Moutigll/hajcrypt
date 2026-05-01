#include "../../includes/x509/pem.h"
#include "../../includes/cipher/base64.h"
#include "../../hajlib/include/hprintf.h"
#include "../../hajlib/include/hstring.h"
#include "../../hajlib/include/hmemory.h"
#include <stdlib.h>

char *pemEncode(const uint8_t *der, size_t derLen, const char *type)
{
	size_t	b64Max = ((derLen + 2) / 3) * 4 + 1;
	char	*b64 = malloc(b64Max);
	if (!b64) return (NULL);
	base64Encode(der, derLen, b64, b64Max);

	/* Compute PEM size */
	size_t	headerLen	= ft_strlen("-----BEGIN -----\n") + ft_strlen(type);
	size_t	footerLen	= ft_strlen("-----END -----\n") + ft_strlen(type);
	size_t	b64Len		= ft_strlen(b64);
	size_t	lines		= (b64Len + 63) / 64;
	size_t	pemLen		= headerLen + b64Len + lines + footerLen + 1;

	char *pem = malloc(pemLen);
	if (!pem) {
		free(b64);
		return (NULL);
	}

	/* Construction */
	ft_bzero(pem, pemLen);
	char *ptr = pem;
	ptr += ft_snprintf(ptr, pemLen - (ptr - pem), "-----BEGIN %s-----\n", type);

	for (size_t i = 0; i < b64Len; i += 64) {
		size_t chunk = (b64Len - i < 64) ? b64Len - i : 64;
		ft_memcpy(ptr, b64 + i, chunk);
		ptr += chunk;
		*ptr++ = '\n';
	}

	ptr += ft_snprintf(ptr, pemLen - (ptr - pem), "-----END %s-----\n", type);
	free(b64);
	return (pem);
}
