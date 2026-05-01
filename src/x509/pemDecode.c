#include <stdlib.h>

#include "../../includes/cipher/base64.h"
#include "../../hajlib/include/hstring.h"
#include "../../hajlib/include/hmemory.h"

#include "../../includes/x509/pem.h"

int pemDecode(const char *pem, t_pem_block *block)
{
	char	*b64 = NULL;
	if (!pem || !block) return (0);
	ft_bzero(block, sizeof(t_pem_block));

	const char *begin = ft_strstr(pem, "-----BEGIN ");
	if (!begin) return (0);
	begin += 11;

	const char *headerEnd = ft_strstr(begin, "-----");
	if (!headerEnd) return (0);

	/* Extract header type */
	size_t typeLen = headerEnd - begin;
	block->header = ft_strndup(begin, typeLen);
	if (!block->header) return (0);

	/* Content start */
	const char *dataStart = headerEnd + 5;
	if (*dataStart == '\n') dataStart++;

	/* Build footer copy with header info to find end of content */
	char footer[256];
	ft_strlcpy(footer, "-----END ", sizeof(footer));
	ft_strlcat(footer, block->header, sizeof(footer));
	ft_strlcat(footer, "-----", sizeof(footer));

	const char *end = ft_strstr(dataStart, footer);
	if (!end) goto error;

	/* Extract base64 content, ignoring newlines */
	size_t	rawLen = end - dataStart;
	b64 = malloc(rawLen + 1);
	if (!b64) goto error;

	size_t j = 0;
	for (size_t i = 0; i < rawLen; i++)
		if (dataStart[i] != '\n' && dataStart[i] != '\r')
			b64[j++] = dataStart[i];
	b64[j] = '\0';

	/* Calculate max DER size and decode */
	size_t derMax = ((j + 3) / 4) * 3; /* Base64 to binary max size */
	block->der = malloc(derMax);
	if (!block->der) goto error;

	if (!base64Decode(b64, block->der)) goto error;

	free(b64);
	return (1);
error:
	pemFreeBlock(block);
	if (b64) free(b64);
	return (0);
}

void pemFreeBlock(t_pem_block *block)
{
	if (!block) return;
	if (block->header) free(block->header);
	if (block->der) free(block->der);
	ft_bzero(block, sizeof(t_pem_block));
}
