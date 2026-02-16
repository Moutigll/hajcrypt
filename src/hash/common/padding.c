#include <stdlib.h>

#include "../../../hajlib/include/hmemory.h"

#include "../../../includes/hash/hash.h"

uint8_t *padMessage(const uint8_t	*msg,
					t_paddParams	*paddParams,
					size_t			*newLen)
{
	size_t baseSize;
	size_t remainder;
	size_t padding;
	uint8_t *buffer;
	size_t i;

	/* Base size: message length + 1 byte for the '1' bit + 8 bytes for the original message length */
	baseSize = paddParams->msgLen + 1 + 8;

	remainder = baseSize % paddParams->blockSize;
	padding = (remainder == 0) ? 0 : paddParams->blockSize - remainder;

	*newLen = baseSize + padding;

	buffer = malloc(*newLen);
	if (!buffer)
		return (NULL);

	/* copy the original message into the buffer */
	ft_memcpy(buffer, msg, paddParams->msgLen);

	/* append the 0x80 byte */
	buffer[paddParams->msgLen] = 0x80;

	/* fill with zeros until the length - 8 bytes */
	for (i = paddParams->msgLen + 1; i < *newLen - 8; i++)
		buffer[i] = 0x00;

	/* append the original message length in bits (little or big endian depending on parameter) */
	for (i = 0; i < 8; i++)
	{
		if (paddParams->isLittleEndian)
			buffer[*newLen - 8 + i] = ((uint64_t)paddParams->msgLen * 8 >> (8 * i)) & 0xFF;
		else
			buffer[*newLen - 8 + i] = ((uint64_t)paddParams->msgLen * 8 >> (8 * (7 - i))) & 0xFF;
	}

	return (buffer);
}
