#include <stdlib.h>

#include "../../../hajlib/include/hmemory.h"

#include "../../../includes/hash/hash.h"

uint8_t *padMessage(const uint8_t	*lastBlock,
					size_t			lastLen,
					t_paddParams	*params,
					size_t			*newLen)
{
	size_t		required;
	size_t		paddingZeros;
	uint8_t		*buffer;
	size_t		i;
	uint64_t	bitLen;

	required = lastLen + 1 + 8; // 1 byte for 0x80 and 8 bytes for length field

	if (required % params->blockSize <= params->blockSize - 8
		&& required % params->blockSize != 0)
		paddingZeros = params->blockSize - (required % params->blockSize);
	else if (required % params->blockSize == 0)
		paddingZeros = 0;
	else
		paddingZeros = (2 * params->blockSize) - (required % params->blockSize);

	*newLen = required + paddingZeros;

	buffer = malloc(*newLen);
	if (!buffer)
		return (NULL);

	ft_memcpy(buffer, lastBlock, lastLen);

	buffer[lastLen] = 0x80;

	i = lastLen + 1;
	while (i < *newLen - 8)
	{
		buffer[i] = 0x00;
		i++;
	}

	bitLen = (uint64_t)params->msgLen * 8;

	i = 0;
	while (i < 8)
	{
		if (params->isLittleEndian)
			buffer[*newLen - 8 + i] =
				(bitLen >> (8 * i)) & 0xFF;
		else
			buffer[*newLen - 8 + i] =
				(bitLen >> (8 * (7 - i))) & 0xFF;
		i++;
	}

	return (buffer);
}
