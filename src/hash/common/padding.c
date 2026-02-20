#include <stdlib.h>

#include "../../../hajlib/include/hmemory.h"

#include "../../../includes/hash/hash.h"

size_t padMessage(uint8_t		*dst,
				  const uint8_t	*lastBlock,
				  size_t		lastLen,
				  t_paddParams	*params)
{
	size_t		required;
	size_t		paddingZeros;
	size_t		totalLen;
	size_t		i;
	uint64_t	bitLen;

	if (!dst || !lastBlock || !params)
		return 0;

	/* Calculate required length: original + 0x80 + 8 bytes length */
	required = lastLen + 1 + 8;

	/* Calculate padding zeros needed to reach block size multiple */
	if (required % params->blockSize <= params->blockSize - 8 &&
		required % params->blockSize != 0)
		paddingZeros = params->blockSize - (required % params->blockSize);
	else if (required % params->blockSize == 0)
		paddingZeros = 0;
	else
		paddingZeros = (2 * params->blockSize) - (required % params->blockSize);

	totalLen = required + paddingZeros;

	/* Copy original data */
	ft_memcpy(dst, lastBlock, lastLen);

	/* Add the 0x80 marker */
	dst[lastLen] = 0x80;

	/* Fill with zeros until the length field */
	for (i = lastLen + 1; i < totalLen - 8; i++)
		dst[i] = 0x00;

	/* Add the length in bits (64-bit) */
	bitLen = (uint64_t)params->msgLen * 8;
	for (i = 0; i < 8; i++)
	{
		if (params->isLittleEndian)
			dst[totalLen - 8 + i] = (bitLen >> (8 * i)) & 0xFF;
		else
			dst[totalLen - 8 + i] = (bitLen >> (8 * (7 - i))) & 0xFF;
	}

	return (totalLen);
}
