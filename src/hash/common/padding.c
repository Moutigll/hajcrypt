#include <stdlib.h>


#include "../../../includes/hash/hash.h"

size_t padMessage(uint8_t *dst, const uint8_t *lastBlock, size_t lastLen, t_paddParams *params)
{
	size_t		offset = 0;
	size_t		i;
	uint64_t	bitLen;
	
	if (!dst || !lastBlock || !params || params->blockSize == 0)
		return (0);
	
	for (i = 0; i < lastLen; i++) /* Copy remaining bytes of the last block */
		dst[offset++] = lastBlock[i];
	
	dst[offset++] = 0x80;
	
	size_t	target = params->blockSize - params->lengthFieldSize;
	size_t	mod = offset % params->blockSize;
	size_t	needed;
	
	if (mod <= target)
		needed = target - mod;
	else
		needed = params->blockSize - mod + target;
	
	for (i = 0; i < needed; i++) /* Pad with zeros */
		dst[offset++] = 0x00;
	
	bitLen = (uint64_t)params->msgLen * 8;
	
	if (params->isLittleEndian) { /* Write length in little-endian format */
		for (i = 0; i < params->lengthFieldSize; i++) { /* Write according to specified length field size */
			int shift = 8 * i;
			if (shift < 64)
				dst[offset + i] = (bitLen >> shift) & 0xFF;
			else
				dst[offset + i] = 0;
		}
	} else { /* Write length in big-endian format */
		for (i = 0; i < params->lengthFieldSize; i++) {
			int shift = 8 * (params->lengthFieldSize - 1 - i);
			if (shift < 64)
				dst[offset + i] = (bitLen >> shift) & 0xFF;
			else
				dst[offset + i] = 0;
		}
	}
	
	return (offset + params->lengthFieldSize);
}
