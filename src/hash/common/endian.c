#include "../../../includes/hash/hash.h"

uint32_t
loadWord32(const uint8_t *ptr, int isLittleEndian)
{
	uint32_t	word;

	if (isLittleEndian)
	{
		word = ((uint32_t)ptr[0])
			| ((uint32_t)ptr[1] << 8)
			| ((uint32_t)ptr[2] << 16)
			| ((uint32_t)ptr[3] << 24);
	}
	else
	{
		word = ((uint32_t)ptr[0] << 24)
			| ((uint32_t)ptr[1] << 16)
			| ((uint32_t)ptr[2] << 8)
			| ((uint32_t)ptr[3]);
	}
	return (word);
}
