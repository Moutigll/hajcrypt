#include "../../includes/cipher/cipher.h"

void pkcs7Pad(uint8_t *block, size_t len, size_t blockSize)
{
	uint8_t pad = blockSize - len;
	
	for (size_t i = len; i < blockSize; i++)
		block[i] = pad;
}

int pkcs7Unpad(uint8_t *block, size_t *len, size_t blockSize)
{
	if (!block || !len)
		return (-1);

	uint8_t pad = block[*len - 1];
	
	/* Check that the padding value is valid */
	if (pad == 0 || pad > blockSize || pad > *len)
		return (-1);
	
	/* Check that the padding bytes are correct */
	for (size_t i = *len - pad; i < *len; i++)
		if (block[i] != pad)
			return (-1);
	
	*len = *len - pad;
	return (0);
}
