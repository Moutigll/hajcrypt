#include "../../includes/cipher/cipher.h"

void pkcs7Pad(uint8_t *block, size_t len, size_t blockSize)
{
	uint8_t pad = blockSize - len;
	
	for (size_t i = len; i < blockSize; i++)
		block[i] = pad;
}

int pkcs7Unpad(uint8_t *block, size_t *len, size_t blockSize)
{
	uint8_t pad = block[blockSize - 1];
	
	/* Check that the padding value is valid */
	if (pad == 0 || pad > blockSize)
		return (-1);
	
	/* Check that the padding bytes are correct */
	for (size_t i = blockSize - pad; i < blockSize; i++)
		if (block[i] != pad)
			return (-1);
	
	*len = blockSize - pad;
	return (0);
}
