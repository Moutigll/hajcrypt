#include "../../includes/kdf/kdf.h"



int	pbkdfHexToBytes(const char *hex, uint8_t *bytes, size_t maxBytes)
{
	size_t	hexLen;
	size_t	i;
	uint8_t	val;
	char	c;

	if (!hex || !bytes)
		return (-1);
	
	hexLen = 0;
	while (hex[hexLen])
		hexLen++;
	
	if (hexLen % 2 != 0 || hexLen / 2 > maxBytes)
		return (-1);
	
	for (i = 0; i < hexLen / 2; i++)
	{
		val = 0;
		
		/* First character, high nibble */
		c = hex[i * 2];
		if (c >= '0' && c <= '9')
			val = (c - '0') << 4;
		else if (c >= 'A' && c <= 'F')
			val = (c - 'A' + 10) << 4;
		else if (c >= 'a' && c <= 'f')
			val = (c - 'a' + 10) << 4;
		else
			return (-1);
		
		/* Second character, low nibble */
		c = hex[i * 2 + 1];
		if (c >= '0' && c <= '9')
			val |= (c - '0');
		else if (c >= 'A' && c <= 'F')
			val |= (c - 'A' + 10);
		else if (c >= 'a' && c <= 'f')
			val |= (c - 'a' + 10);
		else
			return (-1);
		
		bytes[i] = val;
	}
	
	return ((int)(hexLen / 2));
}
