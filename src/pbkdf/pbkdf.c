#include "../../hajlib/include/hstring.h"
#include "../../hajlib/include/hmath.h"

#include "../../includes/pbkdf/pbkdf.h"

int	pbkdfHexToBytes(const char *hex, uint8_t *bytes, size_t maxBytes)
{
	size_t	hexLen;
	size_t	i;
	char	byteStr[3];
	int		val;

	if (!hex || !bytes)
		return (-1);
	
	hexLen = ft_strlen(hex);
	if (hexLen % 2 != 0 || hexLen / 2 > maxBytes)
		return (-1);
	
	i = 0;
	while (i < hexLen / 2)
	{
		byteStr[0] = hex[i * 2];
		byteStr[1] = hex[i * 2 + 1];
		byteStr[2] = '\0';
		
		/* Try uppercase hex digits first */
		val = ft_atoi_base(byteStr, (char *)"0123456789ABCDEF");
		if (val == 0 && (byteStr[0] != '0' || byteStr[1] != '0'))
		{
			/* If uppercase conversion fails, try lowercase */
			val = ft_atoi_base(byteStr, (char *)"0123456789abcdef");
			if (val == 0 && (byteStr[0] != '0' || byteStr[1] != '0'))
				return (-1);
		}
		
		bytes[i] = (uint8_t)val;
		i++;
	}
	
	return ((int)(hexLen / 2));
}
