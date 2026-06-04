#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hstring.h"
#include "../../includes/utils/utils.h"
#include "../../includes/kdf/hkdf.h"

#include "../includes/hkdf.h"

int	tlsHkdfExpandLabel(const uint8_t	*secret,
					   size_t			secretLen,
					   const char		*label,
					   const uint8_t	*context,
					   size_t			contextLen,
					   uint8_t			*output,
					   size_t			outputLen,
					   const t_hashAlgo	*hash)
{
	uint8_t	*info;
	size_t	infoLen;
	uint8_t	lenBuf[2];
	uint8_t	labelLenBuf[1];
	uint8_t	contextLenBuf[1];
	uint8_t	*tmpPtr;
	size_t	labelStrLen;
	int		ret;

	if (!secret || !output || !label || !hash)
		return (0);

	labelStrLen = ft_strlen(label);

	infoLen = 2 + 1 + (TLS13_PREFIX_LEN + labelStrLen) + 1 + contextLen;
	info = (uint8_t *)ft_calloc(infoLen, sizeof(uint8_t));
	if (!info)
		return (0);

	tmpPtr = info;

	/* length (16 bits, big endian) */
	lenBuf[0] = (outputLen >> 8) & 0xFF;
	lenBuf[1] = outputLen & 0xFF;
	ft_memcpy(tmpPtr, lenBuf, 2);
	tmpPtr += 2;

	/* label length */
	labelLenBuf[0] = (uint8_t)(TLS13_PREFIX_LEN + labelStrLen);
	ft_memcpy(tmpPtr, labelLenBuf, 1);
	tmpPtr += 1;

	/* label = "tls13 " + label */
	ft_memcpy(tmpPtr, TLS13_PREFIX, TLS13_PREFIX_LEN);
	tmpPtr += TLS13_PREFIX_LEN;
	ft_memcpy(tmpPtr, label, labelStrLen);
	tmpPtr += labelStrLen;

	/* context length (max 255) */
	contextLenBuf[0] = (contextLen < 256) ? (uint8_t)contextLen : 255;
	ft_memcpy(tmpPtr, contextLenBuf, 1);
	tmpPtr += 1;

	/* context */
	if (context && contextLen > 0)
	{
		size_t	toCopy = (contextLen < 256) ? contextLen : 255;
		ft_memcpy(tmpPtr, context, toCopy);
	}

	ret = hkdfExpand(secret, secretLen, info, infoLen, output, outputLen, hash);

	secureZeroMemory(info, infoLen);
	free(info);
	return (ret);
}
