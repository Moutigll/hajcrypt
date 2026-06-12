#include <stdlib.h>

#include "../../hajlib/include/hmemory.h"
#include "../../includes/utils/utils.h"
#include "../../includes/hash/hmac.h"

#include "../../includes/kdf/hkdf.h"

int	hkdfExtract(const uint8_t	*salt,	size_t	saltLen,
				const uint8_t	*ikm,	size_t	ikmLen,
				uint8_t			*prk,	size_t	prkLen,
				const t_hash	*hash)
{
	uint8_t	*zeroSalt;

	if ((!ikm && ikmLen > 0) || !prk || !hash)
		return (0);
	if (prkLen < hash->digestSize)
		return (0);

	if (!salt || saltLen == 0)
	{
		zeroSalt = ft_calloc(1, hash->digestSize);
		if (!zeroSalt)
			return (0);
		hmac(hash, zeroSalt, hash->digestSize, ikm, ikmLen, prk);
		secureZeroMemory(zeroSalt, hash->digestSize);
		free(zeroSalt);
	}
	else
	{
		hmac(hash, salt, saltLen, ikm, ikmLen, prk);
	}
	return (1);
}

int hkdfExpand(const uint8_t *prk,  size_t prkLen,
               const uint8_t *info, size_t infoLen,
               uint8_t       *okm,  size_t okmLen,
               const t_hash  *hash)
{
    uint8_t previous[128];
    uint8_t current[128];
    uint8_t counter;
    size_t  remaining;
    uint8_t *buffer;
    size_t  bufLen;
    size_t  prevLen;
    int     firstBlock;
    int     ret;

    if (!prk || !okm || !hash)           return 0;
    if (prkLen < hash->digestSize)       return 0;
    if (okmLen > 255 * hash->digestSize) return 0;

    remaining  = okmLen;
    counter    = 1;
    ret        = 1;
    firstBlock = 1;

    while (remaining > 0)
    {
        /* T(0) is the empty string, so skip it on the first block */
        prevLen = firstBlock ? 0 : hash->digestSize;
        bufLen  = prevLen + infoLen + 1;

        buffer = ft_calloc(1, bufLen);
        if (!buffer) { ret = 0; break; }

        if (!firstBlock)
            ft_memcpy(buffer, previous, hash->digestSize);
        if (info && infoLen)
            ft_memcpy(buffer + prevLen, info, infoLen);
        buffer[prevLen + infoLen] = counter;

        hmac(hash, prk, prkLen, buffer, bufLen, current);

        size_t toCopy = (remaining < hash->digestSize) ? remaining : hash->digestSize;
        ft_memcpy(okm + (okmLen - remaining), current, toCopy);
        remaining -= toCopy;
        counter++;
        ft_memcpy(previous, current, hash->digestSize);
        firstBlock = 0;

        secureZeroMemory(buffer, bufLen);
        free(buffer);
    }

    secureZeroMemory(previous, hash->digestSize);
    secureZeroMemory(current, sizeof(current));
    return ret;
}

int	hkdf(const uint8_t	*salt,	size_t	saltLen,
		 const uint8_t	*ikm,	size_t	ikmLen,
		 const uint8_t	*info,	size_t	infoLen,
		 uint8_t		*okm,	size_t	okmLen,
		 const t_hash	*hash)
{
	uint8_t	prk[64];
	
	if (!hkdfExtract(salt, saltLen, ikm, ikmLen, prk, sizeof(prk), hash))
		return (0);
	return (hkdfExpand(prk, hash->digestSize, info, infoLen, okm, okmLen, hash));
}
