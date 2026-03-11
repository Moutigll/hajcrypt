#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hstring.h"

#include "../../includes/hash/md5.h"
#include "../../includes/utils/utils.h"

#include "../../includes/kdf/bytesToKey.h"

static const uint8_t	*getSaltOrDefault(const uint8_t *salt, uint8_t *defaultSalt, size_t saltSize)
{
	if (salt)
		return (salt);
	ft_bzero(defaultSalt, saltSize);
	return (defaultSalt);
}

int	pbkdfBytesToKeySimple(const char	*password,
						  size_t		passLen,
						  const uint8_t	*salt,
						  uint8_t		*key,
						  uint8_t		*iv)
{
	t_md5Ctx		md5Ctx;
	uint8_t			hash[PBKDF_BTK_HASH_SIZE];
	uint8_t			defaultSalt[PBKDF_BTK_SALT_SIZE];
	const uint8_t	*saltPtr;

	if (!password || !key || !iv)
		return (-1);

	saltPtr = getSaltOrDefault(salt, defaultSalt, PBKDF_BTK_SALT_SIZE);

	/* MD5(password || salt) */
	md5Init(&md5Ctx);
	md5Update(&md5Ctx, (const uint8_t *)password, passLen);
	md5Update(&md5Ctx, saltPtr, PBKDF_BTK_SALT_SIZE);
	md5Final(hash, &md5Ctx);

	/* First 8 bytes = key */
	ft_memcpy(key, hash, PBKDF_BTK_KEY_SIZE_8);

	/* Next 8 bytes = IV */
	ft_memcpy(iv, hash + PBKDF_BTK_KEY_SIZE_8, PBKDF_BTK_IV_SIZE_8);

	return (0);
}

int	pbkdfBytesToKeyExtended(const char		*password,
							size_t			passLen,
							const uint8_t	*salt,
							size_t			keyLen,
							uint8_t			*key,
							uint8_t			*iv)
{
	t_md5Ctx		md5Ctx;
	uint8_t			hash[PBKDF_BTK_HASH_SIZE];
	uint8_t			defaultSalt[PBKDF_BTK_SALT_SIZE];
	const uint8_t	*saltPtr;
	uint8_t			*buffer;
	size_t			totalLen = keyLen + PBKDF_BTK_IV_SIZE_8;
	size_t			offset = 0;
	int				first = 1;

	if (!password || !key || !iv)
		return (-1);

	if (keyLen != 8 && keyLen != 16 && keyLen != 24)
		return (-1);

	saltPtr = getSaltOrDefault(salt, defaultSalt, PBKDF_BTK_SALT_SIZE);
	
	buffer = malloc(totalLen);
	if (!buffer)
		return (-1);

	while (offset < totalLen)
	{
		md5Init(&md5Ctx);
		
		/* Hash previous hash except for first iteration */
		if (!first)
			md5Update(&md5Ctx, hash, PBKDF_BTK_HASH_SIZE);
		else
			first = 0;
		
		md5Update(&md5Ctx, (const uint8_t *)password, passLen);
		md5Update(&md5Ctx, saltPtr, PBKDF_BTK_SALT_SIZE);
		md5Final(hash, &md5Ctx);

		size_t to_copy = PBKDF_BTK_HASH_SIZE;
		if (offset + to_copy > totalLen)
			to_copy = totalLen - offset;
		
		ft_memcpy(buffer + offset, hash, to_copy);
		offset += to_copy;
	}

	/* Split buffer into key and IV */
	ft_memcpy(key, buffer, keyLen);
	ft_memcpy(iv, buffer + keyLen, PBKDF_BTK_IV_SIZE_8);
	
	free(buffer);
	return (0);
}

int	pbkdfBytesToKeyFromHex(const char	*password,
						   const char	*saltHex,
						   size_t		keyLen,
						   uint8_t		*key,
						   uint8_t		*iv)
{
	uint8_t		salt[PBKDF_BTK_SALT_SIZE];
	int			converted;

	if (!password || !saltHex || !key || !iv)
		return (-1);

	converted = pbkdfHexToBytes(saltHex, salt, PBKDF_BTK_SALT_SIZE);
	if (converted != PBKDF_BTK_SALT_SIZE)
		return (-1);

	return (pbkdfBytesToKeyExtended(password,
									ft_strlen(password),
									salt, keyLen, key, iv));
}

int	pbkdfBytesToKeyWithRandomSalt(const char	*password,
								  size_t		keyLen,
								  uint8_t		*key,
								  uint8_t		*iv,
								  uint8_t		*generatedSalt)
{
	if (!password || !key || !iv || !generatedSalt)
		return (-1);

	if (hajSecRandBytes(generatedSalt, PBKDF_BTK_SALT_SIZE) != 0)
		return (-1);

	return (pbkdfBytesToKeyExtended(password,
									ft_strlen(password),
									generatedSalt, keyLen, key, iv));
}
