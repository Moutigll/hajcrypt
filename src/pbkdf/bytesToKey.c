#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hstring.h"

#include "../../includes/hash/md5.h"
#include "../../includes/utils/utils.h"

#include "../../includes/pbkdf/pbkdf.h"
#include "../../includes/pbkdf/bytesToKey.h"

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
	size_t			offset;
	size_t			remaining;

	if (!password || !key || !iv)
		return (-1);

	if (keyLen != 8 && keyLen != 16 && keyLen != 24)
		return (-1);

	saltPtr = getSaltOrDefault(salt, defaultSalt, PBKDF_BTK_SALT_SIZE);

	ft_bzero(key, keyLen);
	offset = 0;
	remaining = keyLen;

	while (remaining > 0)
	{
		md5Init(&md5Ctx);
		
		/* If not the first iteration, hash the previous hash to create a chain */
		if (offset > 0)
			md5Update(&md5Ctx, hash, PBKDF_BTK_HASH_SIZE);
		
		/* Hash password and salt */
		md5Update(&md5Ctx, (const uint8_t *)password, passLen);
		md5Update(&md5Ctx, saltPtr, PBKDF_BTK_SALT_SIZE);
		
		md5Final(hash, &md5Ctx);
		
		/* Copy the hash output to the key buffer, handling cases where keyLen > hash size */
		if (remaining >= PBKDF_BTK_HASH_SIZE)
		{
			ft_memcpy(key + offset, hash, PBKDF_BTK_HASH_SIZE);
			offset += PBKDF_BTK_HASH_SIZE;
			remaining -= PBKDF_BTK_HASH_SIZE;
		}
		else
		{
			ft_memcpy(key + offset, hash, remaining);
			offset += remaining;
			remaining = 0;
		}
	}

	/* For IV, we can simply hash the key and salt again */
	md5Init(&md5Ctx);
	md5Update(&md5Ctx, key, keyLen);
	md5Update(&md5Ctx, (const uint8_t *)password, passLen);
	md5Update(&md5Ctx, saltPtr, PBKDF_BTK_SALT_SIZE);
	md5Final(hash, &md5Ctx);
	
	/* Use the first 8 bytes of the final hash as IV */
	ft_memcpy(iv, hash, PBKDF_BTK_IV_SIZE_8);

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
