#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hstring.h"
#include "../../includes/utils/random.h"

#include "../../includes/kdf/bytesToKey.h"

static const uint8_t	*getSaltOrDefault(const uint8_t *salt, uint8_t *defaultSalt, size_t saltSize)
{
	if (salt)
		return (salt);
	ft_bzero(defaultSalt, saltSize);
	return (defaultSalt);
}

int	pbkdfBytesToKeySimple(const t_hash	*hash,
						  const char	*password,
						  size_t		passLen,
						  const uint8_t	*salt,
						  uint8_t		*key,
						  uint8_t		*iv)
{
	void			*ctx;
	uint8_t			digest[64];
	uint8_t			defaultSalt[PBKDF_BTK_SALT_SIZE];
	const uint8_t	*saltPtr;
	size_t			digestSize;

	if (!hash || !password || !key || !iv)
		return (-1);

	digestSize = hash->digestSize;
	if (digestSize < PBKDF_BTK_KEY_SIZE_8 + PBKDF_BTK_IV_SIZE_8)
		return (-1);

	saltPtr = getSaltOrDefault(salt, defaultSalt, PBKDF_BTK_SALT_SIZE);

	ctx = malloc(hash->ctxSize);
	if (!ctx)
		return (-1);

	hash->init(ctx);
	hash->update(ctx, (const uint8_t *)password, passLen);
	hash->update(ctx, saltPtr, PBKDF_BTK_SALT_SIZE);
	hash->final(digest, ctx);

	free(ctx);

	ft_memcpy(key, digest, PBKDF_BTK_KEY_SIZE_8);
	ft_memcpy(iv, digest + PBKDF_BTK_KEY_SIZE_8, PBKDF_BTK_IV_SIZE_8);

	return (0);
}

int	pbkdfBytesToKeyExtended(const t_hash	*hash,
							const char		*password,
							size_t			passLen,
							const uint8_t	*salt,
							size_t			keyLen,
							uint8_t			*key,
							uint8_t			*iv)
{
	void			*ctx;
	uint8_t			digest[64];
	uint8_t			prev_digest[64];
	uint8_t			defaultSalt[PBKDF_BTK_SALT_SIZE];
	const uint8_t	*saltPtr;
	uint8_t			*buffer;
	size_t			totalLen = keyLen + PBKDF_BTK_IV_SIZE_8;
	size_t			offset = 0;
	int				first = 1;
	size_t			digestSize;

	if (!hash || !password || !key || !iv)
		return (-1);

	if (keyLen != 8 && keyLen != 16 && keyLen != 24)
		return (-1);

	digestSize = hash->digestSize;
	if (digestSize < 16)
		return (-1);

	saltPtr = getSaltOrDefault(salt, defaultSalt, PBKDF_BTK_SALT_SIZE);

	buffer = malloc(totalLen);
	if (!buffer)
		return (-1);

	ctx = malloc(hash->ctxSize);
	if (!ctx) {
		free(buffer);
		return (-1);
	}

	while (offset < totalLen)
	{
		hash->init(ctx);

		if (!first)
			hash->update(ctx, prev_digest, digestSize);
		else
			first = 0;

		hash->update(ctx, (const uint8_t *)password, passLen);
		hash->update(ctx, saltPtr, PBKDF_BTK_SALT_SIZE);
		hash->final(digest, ctx);

		ft_memcpy(prev_digest, digest, digestSize);

		size_t to_copy = digestSize;
		if (offset + to_copy > totalLen)
			to_copy = totalLen - offset;

		ft_memcpy(buffer + offset, digest, to_copy);
		offset += to_copy;
	}

	free(ctx);

	ft_memcpy(key, buffer, keyLen);
	ft_memcpy(iv, buffer + keyLen, PBKDF_BTK_IV_SIZE_8);

	free(buffer);
	return (0);
}

int	pbkdfBytesToKeyFromHex(const t_hash	*hash,
						   const char	*password,
						   const char	*saltHex,
						   size_t		keyLen,
						   uint8_t		*key,
						   uint8_t		*iv)
{
	uint8_t		salt[PBKDF_BTK_SALT_SIZE];
	int			converted;

	if (!hash || !password || !saltHex || !key || !iv)
		return (-1);

	converted = pbkdfHexToBytes(saltHex, salt, PBKDF_BTK_SALT_SIZE);
	if (converted != PBKDF_BTK_SALT_SIZE)
		return (-1);

	return (pbkdfBytesToKeyExtended(hash, password, ft_strlen(password), salt, keyLen, key, iv));
}

int	pbkdfBytesToKeyWithRandomSalt(const t_hash	*hash,
								  const char	*password,
								  size_t		keyLen,
								  uint8_t		*key,
								  uint8_t		*iv,
								  uint8_t		*generatedSalt)
{
	if (!hash || !password || !key || !iv || !generatedSalt)
		return (-1);

	if (hajSecRandBytes(generatedSalt, PBKDF_BTK_SALT_SIZE) != 0)
		return (-1);

	return (pbkdfBytesToKeyExtended(hash, password, ft_strlen(password), generatedSalt, keyLen, key, iv));
}
