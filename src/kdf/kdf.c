#include "../../hajlib/include/hmemory.h"
#include "../../hajlib/include/hstring.h"

#include "../../includes/hash/sha256.h"
#include "../../includes/kdf/bytesToKey.h"
#include "../../includes/kdf/pbkdf2.h"
#include "../../includes/kdf/bcrypt.h"
#include "../../includes/kdf/argon2.h"

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

int deriveKeyFromParams(t_sslOptions *opts, uint8_t *key, size_t keyLen, uint8_t *iv)
{
	uint8_t	salt[8];
	size_t	saltLen = 8;
	
	/* Convert salt from hex to bytes */
	if (opts->saltHex) {
		if (pbkdfHexToBytes(opts->saltHex, salt, 8) < 0)
			return (-1);
	} else
		return (-1);

	switch (opts->kdfChoice) {
		case KDF_BYTESTOKEY:
			return (pbkdfBytesToKeyExtended(opts->password,
										  ft_strlen(opts->password),
										  salt, keyLen, key, iv));
		
		case KDF_PBKDF2: {
			t_pbkdf2Ctx ctx;
			pbkdf2Init(&ctx, &g_sha256Hash,
					  (const uint8_t*)opts->password,
					  ft_strlen(opts->password),
					  salt, saltLen,
					  opts->kdfIterations);
			return (pbkdf2Derive(&ctx, key, keyLen) == 0 ? 0 : -1);
		}
		
		case KDF_BCRYPT: {
			uint8_t derived[24];
			int ret = bcryptHash(opts->password, salt,
								opts->kdfIterations, (char*)derived);
			if (ret != 0) return (-1);
			ft_memcpy(key, derived, keyLen < 24 ? keyLen : 24);
			return (0);
		}
		
		case KDF_ARGON2D:
		case KDF_ARGON2I:
		case KDF_ARGON2ID: {
			t_argon2Type type;
			t_argon2Ctx ctx;
			
			type = (opts->kdfChoice == KDF_ARGON2D) ? ARGON2_D :
				   (opts->kdfChoice == KDF_ARGON2I) ? ARGON2_I : ARGON2_ID;
			
			argon2Init(&ctx,
					  (const uint8_t*)opts->password,
					  ft_strlen(opts->password),
					  salt, saltLen,
					  opts->kdfMemory,
					  opts->kdfIterations,
					  opts->kdfParallelism,
					  type);
			ctx.outputLen = keyLen;
			int ret = argon2Hash(&ctx, key, keyLen);
			argon2Free(&ctx);
			return (ret == 0 ? 0 : -1);
		}
		
		default:
			return (-1);
	}
}
