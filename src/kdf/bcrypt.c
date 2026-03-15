#include <stddef.h>
#include <stdint.h>

#include "../../hajlib/include/hstring.h"
#include "../../hajlib/include/hmemory.h"

#include "../../includes/kdf/bcrypt.h"
#include "../../includes/cipher/blowfish.h"
#include "../../includes/utils/random.h"

#include "../../includes/kdf/bcrypt.h"

/* bcrypt-specific Base64 alphabet (different from standard Base64) */
static const char g_bcryptBase64[] =
	"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/**
 * @brief Expand the Blowfish state with a key (like blowfishInitKey but using existing state)
 * 
 * This function reuses the same logic as blowfishInitKey but does not reinitialize
 * the P and S arrays; instead, it XORs the key into the P-array and then re-encrypts
 * the zero block to update all subkeys.
 * 
 * @param ctx   Blowfish context (P and S arrays)
 * @param key   Key bytes
 * @param keyLen Length of key
 */
static void blowfishExpandWithKey(t_blowfishEcbCtx *ctx, const uint8_t *key, size_t keyLen)
{
	uint32_t	i;
	uint32_t	j;
	uint32_t	data;
	uint32_t	l;
	uint32_t	r;
	uint64_t	block;

	/* XOR P-array with key */
	j = 0;
	for (i = 0; i < 18; i++)
	{
		data = ((uint32_t)key[j % keyLen] << 24) |
			   ((uint32_t)key[(j + 1) % keyLen] << 16) |
			   ((uint32_t)key[(j + 2) % keyLen] << 8) |
			   (uint32_t)key[(j + 3) % keyLen];
		ctx->P[i] ^= data;
		j = (j + 4) % keyLen;
	}

	/* Re-encrypt zero block to update P-array */
	l = 0;
	r = 0;
	for (i = 0; i < 18; i += 2)
	{
		block = ((uint64_t)l << 32) | r;
		block = blowfishEncryptBlock(ctx, block);
		l = block >> 32;
		r = block & 0xFFFFFFFF;
		ctx->P[i] = l;
		ctx->P[i + 1] = r;
	}

	/* Update S-boxes */
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 256; j += 2)
		{
			block = ((uint64_t)l << 32) | r;
			block = blowfishEncryptBlock(ctx, block);
			l = block >> 32;
			r = block & 0xFFFFFFFF;
			ctx->S[i][j] = l;
			ctx->S[i][j + 1] = r;
		}
	}
}

/**
 * @brief Expand the Blowfish state with a salt (XOR salt into P-array and re-encrypt)
 * 
 * @param ctx   Blowfish context
 * @param salt  Salt bytes (16 bytes)
 */
static void blowfishExpandWithSalt(t_blowfishEcbCtx *ctx, const uint8_t salt[16])
{
	uint32_t	i;
	uint32_t	j;
	uint32_t	saltWord;
	uint32_t	l;
	uint32_t	r;
	uint64_t	block;

	/* XOR salt into P-array (salt is 16 bytes, so we have 4 words) */
	for (i = 0; i < 4; i++)
	{
		saltWord = ((uint32_t)salt[i * 4] << 24) |
				   ((uint32_t)salt[i * 4 + 1] << 16) |
				   ((uint32_t)salt[i * 4 + 2] << 8) |
				   (uint32_t)salt[i * 4 + 3];
		ctx->P[i] ^= saltWord;
	}

	/* Re-encrypt zero block to update P-array */
	l = 0;
	r = 0;
	for (i = 0; i < 18; i += 2)
	{
		block = ((uint64_t)l << 32) | r;
		block = blowfishEncryptBlock(ctx, block);
		l = block >> 32;
		r = block & 0xFFFFFFFF;
		ctx->P[i] = l;
		ctx->P[i + 1] = r;
	}

	/* Update S-boxes */
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 256; j += 2)
		{
			block = ((uint64_t)l << 32) | r;
			block = blowfishEncryptBlock(ctx, block);
			l = block >> 32;
			r = block & 0xFFFFFFFF;
			ctx->S[i][j] = l;
			ctx->S[i][j + 1] = r;
		}
	}
}

/**
 * @brief EksBlowfishSetup - the expensive key schedule of bcrypt
 * 
 * @param ctx   bcrypt context
 * @param key   password bytes
 * @param keyLen password length
 * @param salt  16-byte salt
 * @param cost  iteration cost (2^cost rounds)
 */
static void eksBlowfishSetup(t_bcryptCtx	*ctx,
							 const uint8_t	*key,
							 size_t			keyLen,
							 const uint8_t	salt[16],
							 uint32_t		cost)
{
	uint32_t	rounds;
	uint32_t	i;

	/* Initialize Blowfish with standard constants */
	blowfishInitKey(&ctx->blowfishCtx, key, keyLen);

	/* XOR salt into P-array (first 4 words) */
	for (i = 0; i < 4; i++)
	{
		uint32_t saltWord = ((uint32_t)salt[i * 4] << 24) |
							((uint32_t)salt[i * 4 + 1] << 16) |
							((uint32_t)salt[i * 4 + 2] << 8) |
							(uint32_t)salt[i * 4 + 3];
		ctx->blowfishCtx.P[i] ^= saltWord;
	}

	/* Perform 2^cost rounds of key expansion with salt and key */
	rounds = 1 << cost;
	for (i = 0; i < rounds; i++)
	{
		blowfishExpandWithSalt(&ctx->blowfishCtx, salt);
		blowfishExpandWithKey(&ctx->blowfishCtx, key, keyLen);
	}
}

/**
 * @brief Encrypt the magic string 64 times using the current Blowfish state
 * 
 * @param ctx   bcrypt context
 * @param output 24-byte output hash
 */
static void bcryptEncryptMagic(const t_bcryptCtx *ctx, uint8_t output[24])
{
	uint8_t	 data[24];
	uint32_t	i;
	uint32_t	j;
	uint64_t	block;

	/* Copy magic string */
	ft_memcpy(data, BCRYPT_MAGIC_STR, 24);

	/* 64 rounds of encryption */
	for (i = 0; i < 64; i++)
	{
		/* Encrypt each 8-byte block */
		for (j = 0; j < 24; j += 8)
		{
			/* Assemble 64-bit block in big-endian order */
			block = ((uint64_t)data[j] << 56) |
					((uint64_t)data[j + 1] << 48) |
					((uint64_t)data[j + 2] << 40) |
					((uint64_t)data[j + 3] << 32) |
					((uint64_t)data[j + 4] << 24) |
					((uint64_t)data[j + 5] << 16) |
					((uint64_t)data[j + 6] << 8) |
					(uint64_t)data[j + 7];

			block = blowfishEncryptBlock(&ctx->blowfishCtx, block);

			/* Store back */
			data[j] = (block >> 56) & 0xFF;
			data[j + 1] = (block >> 48) & 0xFF;
			data[j + 2] = (block >> 40) & 0xFF;
			data[j + 3] = (block >> 32) & 0xFF;
			data[j + 4] = (block >> 24) & 0xFF;
			data[j + 5] = (block >> 16) & 0xFF;
			data[j + 6] = (block >> 8) & 0xFF;
			data[j + 7] = block & 0xFF;
		}
	}

	/* Copy result */
	ft_memcpy(output, data, 24);
}

/**
 * @brief bcrypt-specific Base64 encoding
 * 
 * @param dst   output string (null-terminated)
 * @param src   input bytes
 * @param len   number of input bytes
 */
void bcryptEncodeBase64(char *dst, const uint8_t *src, size_t len)
{
	uint32_t	i;
	uint32_t	j;
	uint32_t	c1, c2, c3;

	i = 0;
	j = 0;
	
	while (i < len)
	{
		c1 = src[i++];
		c2 = (i < len) ? src[i++] : 0;
		c3 = (i < len) ? src[i++] : 0;

		dst[j++] = g_bcryptBase64[c1 >> 2];
		dst[j++] = g_bcryptBase64[((c1 & 0x03) << 4) | (c2 >> 4)];
		
		if (i - 2 < len)  /* We had at least c2 */
			dst[j++] = g_bcryptBase64[((c2 & 0x0F) << 2) | (c3 >> 6)];
		else
			dst[j++] = '=';
			
		if (i - 1 < len)  /* We had c3 */
			dst[j++] = g_bcryptBase64[c3 & 0x3F];
		else
			dst[j++] = '=';
	}

	dst[j] = '\0';
}

/**
 * @brief bcrypt-specific Base64 decoding
 * 
 * @param dst   output bytes buffer
 * @param src   input string
 * @param maxLen maximum number of bytes to write
 * @return number of bytes written, or -1 on error
 */
int bcryptDecodeBase64(uint8_t *dst, const char *src, size_t maxLen)
{
	uint32_t	i;
	uint32_t	j;
	uint32_t	x, y, z;
	char		*pos;

	i = 0;
	j = 0;
	while (src[i] && src[i + 1] && src[i + 2] && src[i + 3] && j < maxLen)
	{
		/* Find indices in bcryptBase64 table */
		pos = ft_strchr(g_bcryptBase64, src[i]);
		if (!pos)
			return (-1);
		x = pos - g_bcryptBase64;

		pos = ft_strchr(g_bcryptBase64, src[i + 1]);
		if (!pos)
			return (-1);
		y = pos - g_bcryptBase64;

		pos = ft_strchr(g_bcryptBase64, src[i + 2]);
		if (!pos)
			return (-1);
		z = pos - g_bcryptBase64;

		/* First byte */
		dst[j++] = (x << 2) | (y >> 4);

		/* Second byte if not padding */
		if (src[i + 2] != '=' && j < maxLen)
		{
			dst[j++] = ((y & 0x0F) << 4) | (z >> 2);
		}

		/* Third byte if not padding */
		if (src[i + 3] != '=' && j < maxLen)
		{
			pos = ft_strchr(g_bcryptBase64, src[i + 3]);
			if (!pos)
				return (-1);
			dst[j++] = ((z & 0x03) << 6) | (pos - g_bcryptBase64);
		}

		i += 4;
	}

	return ((int)j);
}

/* ---------- Public API ---------- */

int bcryptHash(const char *password,
			   const uint8_t salt[16],
			   uint32_t cost,
			   char output[60])
{
	t_bcryptCtx ctx;
	uint8_t	 hash[24];
	uint8_t	 key[BCRYPT_MAX_PASSWD];
	size_t	  keyLen;
	char		*saltEnc;
	char		*hashEnc;
	uint32_t	i;

	if (!password || !salt || !output)
		return (-1);
	if (cost < BCRYPT_COST_MIN || cost > BCRYPT_COST_MAX)
		return (-1);

	/* Copy password, truncate if needed */
	keyLen = ft_strlen(password);
	if (keyLen > BCRYPT_MAX_PASSWD)
		keyLen = BCRYPT_MAX_PASSWD;
	for (i = 0; i < keyLen; i++)
		key[i] = (uint8_t)password[i];

	/* Store salt and cost in context */
	ctx.cost = cost;
	ft_memcpy(ctx.salt, salt, 16);

	/* EksBlowfishSetup */
	eksBlowfishSetup(&ctx, key, keyLen, salt, cost);

	/* Encrypt magic string */
	bcryptEncryptMagic(&ctx, hash);

	/* Format output: "$2b$[cost]$[salt][hash]" */
	output[0] = '$';
	output[1] = '2';
	output[2] = 'b';
	output[3] = '$';
	output[4] = '0' + (cost / 10);
	output[5] = '0' + (cost % 10);
	output[6] = '$';

	saltEnc = output + 7;
	hashEnc = saltEnc + 22;   /* 16 bytes encoded as 22 chars */

	bcryptEncodeBase64(saltEnc, salt, 16);
	bcryptEncodeBase64(hashEnc, hash, 24);
	output[59] = '\0';

	return (0);
}

int bcryptVerify(const char *password, const char *hash)
{
	char		newHash[60];
	uint8_t		salt[16];
	uint32_t	cost;
	int			saltLen;
	uint32_t	i;
	int			diff;

	if (!password || !hash)
		return (-1);

	/* Check format "$2b$XX$..." */
	if (hash[0] != '$' || hash[1] != '2' || hash[2] != 'b' || hash[3] != '$')
		return (-1);

	/* Extract cost */
	if (hash[4] < '0' || hash[4] > '9' || hash[5] < '0' || hash[5] > '9')
		return (-1);
	cost = (hash[4] - '0') * 10 + (hash[5] - '0');

	/* Decode salt (22 chars -> 16 bytes) */
	saltLen = bcryptDecodeBase64(salt, hash + 7, 16);
	if (saltLen != 16)
		return (-1);

	/* Recompute hash */
	if (bcryptHash(password, salt, cost, newHash) != 0)
		return (-1);

	/* Constant-time comparison */
	diff = 0;
	for (i = 0; i < 60; i++)
		diff |= newHash[i] ^ hash[i];

	return (diff == 0 ? 0 : -1);
}

int bcryptGenSalt(uint8_t salt[16])
{
	if (!salt)
		return (-1);

	return (hajSecRandBytes(salt, 16));
}

int bcryptSimple(const char *password, uint32_t cost, char output[60])
{
	uint8_t	salt[16];

	if (!password || !output)
		return (-1);

	if (bcryptGenSalt(salt) != 0)
		return (-1);

	return (bcryptHash(password, salt, cost, output));
}

int bcryptHashWithSalt(const char *password,
					   const char *saltStr,
					   uint32_t cost,
					   char *output)
{
	uint8_t salt[16];

	if (!password || !saltStr || !output)
		return (-1);

	if (bcryptDecodeBase64(salt, saltStr, 16) != 16)
		return (-1);

	return (bcryptHash(password, salt, cost, output));
}
