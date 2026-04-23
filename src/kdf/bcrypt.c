#include <stddef.h>
#include <stdint.h>

#include "../../hajlib/include/hstring.h"
#include "../../hajlib/include/hmemory.h"

#include "../../includes/kdf/bcrypt.h"
#include "../../includes/cipher/blowfish.h"
#include "../../includes/utils/random.h"
#include "../../includes/utils/utils.h"

/* bcrypt-specific Base64 alphabet (different from standard Base64) */
static const char g_bcryptBase64[] =
	"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

void bcryptEncodeBase64(char *dst, const uint8_t *src, size_t len)
{
	uint32_t	i = 0;
	uint32_t	j = 0;
	uint32_t	c1, c2, c3;

	while (i < len)
	{
		c1 = src[i++];
		dst[j++] = g_bcryptBase64[c1 >> 2];
		c1 = (c1 & 0x03) << 4;
		if (i >= len) { dst[j++] = g_bcryptBase64[c1]; break; }

		c2 = src[i++];
		c1 |= (c2 >> 4);
		dst[j++] = g_bcryptBase64[c1];
		c2 = (c2 & 0x0F) << 2;
		if (i >= len) { dst[j++] = g_bcryptBase64[c2]; break; }

		c3 = src[i++];
		c2 |= (c3 >> 6);
		dst[j++] = g_bcryptBase64[c2];
		dst[j++] = g_bcryptBase64[c3 & 0x3F];
	}
	dst[j] = '\0';
}

int bcryptDecodeBase64(uint8_t *dst, const char *src, size_t maxLen)
{
	uint32_t	i = 0;
	uint32_t	j = 0;
	uint32_t	v[4];
	size_t		len;
	int			k;
	int			valid_chars;

	if (!src || !dst)
		return (-1);

	len = ft_strlen(src);

	while (i < len && j < maxLen)
	{
		valid_chars = 0;
		for (k = 0; k < 4; k++)
		{
			if (i + k >= len)
			{
				v[k] = 0;
				continue;
			}
			if (src[i + k] == '=')
			{
				v[k] = 0;
			}
			else
			{
				char	*pos = ft_strchr(g_bcryptBase64, src[i + k]);
				if (!pos)
					return (-1);
				v[k] = pos - g_bcryptBase64;
				valid_chars++;
			}
		}
		if (valid_chars >= 2 && j < maxLen)
			dst[j++] = (v[0] << 2) | (v[1] >> 4);
		if (valid_chars >= 3 && j < maxLen)
			dst[j++] = ((v[1] & 0x0F) << 4) | (v[2] >> 2);
		if (valid_chars == 4 && j < maxLen)
			dst[j++] = ((v[2] & 0x03) << 6) | v[3];
		if (valid_chars < 4)
			break;
		i += 4;
	}
	return ((int)j);
}

/*
 * expand0state(key) — ExpandKey(state, 0, key)
 * XOR key into P-array, then encrypt the all-zero block (no salt in ctext).
 * Used in the 2^cost iteration loop.
 */
static void blowfishExpand0StateKey(t_blowfishEcbCtx *ctx, const uint8_t *key, size_t keyLen)
{
	uint32_t	i;
	uint32_t	j;
	uint32_t	data;
	uint8_t		block[8] = {0};
	uint8_t		out[8];

	/* XOR key into P-array (cycling by byte) */
	j = 0;
	for (i = 0; i < 18; i++)
	{
		data = ((uint32_t)key[j % keyLen]	   << 24) |
			   ((uint32_t)key[(j + 1) % keyLen] << 16) |
			   ((uint32_t)key[(j + 2) % keyLen] <<  8) |
			   (uint32_t) key[(j + 3) % keyLen];
		ctx->P[i] ^= data;
		j = (j + 4) % keyLen;
	}

	/* Re-encrypt zero block to update P-array */
	for (i = 0; i < 18; i += 2)
	{
		blowfishEncryptBlock(ctx->P, ctx->S, block, out);
		ctx->P[i]	 = ((uint32_t)out[0] << 24) | ((uint32_t)out[1] << 16) |
						((uint32_t)out[2] <<  8) |  (uint32_t)out[3];
		ctx->P[i + 1] = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
						((uint32_t)out[6] <<  8) |  (uint32_t)out[7];
		ft_memcpy(block, out, 8);
	}
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 256; j += 2)
		{
			blowfishEncryptBlock(ctx->P, ctx->S, block, out);
			ctx->S[i][j]	 = ((uint32_t)out[0] << 24) | ((uint32_t)out[1] << 16) |
							   ((uint32_t)out[2] <<  8) |  (uint32_t)out[3];
			ctx->S[i][j + 1] = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
							   ((uint32_t)out[6] <<  8) |  (uint32_t)out[7];
			ft_memcpy(block, out, 8);
		}
	}
}

/*
 * expand0state(salt) — ExpandKey(state, 0, salt)
 * Treat salt as key material (XOR into P), encrypt zero block.
 * Used in the 2^cost iteration loop.
 */
static void blowfishExpand0StateSalt(t_blowfishEcbCtx *ctx, const uint8_t salt[16])
{
	uint32_t	i;
	uint32_t	j;
	uint32_t	saltWord;
	uint8_t		block[8] = {0};
	uint8_t		out[8];

	/* XOR salt into P-array (cycling across 16 bytes) */
	j = 0;
	for (i = 0; i < 18; i++)
	{
		saltWord = ((uint32_t)salt[j]	   << 24) |
				   ((uint32_t)salt[j + 1]   << 16) |
				   ((uint32_t)salt[j + 2]   <<  8) |
				   (uint32_t) salt[j + 3];
		ctx->P[i] ^= saltWord;
		j = (j + 4) % 16;
	}

	/* Re-encrypt zero block (no data injection) — update P then S-boxes */
	for (i = 0; i < 18; i += 2)
	{
		blowfishEncryptBlock(ctx->P, ctx->S, block, out);
		ctx->P[i]	 = ((uint32_t)out[0] << 24) | ((uint32_t)out[1] << 16) |
						((uint32_t)out[2] <<  8) |  (uint32_t)out[3];
		ctx->P[i + 1] = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
						((uint32_t)out[6] <<  8) |  (uint32_t)out[7];
		ft_memcpy(block, out, 8);
	}
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 256; j += 2)
		{
			blowfishEncryptBlock(ctx->P, ctx->S, block, out);
			ctx->S[i][j]	 = ((uint32_t)out[0] << 24) | ((uint32_t)out[1] << 16) |
							   ((uint32_t)out[2] <<  8) |  (uint32_t)out[3];
			ctx->S[i][j + 1] = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
							   ((uint32_t)out[6] <<  8) |  (uint32_t)out[7];
			ft_memcpy(block, out, 8);
		}
	}
}

/*
 * expandstate(salt, key) — ExpandKey(state, salt, key)   [the INITIAL call]
 *
 * This is different from expand0state: before each Blowfish encryption the
 * next 8 bytes of salt (cycling through 16 bytes) are XORed into the running
 * plaintext block, producing a data-dependent ciphertext stream.
 *
 * Reference: Provos & Mazières, "A Future-Adaptable Password Scheme", 1999.
 */
static void blowfishExpandStateWithData(t_blowfishEcbCtx	*ctx,
										const uint8_t		*key,
										size_t				keyLen,
										const uint8_t		salt[16])
{
	uint32_t	i;
	uint32_t	j;
	uint32_t	data;
	uint32_t	saltOff;
	uint8_t		block[8] = {0};
	uint8_t		out[8];

	/* Step 1: XOR key into P-array (same as expand0state) */
	j = 0;
	for (i = 0; i < 18; i++)
	{
		data = ((uint32_t)key[j % keyLen]	   << 24) |
			   ((uint32_t)key[(j + 1) % keyLen] << 16) |
			   ((uint32_t)key[(j + 2) % keyLen] <<  8) |
			   (uint32_t) key[(j + 3) % keyLen];
		ctx->P[i] ^= data;
		j = (j + 4) % keyLen;
	}

	/*
	 * Step 2: Re-encrypt P-array.
	 * Before each call to blowfishEncryptBlock, XOR the next 8 bytes of salt
	 * (4 bytes into L, 4 bytes into R) into the running block.  The salt
	 * cycles every 16 bytes (it is exactly 16 bytes long).
	 */
	saltOff = 0;
	for (i = 0; i < 18; i += 2)
	{
		/* XOR next 4 bytes of salt into L */
		block[0] ^= salt[saltOff];
		block[1] ^= salt[(saltOff + 1) % 16];
		block[2] ^= salt[(saltOff + 2) % 16];
		block[3] ^= salt[(saltOff + 3) % 16];
		saltOff   = (saltOff + 4) % 16;

		/* XOR next 4 bytes of salt into R */
		block[4] ^= salt[saltOff];
		block[5] ^= salt[(saltOff + 1) % 16];
		block[6] ^= salt[(saltOff + 2) % 16];
		block[7] ^= salt[(saltOff + 3) % 16];
		saltOff   = (saltOff + 4) % 16;

		blowfishEncryptBlock(ctx->P, ctx->S, block, out);
		ctx->P[i]	 = ((uint32_t)out[0] << 24) | ((uint32_t)out[1] << 16) |
						((uint32_t)out[2] <<  8) |  (uint32_t)out[3];
		ctx->P[i + 1] = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
						((uint32_t)out[6] <<  8) |  (uint32_t)out[7];
		ft_memcpy(block, out, 8);
	}

	/* Step 3: Update S-boxes the same way (salt injection continues) */
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 256; j += 2)
		{
			block[0] ^= salt[saltOff];
			block[1] ^= salt[(saltOff + 1) % 16];
			block[2] ^= salt[(saltOff + 2) % 16];
			block[3] ^= salt[(saltOff + 3) % 16];
			saltOff   = (saltOff + 4) % 16;

			block[4] ^= salt[saltOff];
			block[5] ^= salt[(saltOff + 1) % 16];
			block[6] ^= salt[(saltOff + 2) % 16];
			block[7] ^= salt[(saltOff + 3) % 16];
			saltOff   = (saltOff + 4) % 16;

			blowfishEncryptBlock(ctx->P, ctx->S, block, out);
			ctx->S[i][j]	 = ((uint32_t)out[0] << 24) | ((uint32_t)out[1] << 16) |
							   ((uint32_t)out[2] <<  8) |  (uint32_t)out[3];
			ctx->S[i][j + 1] = ((uint32_t)out[4] << 24) | ((uint32_t)out[5] << 16) |
							   ((uint32_t)out[6] <<  8) |  (uint32_t)out[7];
			ft_memcpy(block, out, 8);
		}
	}
}

/* ----------------------------------------------------------------------------
 * EksBlowfishSetup — the bcrypt key schedule
 *
 * Correct algorithm (Provos & Mazières 1999):
 *
 *   state  = InitState()
 *   state  = ExpandKey(state, salt, key) <- salt injected in ctext
 *   repeat 2^cost:
 *	 state = ExpandKey(state, 0, key)	<- no data injection, key first
 *	 state = ExpandKey(state, 0, salt)	<- no data injection, salt second
 * ---------------------------------------------------------------------------- */

static void eksBlowfishSetup(t_bcryptCtx	*ctx,
							 const uint8_t	*key,
							 size_t			keyLen,
							 const uint8_t	*salt,
							 uint32_t		cost)
{
	uint32_t	rounds;
	uint32_t	i;

	/* 1. InitState: load standard Pi constants (no key schedule yet) */
	blowfishInitState(ctx->blowfishCtx.P, ctx->blowfishCtx.S);

	/* 2. Initial ExpandKey with salt injected into ciphertext stream */
	blowfishExpandStateWithData(&ctx->blowfishCtx, key, keyLen, salt);

	/* 3. Expensive loop: expand0state(key) then expand0state(salt) */
	rounds = 1U << cost;
	for (i = 0; i < rounds; i++)
	{
		blowfishExpand0StateKey(&ctx->blowfishCtx, key, keyLen);
		blowfishExpand0StateSalt(&ctx->blowfishCtx, salt);
	}
}

static void bcryptEncryptMagic(const t_bcryptCtx *ctx, uint8_t output[24])
{
	uint8_t		data[24];
	uint32_t	i;
	uint32_t	j;

	ft_memcpy(data, BCRYPT_MAGIC_STR, 24);

	/* 64 ECB rounds — each 8-byte block encrypted independently each round */
	for (i = 0; i < 64; i++)
	{
		for (j = 0; j < 24; j += 8)
			blowfishEncryptBlock(ctx->blowfishCtx.P, ctx->blowfishCtx.S,
								 &data[j], &data[j]);
	}

	ft_memcpy(output, data, 24);
}


/* -------------- bcrypt API functions -------------- */


int bcryptHash(const char		*password,
			   const uint8_t	*salt,
			   uint32_t			cost,
			   char				*output)
{
	t_bcryptCtx	ctx;
	uint8_t		hash[24];
	uint8_t		key[BCRYPT_MAX_PASSWD];
	size_t		keyLen;
	char		*saltEnc;
	char		*hashEnc;
	uint32_t	i;

	if (!password || !salt || !output)
		return (-1);
	if (cost < BCRYPT_COST_MIN || cost > BCRYPT_COST_MAX)
		return (-1);

	keyLen = ft_strlen(password);
	if (keyLen >= BCRYPT_MAX_PASSWD)
		keyLen = BCRYPT_MAX_PASSWD;
	else
		keyLen += 1;	/* include '\0' */

	for (i = 0; i < keyLen; i++)
		key[i] = (uint8_t)password[i];

	ctx.cost = cost;
	ft_memcpy(ctx.salt, salt, 16);

	eksBlowfishSetup(&ctx, key, keyLen, salt, cost);
	bcryptEncryptMagic(&ctx, hash);

	/*
	 * Format: "$2b$XX$<22-char salt><31-char hash>"
	 * Total  : 7 + 22 + 31 = 60 chars + '\0' → 61 bytes
	 */
	output[0] = '$';  output[1] = '2';  output[2] = 'b';
	output[3] = '$';
	output[4] = '0' + (cost / 10);
	output[5] = '0' + (cost % 10);
	output[6] = '$';

	saltEnc = output + 7;
	hashEnc = saltEnc + 22;	 /* 16 raw bytes → 22 bcrypt-b64 chars */

	bcryptEncodeBase64(saltEnc, salt, 16);
	bcryptEncodeBase64(hashEnc, hash, 23);  /* standard bcrypt: only 23 bytes */

	return (0);
}

int bcryptVerify(const char *password, const char *hash)
{
	char		newHash[BCRYPT_STRING_LEN + 1];
	uint8_t		salt[16];
	uint32_t	cost;
	char		saltBuf[23];
	int			saltLen;
	uint32_t	i;
	int			diff;

	if (!password || !hash) return (-1);
	if (hash[0] != '$' || hash[1] != '2' || hash[2] != 'b' || hash[3] != '$')
		return (-1);
	if (hash[4] < '0' || hash[4] > '9' || hash[5] < '0' || hash[5] > '9')
		return (-1);
	if (hash[6] != '$')
		return (-1);

	cost = (uint32_t)(hash[4] - '0') * 10 + (uint32_t)(hash[5] - '0');

	for (i = 0; i < 22; i++)
		saltBuf[i] = hash[7 + i];
	saltBuf[22] = '\0';

	saltLen = bcryptDecodeBase64(salt, saltBuf, 16);
	if (saltLen != 16)
		return (-1);

	if (bcryptHash(password, salt, cost, newHash) != 0)
		return (-1);

	diff = 0;
	for (i = 0; i < 60; i++)
		diff |= (uint8_t)newHash[i] ^ (uint8_t)hash[i];

	return (diff == 0 ? 0 : -1);
}

int bcryptGenSalt(uint8_t salt[16])
{
	if (!salt)
		return (-1);
	return (hajSecRandBytes(salt, 16));
}

int bcryptSimple(const char *password, uint32_t cost, char output[BCRYPT_STRING_LEN])
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
					   uint32_t   cost,
					   char	   *output)
{
	uint8_t	salt[16];

	if (!password || !saltStr || !output)
		return (-1);
	if (bcryptDecodeBase64(salt, saltStr, 16) != 16)
		return (-1);
	return (bcryptHash(password, salt, cost, output));
}

int bcryptPbkdf(const char		*pass,	size_t	passLen,
				const uint8_t	*salt,	size_t	saltLen,
				uint8_t			*key,	size_t	keyLen,
				unsigned int	rounds)
{
	t_bcryptCtx	ctx;
	uint8_t		*output;
	uint8_t		count[4];
	uint8_t		*saltCpy;
	size_t		i;
	size_t		generated = 0;
	uint32_t	counter = 0;

	if (!pass || !salt || !key || keyLen == 0 || rounds == 0)
		return (-1);

	output  = malloc(BCRYPT_OUTPUT_SIZE);
	saltCpy = malloc(saltLen + 4);
	if (!output || !saltCpy)
	{
		free(output);
		free(saltCpy);
		return (-1);
	}

	ft_memcpy(saltCpy, salt, saltLen);

	while (generated < keyLen)
	{
		count[0] = (counter >> 24) & 0xFF;
		count[1] = (counter >> 16) & 0xFF;
		count[2] = (counter >>  8) & 0xFF;
		count[3] =  counter		& 0xFF;
		ft_memcpy(saltCpy + saltLen, count, 4);

		eksBlowfishSetup(&ctx, (const uint8_t *)pass, passLen, saltCpy, rounds);
		bcryptEncryptMagic(&ctx, output);

		if (counter > 0)
		{
			for (i = 0; i < BCRYPT_OUTPUT_SIZE; i++)
				output[i] ^= key[generated - BCRYPT_OUTPUT_SIZE + i];
		}

		for (i = 0; i < BCRYPT_OUTPUT_SIZE && generated < keyLen; i++)
			key[generated++] = output[i];

		counter++;
	}

	/* Clean sensitive data */
	secureZeroMemory(output, BCRYPT_OUTPUT_SIZE);
	secureZeroMemory(saltCpy, saltLen + 4);
	secureZeroMemory(&ctx, sizeof(ctx));

	free(output);
	free(saltCpy);
	return (0);
}
