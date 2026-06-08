#include "../../hajlib/include/hmemory.h"

#include "../../includes/hash/hmac.h"

void	hmacInit(t_hmacCtx	*ctx,
			  const t_hash	*algo,
			  const uint8_t	*key,
			  size_t		keyLen)
{
	uint8_t	k0[algo->blockSize];
	size_t	i;

	ctx->algo = algo;

	ft_bzero(k0, algo->blockSize);

	if (keyLen > algo->blockSize)
	{
		algo->init(ctx->innerCtx);
		algo->update(ctx->innerCtx, key, keyLen);
		algo->final(k0, ctx->innerCtx);
	}
	else
		ft_memcpy(k0, key, keyLen);

	/* Prepare inner context */
	i = 0;
	while (i < algo->blockSize)
	{
		k0[i] ^= 0x36;
		i++;
	}

	algo->init(ctx->innerCtx);
	algo->update(ctx->innerCtx, k0, algo->blockSize);

	/* Prepare outer context */
	i = 0;
	while (i < algo->blockSize)
	{
		k0[i] ^= 0x36 ^ 0x5c;
		i++;
	}

	algo->init(ctx->outerCtx);
	algo->update(ctx->outerCtx, k0, algo->blockSize);
}

void	hmacFinal(t_hmacCtx *ctx, uint8_t *digest)
{
	uint8_t tmp[ctx->algo->digestSize];

	ctx->algo->final(tmp, ctx->innerCtx);
	ctx->algo->update(ctx->outerCtx, tmp, ctx->algo->digestSize);
	ctx->algo->final(digest, ctx->outerCtx);
}

void	hmac(const t_hash	*algo,
			 const uint8_t		*key,	size_t	keyLen,
			 const uint8_t		*data,	size_t	dataLen,
			 uint8_t			*out)
{
	t_hmacCtx	ctx;

	hmacInit(&ctx, algo, key, keyLen);
	ctx.algo->update(ctx.innerCtx, data, dataLen);
	hmacFinal(&ctx, out);
}


/* ------------------------ per-algorithm wrappers ------------------------ */

void	sha1HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen)
{
	hmacInit(ctx, &g_sha1Hash, key, keyLen);
}

void	sha224HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen)
{
	hmacInit(ctx, &g_sha224Hash, key, keyLen);
}

void	sha256HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen)
{
	hmacInit(ctx, &g_sha256Hash, key, keyLen);
}

void	sha384HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen)
{
	hmacInit(ctx, &g_sha384Hash, key, keyLen);
}

void	sha512HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen)
{
	hmacInit(ctx, &g_sha512Hash, key, keyLen);
}

void	sha512_224HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen)
{
	hmacInit(ctx, &g_sha512_224Hash, key, keyLen);
}

void	sha512_256HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen)
{
	hmacInit(ctx, &g_sha512_256Hash, key, keyLen);
}

void	md5HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen)
{
	hmacInit(ctx, &g_md5Hash, key, keyLen);
}

void	whirlpoolHmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen)
{
	hmacInit(ctx, &g_whirlpoolHash, key, keyLen);
}
