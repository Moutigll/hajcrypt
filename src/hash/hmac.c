#include "../../hajlib/include/hmemory.h"

#include "../../includes/hash/md5.h"
#include "../../includes/hash/sha256.h"
#include "../../includes/hash/whirlpool.h"

#include "../../includes/hash/hmac.h"

void	hmacInit(t_hmacCtx			*ctx,
			  const t_hashAlgo	*algo,
			  const uint8_t		*key,
			  size_t			keyLen)
{
	uint8_t	k0[algo->blockSize];
	size_t	i;

	ctx->algo = algo;

	ft_bzero(k0, algo->blockSize);

	if (keyLen > algo->blockSize)
	{
		algo->hashInit(ctx->innerCtx);
		algo->hashUpdate(ctx->innerCtx, key, keyLen);
		algo->hashFinal(k0, ctx->innerCtx);
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

	algo->hashInit(ctx->innerCtx);
	algo->hashUpdate(ctx->innerCtx, k0, algo->blockSize);

	/* Prepare outer context */
	i = 0;
	while (i < algo->blockSize)
	{
		k0[i] ^= 0x36 ^ 0x5c;
		i++;
	}

	algo->hashInit(ctx->outerCtx);
	algo->hashUpdate(ctx->outerCtx, k0, algo->blockSize);
}

void	hmacFinal(t_hmacCtx *ctx, uint8_t *digest)
{
	uint8_t tmp[ctx->algo->digestSize];

	ctx->algo->hashFinal(tmp, ctx->innerCtx);

	ctx->algo->hashUpdate(ctx->outerCtx, tmp,
						  ctx->algo->digestSize);

	ctx->algo->hashFinal(digest, ctx->outerCtx);
}

static const t_hashAlgo	g_sha256Algo = {
	.hashInit = sha256Init,
	.hashUpdate = sha256Update,
	.hashFinal = sha256Final,
	.blockSize = 64,
	.digestSize = 32,
	.ctxSize = sizeof(t_sha256Ctx)
};

static const t_hashAlgo	g_md5Algo = {
	.hashInit = md5Init,
	.hashUpdate = md5Update,
	.hashFinal = md5Final,
	.blockSize = 64,
	.digestSize = 16,
	.ctxSize = sizeof(t_md5Ctx)
};

static const t_hashAlgo	g_whirlpoolAlgo = {
	.hashInit = whirlpoolInit,
	.hashUpdate = whirlpoolUpdate,
	.hashFinal = whirlpoolFinal,
	.blockSize = 64,
	.digestSize = 64,
	.ctxSize = sizeof(t_whirlpoolCtx)
};


/* ------------------------ public API ------------------------ */

void	sha256HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen)
{
	hmacInit(ctx, &g_sha256Algo, key, keyLen);
}

void	md5HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen)
{
	hmacInit(ctx, &g_md5Algo, key, keyLen);
}

void	whirlpoolHmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen)
{
	hmacInit(ctx, &g_whirlpoolAlgo, key, keyLen);
}
