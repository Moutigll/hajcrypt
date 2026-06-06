#include <stdlib.h>

#include "../../hajlib/include/hmemory.h"

#include "../../includes/hash/md5.h"
#include "../../includes/hash/sha.h" /* IWYU pragma: keep */
#include "../../includes/hash/whirlpool.h"
#include "../../includes/utils/utils.h"

#include "../../includes/hash/hmac.h"

void	hmacInit(t_hmacCtx		*ctx,
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

	/* inner key: k0 XOR 0x36 */
	i = 0;
	while (i < algo->blockSize)
	{
		k0[i] ^= 0x36;
		i++;
	}

	algo->hashInit(ctx->innerCtx);
	algo->hashUpdate(ctx->innerCtx, k0, algo->blockSize);

	/* outer key: k0 XOR 0x5c (undo 0x36, then XOR 0x5c) */
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
	uint8_t	tmp[ctx->algo->digestSize];

	ctx->algo->hashFinal(tmp, ctx->innerCtx);
	ctx->algo->hashUpdate(ctx->outerCtx, tmp, ctx->algo->digestSize);
	ctx->algo->hashFinal(digest, ctx->outerCtx);
}

void	hmac(const t_hashAlgo	*algo,
			 const uint8_t		*key,	size_t	keyLen,
			 const uint8_t		*data,	size_t	dataLen,
			 uint8_t			*out)
{
	t_hmacCtx	ctx;

	hmacInit(&ctx, algo, key, keyLen);
	ctx.algo->hashUpdate(ctx.innerCtx, data, dataLen);
	hmacFinal(&ctx, out);
}


/* ------------------------ hash algorithm descriptors ------------------------ */

const t_hashAlgo	g_sha1Algo = {
	.hashInit = sha1Init,
	.hashUpdate = sha1Update,
	.hashFinal = sha1Final,
	.blockSize = 64,
	.digestSize = 20,
	.ctxSize = sizeof(t_sha1Ctx)
};

const t_hashAlgo	g_sha224Algo = {
	.hashInit = sha224Init,
	.hashUpdate = sha224Update,
	.hashFinal = sha224Final,
	.blockSize = 64,
	.digestSize = 28,
	.ctxSize = sizeof(t_sha224Ctx)
};

const t_hashAlgo	g_sha256Algo = {
	.hashInit = sha256Init,
	.hashUpdate = sha256Update,
	.hashFinal = sha256Final,
	.blockSize = 64,
	.digestSize = 32,
	.ctxSize = sizeof(t_sha256Ctx)
};

const t_hashAlgo	g_sha384Algo = {
	.hashInit = sha384Init,
	.hashUpdate = sha384Update,
	.hashFinal = sha384Final,
	.blockSize = 128,
	.digestSize = 48,
	.ctxSize = sizeof(t_sha384Ctx)
};

const t_hashAlgo	g_sha512Algo = {
	.hashInit = sha512Init,
	.hashUpdate = sha512Update,
	.hashFinal = sha512Final,
	.blockSize = 64,
	.digestSize = 64,
	.ctxSize = sizeof(t_sha512Ctx)
};

const t_hashAlgo	g_sha512_224Algo = {
	.hashInit = sha512_224Init,
	.hashUpdate = sha512_224Update,
	.hashFinal = sha512_224Final,
	.blockSize = 128,
	.digestSize = 28,
	.ctxSize = sizeof(t_sha512_224Ctx)
};

const t_hashAlgo	g_sha512_256Algo = {
	.hashInit = sha512_256Init,
	.hashUpdate = sha512_256Update,
	.hashFinal = sha512_256Final,
	.blockSize = 128,
	.digestSize = 32,
	.ctxSize = sizeof(t_sha512_256Ctx)
};

const t_hashAlgo	g_md5Algo = {
	.hashInit = md5Init,
	.hashUpdate = md5Update,
	.hashFinal = md5Final,
	.blockSize = 64,
	.digestSize = 16,
	.ctxSize = sizeof(t_md5Ctx)
};

const t_hashAlgo	g_whirlpoolAlgo = {
	.hashInit = whirlpoolInit,
	.hashUpdate = whirlpoolUpdate,
	.hashFinal = whirlpoolFinal,
	.blockSize = 64,
	.digestSize = 64,
	.ctxSize = sizeof(t_whirlpoolCtx)
};


/* ------------------------ per-algorithm wrappers ------------------------ */

void	sha1HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen)
{
	hmacInit(ctx, &g_sha1Algo, key, keyLen);
}

void	sha224HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen)
{
	hmacInit(ctx, &g_sha224Algo, key, keyLen);
}

void	sha256HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen)
{
	hmacInit(ctx, &g_sha256Algo, key, keyLen);
}

void	sha384HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen)
{
	hmacInit(ctx, &g_sha384Algo, key, keyLen);
}

void	sha512HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen)
{
	hmacInit(ctx, &g_sha512Algo, key, keyLen);
}

void	sha512_224HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen)
{
	hmacInit(ctx, &g_sha512_224Algo, key, keyLen);
}

void	sha512_256HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen)
{
	hmacInit(ctx, &g_sha512_256Algo, key, keyLen);
}

void	md5HmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen)
{
	hmacInit(ctx, &g_md5Algo, key, keyLen);
}

void	whirlpoolHmacInit(t_hmacCtx *ctx, const uint8_t *key, size_t keyLen)
{
	hmacInit(ctx, &g_whirlpoolAlgo, key, keyLen);
}



/* ------------------------- HMAC_DRBG implementation ------------------------ */



static void hmacDrbgHmac(t_hmacDrbg *drbg, const uint8_t *key, const uint8_t *input, size_t inputLen, uint8_t *output)
{
	t_hmacCtx hmacCtx;

	hmacInit(&hmacCtx, drbg->hash, key, drbg->hashLen);
	hmacCtx.algo->hashUpdate(hmacCtx.innerCtx, input, inputLen);
	hmacFinal(&hmacCtx, output);
}

void hmacDrbgUpdate(t_hmacDrbg *drbg, const uint8_t *data, size_t dataLen)
{
	uint8_t		*input;
	size_t		inputLen;
	t_hmacCtx	hmacCtx;

	/* K = HMAC(K, V || 0x00 || data) */
	inputLen = drbg->hashLen + 1 + dataLen;
	input = malloc(inputLen);
	if (!input)
		return;

	ft_memcpy(input, drbg->V, drbg->hashLen);
	input[drbg->hashLen] = 0x00;
	if (data && dataLen)
		ft_memcpy(input + drbg->hashLen + 1, data, dataLen);

	hmacInit(&hmacCtx, drbg->hash, drbg->K, drbg->hashLen);
	hmacCtx.algo->hashUpdate(hmacCtx.innerCtx, input, inputLen);
	hmacFinal(&hmacCtx, drbg->K);

	/* V = HMAC(K, V) */
	hmacInit(&hmacCtx, drbg->hash, drbg->K, drbg->hashLen);
	hmacCtx.algo->hashUpdate(hmacCtx.innerCtx, drbg->V, drbg->hashLen);
	hmacFinal(&hmacCtx, drbg->V);

	/* If data is provided, repeat with 0x01 */
	if (data && dataLen) {
		input[drbg->hashLen] = 0x01;
		/* input already contains V || 0x01 || data, reuse it */

		hmacInit(&hmacCtx, drbg->hash, drbg->K, drbg->hashLen);
		hmacCtx.algo->hashUpdate(hmacCtx.innerCtx, input, inputLen);
		hmacFinal(&hmacCtx, drbg->K);

		hmacInit(&hmacCtx, drbg->hash, drbg->K, drbg->hashLen);
		hmacCtx.algo->hashUpdate(hmacCtx.innerCtx, drbg->V, drbg->hashLen);
		hmacFinal(&hmacCtx, drbg->V);
	}

	secureZeroMemory(input, inputLen);
	free(input);
}

void hmacDrbgReseed(t_hmacDrbg		*drbg,
					const uint8_t	*entropy,		size_t	entropyLen,
					const uint8_t	*additional,	size_t	additionalLen)
{
	uint8_t	*seed;
	size_t	seedLen;

	seedLen = entropyLen + additionalLen;
	seed = malloc(seedLen);
	if (!seed)
		return;

	ft_memcpy(seed, entropy, entropyLen);
	if (additional && additionalLen)
		ft_memcpy(seed + entropyLen, additional, additionalLen);

	hmacDrbgUpdate(drbg, seed, seedLen);
	drbg->reseedCounter = 1;

	secureZeroMemory(seed, seedLen);
	free(seed);
}

int hmacDrbgGenerate(t_hmacDrbg *drbg, uint8_t *out, size_t outLen)
{
	size_t	generated;
	size_t	toCopy;
	t_hmacCtx	hmacCtx;

	if (outLen > HMAC_DRBG_MAX_REQUEST)
		return (0);

	if (drbg->reseedCounter >= HMAC_DRBG_RESEED_INTERVAL)
		return (0);

	generated = 0;
	while (generated < outLen) {
		/* V = HMAC(K, V) */
		hmacInit(&hmacCtx, drbg->hash, drbg->K, drbg->hashLen);
		hmacCtx.algo->hashUpdate(hmacCtx.innerCtx, drbg->V, drbg->hashLen);
		hmacFinal(&hmacCtx, drbg->V);

		toCopy = outLen - generated;
		if (toCopy > drbg->hashLen)
			toCopy = drbg->hashLen;
		ft_memcpy(out + generated, drbg->V, toCopy);
		generated += toCopy;
	}

	hmacDrbgUpdate(drbg, NULL, 0);
	drbg->reseedCounter++;

	return (1);
}

int	hmacDrbgInit(t_hmacDrbg		*drbg,		const t_hashAlgo	*hash,
				 const uint8_t	*entropy,	size_t				entropyLen,
				 const uint8_t	*nonce,		size_t				nonceLen,
				 const uint8_t	*personal,	size_t				personalLen)
{
	uint8_t	*seed;
	size_t	seedLen;

	if (!drbg || !hash || !entropy || entropyLen == 0)
		return (0);

	ft_bzero(drbg, sizeof(t_hmacDrbg));
	drbg->hash = hash;
	drbg->hashLen = hash->digestSize;

	/* V = 0x01... (hashLen bytes) */
	ft_memset(drbg->V, 0x01, drbg->hashLen);

	seedLen = entropyLen + nonceLen + personalLen;
	seed = malloc(seedLen);
	if (!seed)
		return (0);

	ft_memcpy(seed, entropy, entropyLen);
	if (nonce && nonceLen)
		ft_memcpy(seed + entropyLen, nonce, nonceLen);
	if (personal && personalLen)
		ft_memcpy(seed + entropyLen + nonceLen, personal, personalLen);

	hmacDrbgUpdate(drbg, seed, seedLen);
	drbg->reseedCounter = 1;

	secureZeroMemory(seed, seedLen);
	free(seed);

	return (1);
}
