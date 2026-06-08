#include <stdlib.h>

#include "../../hajlib/include/hmemory.h"

#include "../../includes/utils/utils.h"

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

	/* inner key: k0 XOR 0x36 */
	i = 0;
	while (i < algo->blockSize)
	{
		k0[i] ^= 0x36;
		i++;
	}

	algo->init(ctx->innerCtx);
	algo->update(ctx->innerCtx, k0, algo->blockSize);

	/* outer key: k0 XOR 0x5c (undo 0x36, then XOR 0x5c) */
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
	uint8_t	tmp[ctx->algo->digestSize];

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



/* ------------------------- HMAC_DRBG implementation ------------------------ */



static void hmacDrbgHmac(t_hmacDrbg *drbg, const uint8_t *key, const uint8_t *input, size_t inputLen, uint8_t *output)
{
	t_hmacCtx hmacCtx;

	hmacInit(&hmacCtx, drbg->hash, key, drbg->hashLen);
	hmacCtx.algo->update(hmacCtx.innerCtx, input, inputLen);
	hmacFinal(&hmacCtx, output);
}

void hmacDrbgUpdate(t_hmacDrbg *drbg, const uint8_t *data, size_t dataLen)
{
	uint8_t		*input;
	size_t		inputLen;

	/* K = HMAC(K, V || 0x00 || data) */
	inputLen = drbg->hashLen + 1 + dataLen;
	input = malloc(inputLen);
	if (!input)
		return;

	ft_memcpy(input, drbg->V, drbg->hashLen);
	input[drbg->hashLen] = 0x00;
	if (data && dataLen)
		ft_memcpy(input + drbg->hashLen + 1, data, dataLen);

	hmacDrbgHmac(drbg, drbg->K, input, inputLen, drbg->K);

	/* V = HMAC(K, V) */
	hmacDrbgHmac(drbg, drbg->K, drbg->V, drbg->hashLen, drbg->V);

	/* If data is provided, repeat with 0x01 */
	if (data && dataLen) {
		ft_memcpy(input, drbg->V, drbg->hashLen);
		input[drbg->hashLen] = 0x01;
		hmacDrbgHmac(drbg, drbg->K, input, inputLen, drbg->K);
		hmacDrbgHmac(drbg, drbg->K, drbg->V, drbg->hashLen, drbg->V);
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
		hmacCtx.algo->update(hmacCtx.innerCtx, drbg->V, drbg->hashLen);
		hmacCtx.algo->final(drbg->V, hmacCtx.outerCtx);

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

int	hmacDrbgInit(t_hmacDrbg		*drbg,		const t_hash	*hash,
				 const uint8_t	*entropy,	size_t			entropyLen,
				 const uint8_t	*nonce,		size_t			nonceLen,
				 const uint8_t	*personal,	size_t			personalLen)
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
