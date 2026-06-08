#include <stdlib.h>

#include "../../hajlib/include/hmemory.h"
#include "../../includes/kdf/pbkdf2.h"
#include "../../includes/hash/hmac.h"

#define PBKDF2_MAX_DIGEST 64

int pbkdf2Init(t_pbkdf2Ctx	*ctx,
			  const t_hash	*hash,
			  const uint8_t	*pass,
			  size_t		passLen,
			  const uint8_t	*salt,
			  size_t		saltLen,
			  uint32_t		iter)
{
	if (!ctx || !hash || !pass || !salt)
		return (-1);
	if (iter == 0 || passLen == 0 || saltLen == 0)
		return (-1);
	
	ctx->hash = hash;
	ctx->pass = pass;
	ctx->passLen = passLen;
	ctx->salt = salt;
	ctx->saltLen = saltLen;
	ctx->iter = iter;
	return (0);
}

static int  pbkdf2F(const t_pbkdf2Ctx	*ctx,
				   uint32_t				blockIdx,
				   uint8_t				*out)
{
	t_hmacCtx	hmac;
	uint8_t		u[PBKDF2_MAX_DIGEST];
	uint8_t		inner_hash[PBKDF2_MAX_DIGEST];
	uint8_t		idxBuf[4];
	uint32_t	i;
	size_t		j;

	idxBuf[0] = (blockIdx >> 24) & 0xFF;
	idxBuf[1] = (blockIdx >> 16) & 0xFF;
	idxBuf[2] = (blockIdx >> 8) & 0xFF;
	idxBuf[3] = blockIdx & 0xFF;
	
	/* --- U_1 = HMAC(Pass, Salt || INT(blockIdx)) --- */
	ctx->hash->hmacInit(&hmac, ctx->pass, ctx->passLen);
	
	/* 1. Inner hash */
	ctx->hash->update(hmac.innerCtx, ctx->salt, ctx->saltLen);
	ctx->hash->update(hmac.innerCtx, idxBuf, 4);
	ctx->hash->final(inner_hash, hmac.innerCtx);
	
	/* 2. Outer hash */
	ctx->hash->update(hmac.outerCtx, inner_hash, ctx->hash->digestSize);
	ctx->hash->final(u, hmac.outerCtx);
	
	ft_memcpy(out, u, ctx->hash->digestSize);
	
	/* --- U_2 to U_c = HMAC(Pass, U_{i-1}) --- */
	i = 1;
	while (i < ctx->iter)
	{
		ctx->hash->hmacInit(&hmac, ctx->pass, ctx->passLen);
		
		/* 1. Inner hash */
		ctx->hash->update(hmac.innerCtx, u, ctx->hash->digestSize);
		ctx->hash->final(inner_hash, hmac.innerCtx);
		
		/* 2. Outer hash */
		ctx->hash->update(hmac.outerCtx, inner_hash, ctx->hash->digestSize);
		ctx->hash->final(u, hmac.outerCtx);
		
		/* XOR with previous U */
		j = 0;
		while (j < ctx->hash->digestSize)
		{
			out[j] ^= u[j];
			j++;
		}
		i++;
	}
	return (0);
}

int pbkdf2Derive(const t_pbkdf2Ctx	*ctx,
				 uint8_t			*out,
				 size_t				outLen)
{
	uint32_t	blocks;
	uint32_t	i;
	size_t		digest;
	size_t		offset;
	uint8_t		tmp[PBKDF2_MAX_DIGEST];

	if (!ctx || !out)
		return (-1);
	if (outLen == 0)
		return (0);
	
	digest = ctx->hash->digestSize;
	blocks = (outLen + digest - 1) / digest;
	offset = 0;
	i = 1;
	
	while (i <= blocks)
	{
		if (pbkdf2F(ctx, i, tmp) != 0)
			return (-1);
		
		if (offset + digest > outLen)
			ft_memcpy(out + offset, tmp, outLen - offset);
		else
			ft_memcpy(out + offset, tmp, digest);
		
		offset += digest;
		i++;
	}
	return (0);
}

int pbkdf2DeriveKeyIv(const t_pbkdf2Ctx	*ctx,
					  uint8_t			*key,
					  uint8_t			*iv,
					  size_t			keyLen,
					  size_t			ivLen)
{
	uint8_t	*derived;
	size_t	total;

	if (!ctx)
		return (-1);
	
	total = keyLen + ivLen;
	if (total == 0)
		return (0);
		
	derived = malloc(total);
	if (!derived)
		return (-1);
	
	if (pbkdf2Derive(ctx, derived, total) != 0)
	{
		free(derived);
		return (-1);
	}
	
	if (key && keyLen > 0)
		ft_memcpy(key, derived, keyLen);
	if (iv && ivLen > 0)
		ft_memcpy(iv, derived + keyLen, ivLen);
		
	free(derived);
	return (0);
}
