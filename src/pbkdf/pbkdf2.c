#include <stdlib.h>

#include "../../hajlib/include/hmemory.h"
#include "../../includes/pbkdf/pbkdf2.h"

#define PBKDF2_MAX_DIGEST 64

int	pbkdf2Init(t_pbkdf2Ctx		*ctx,
			  const t_hash		*hash,
			  const uint8_t		*pass,
			  size_t			passLen,
			  const uint8_t		*salt,
			  size_t			saltLen,
			  uint32_t			iter)
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

static int	pbkdf2F(const t_pbkdf2Ctx	*ctx,
				   uint32_t				blockIdx,
				   uint8_t				*out)
{
	t_hmacCtx	hmac;
	uint8_t		block[72];
	uint8_t		u[PBKDF2_MAX_DIGEST];
	uint32_t	i;
	size_t		j;
	size_t		blockLen;

	blockLen = ctx->saltLen + 4;
	ft_memcpy(block, ctx->salt, ctx->saltLen);
	block[ctx->saltLen] = (blockIdx >> 24) & 0xFF;
	block[ctx->saltLen + 1] = (blockIdx >> 16) & 0xFF;
	block[ctx->saltLen + 2] = (blockIdx >> 8) & 0xFF;
	block[ctx->saltLen + 3] = blockIdx & 0xFF;
	
	ctx->hash->hmacInit(&hmac, ctx->pass, ctx->passLen);
	ctx->hash->update(hmac.innerCtx, block, blockLen);
	ctx->hash->final(u, hmac.innerCtx);
	
	ft_memcpy(out, u, ctx->hash->digestSize);
	i = 1;
	while (i < ctx->iter)
	{
		ctx->hash->hmacInit(&hmac, ctx->pass, ctx->passLen);
		ctx->hash->update(hmac.innerCtx, u, ctx->hash->digestSize);
		ctx->hash->final(u, hmac.innerCtx);
		
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

int	pbkdf2Derive(const t_pbkdf2Ctx	*ctx,
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

int	pbkdf2DeriveKeyIv(const t_pbkdf2Ctx	*ctx,
					  uint8_t			*key,
					  uint8_t			*iv,
					  size_t			keyLen,
					  size_t			ivLen)
{
	uint8_t	*derived;
	size_t	total;

	if (!ctx || !key || !iv)
		return (-1);
	
	total = keyLen + ivLen;
	derived = malloc(total);
	if (!derived)
		return (-1);
	
	if (pbkdf2Derive(ctx, derived, total) != 0)
	{
		free(derived);
		return (-1);
	}
	
	ft_memcpy(key, derived, keyLen);
	ft_memcpy(iv, derived + keyLen, ivLen);
	free(derived);
	return (0);
}
