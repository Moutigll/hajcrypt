#include "../../../hajlib/include/hmemory.h"

#include "../../../includes/cipher/modes.h"

static void processOneBlock(t_cbcGenCtx *ctx, uint8_t *block)
{
	uint8_t	tmp[64];
	
	if (ctx->dir == CIPHER_ENCRYPT)
	{
		for (size_t i = 0; i < ctx->blockSize; i++)
			block[i] ^= ctx->iv[i];
		
		ctx->processBlock(block, block, ctx->cipherCtx, 1);
		ft_memcpy(ctx->iv, block, ctx->blockSize);
	}
	else
	{
		ft_memcpy(tmp, block, ctx->blockSize);
		ctx->processBlock(block, block, ctx->cipherCtx, 0);
		
		for (size_t i = 0; i < ctx->blockSize; i++)
			block[i] ^= ctx->iv[i];
		
		ft_memcpy(ctx->iv, tmp, ctx->blockSize);
	}
}

void cbcGenUpdate(t_cbcGenCtx	*ctx,
				  const uint8_t	*in,
				  size_t		inLen,
				  uint8_t		*out,
				  size_t		*outLen)
{
	uint8_t	*outStart = out;
	size_t	blockSize = ctx->blockSize;

	*outLen = 0;

	/* Partial block from previous update */
	if (ctx->bufferLen > 0)
	{
		size_t need = blockSize - ctx->bufferLen;

		if (inLen < need)
		{
			ft_memcpy(ctx->buffer + ctx->bufferLen, in, inLen);
			ctx->bufferLen += inLen;
			return;
		}

		ft_memcpy(ctx->buffer + ctx->bufferLen, in, need);
		processOneBlock(ctx, ctx->buffer);
		ft_memcpy(out, ctx->buffer, blockSize);

		out += blockSize;
		in += need;
		inLen -= need;
		ctx->bufferLen = 0;
	}

	/* Process full blocks */
	if (inLen >= blockSize)
	{
		size_t blocks = inLen / blockSize;

		if (ctx->dir == CIPHER_ENCRYPT)
		{
			for (size_t i = 0; i < blocks; i++)
			{
				ft_memcpy(out, in, blockSize);
				processOneBlock(ctx, out);
				out += blockSize;
				in += blockSize;
			}
			inLen -= blocks * blockSize;
		}
		else
		{
			for (size_t i = 0; i < blocks; i++)
			{
				ft_memcpy(out, in, blockSize);
				processOneBlock(ctx, out);
				out += blockSize;
				in += blockSize;
			}
			inLen -= blocks * blockSize;
		}
	}

	/* Store remaining partial block */
	if (inLen > 0)
	{
		ft_memcpy(ctx->buffer, in, inLen);
		ctx->bufferLen = inLen;
	}

	*outLen = out - outStart;
}


void cbcGenFinal(t_cbcGenCtx *ctx, uint8_t *out, size_t *outLen)
{
	uint8_t	block[64];
	size_t	unpaddedLen;
	
	*outLen = 0;
	
	if (ctx->dir == CIPHER_ENCRYPT)
	{
		ft_memcpy(block, ctx->buffer, ctx->bufferLen);
		pkcs7Pad(block, ctx->bufferLen, ctx->blockSize);
		processOneBlock(ctx, block);
		ft_memcpy(out, block, ctx->blockSize);
		*outLen = ctx->blockSize;
	}
	else
	{
		if (ctx->bufferLen != ctx->blockSize)
			return;
		
		ft_memcpy(block, ctx->buffer, ctx->blockSize);
		processOneBlock(ctx, block);
		
		if (pkcs7Unpad(block, &unpaddedLen, ctx->blockSize) != 0)
			return;
		
		ft_memcpy(out, block, unpaddedLen);
		*outLen = unpaddedLen;
	}
}
