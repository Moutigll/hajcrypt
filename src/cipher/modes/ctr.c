#include "../../../includes/cipher/modes.h"

static void	ctrNextBlock(t_ctrGenCtx *ctx)
{
	size_t	i = ctx->blockSize;

	ctx->processBlock(ctx->counter, ctx->keystream, ctx->cipherCtx);
	ctx->keystreamOff = 0;

	while (i--)
	{
		if (++ctx->counter[i] != 0)
			break ;
	}
}

void	ctrGenUpdate(t_ctrGenCtx	*ctx,
					 const uint8_t	*in,
					 size_t			inLen,
					 uint8_t		*out,
					 size_t			*outLen)
{
	*outLen = 0;

	/* Consume remaining bytes from the current keystream block first */
	while (inLen > 0 && ctx->keystreamOff < ctx->blockSize)
	{
		*out++ = *in++ ^ ctx->keystream[ctx->keystreamOff++];
		inLen--;
		(*outLen)++;
	}

	/* Process full blocks */
	while (inLen >= ctx->blockSize)
	{
		ctrNextBlock(ctx);
		for (size_t i = 0; i < ctx->blockSize; i++)
			out[i] = in[i] ^ ctx->keystream[i];
		ctx->keystreamOff = ctx->blockSize;
		out    += ctx->blockSize;
		in     += ctx->blockSize;
		inLen  -= ctx->blockSize;
		*outLen += ctx->blockSize;
	}

	/* Handle remaining partial block */
	if (inLen > 0)
	{
		ctrNextBlock(ctx);
		for (size_t i = 0; i < inLen; i++)
			out[i] = in[i] ^ ctx->keystream[i];
		ctx->keystreamOff = inLen;
		*outLen += inLen;
	}
}
