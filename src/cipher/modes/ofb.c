#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/cipher/modes.h"

/**
 * @brief Generate the next block of keystream for OFB mode
 * This function encrypts the current keystream block to produce the next keystream block.
 * @param ctx The OFB context
 */
static void ofbNextBlock(t_ofbGenCtx *ctx)
{
	ctx->processBlock(ctx->keystream, ctx->keystream, ctx->cipherCtx);
	ctx->keystreamOff = 0;
}

void ofbGenUpdate(t_ofbGenCtx	*ctx,
				  const uint8_t	*in,
				  size_t		inLen,
				  uint8_t		*out,
				  size_t		*outLen)
{
	const size_t	blockSize = ctx->blockSize;
	*outLen = 0;

	/* empty input buffer */
	if (ctx->inputBufLen > 0)
	{
		size_t need = blockSize - ctx->inputBufLen;
		size_t take = (need < inLen) ? need : inLen;

		ft_memcpy(ctx->inputBuf + ctx->inputBufLen, in, take);
		ctx->inputBufLen += take;
		in			   += take;
		inLen			-= take;

		if (ctx->inputBufLen == blockSize)
		{
			/* Generate the next keystream block if needed */
			if (ctx->keystreamOff == blockSize)
				ofbNextBlock(ctx);

			for (size_t i = 0; i < blockSize; i++)
				out[i] = ctx->inputBuf[i] ^ ctx->keystream[ctx->keystreamOff + i];

			ctx->keystreamOff += blockSize;
			out			  += blockSize;
			*outLen		  += blockSize;
			ctx->inputBufLen  = 0;
		}
	}

	/* Process full blocks directly from input */
	while (inLen >= blockSize)
	{
		if (ctx->keystreamOff == blockSize)
			ofbNextBlock(ctx);

		for (size_t i = 0; i < blockSize; i++)
			out[i] = in[i] ^ ctx->keystream[ctx->keystreamOff + i];

		ctx->keystreamOff += blockSize;
		out			   += blockSize;
		in				+= blockSize;
		inLen			 -= blockSize;
		*outLen		   += blockSize;
	}

	/* Buffer any remaining input for the finalization step */
	if (inLen > 0)
	{
		ft_memcpy(ctx->inputBuf + ctx->inputBufLen, in, inLen);
		ctx->inputBufLen += inLen;
	}
}

void ofbGenFinal(t_ofbGenCtx *ctx, uint8_t *out, size_t *outLen)
{
	*outLen = 0;
	if (ctx->inputBufLen == 0)
		return;

	/* No padding needed for OFB, just xor the remaining bytes with the keystream */
	if (ctx->keystreamOff == ctx->blockSize)
		ofbNextBlock(ctx);

	for (size_t i = 0; i < ctx->inputBufLen; i++)
		out[i] = ctx->inputBuf[i] ^ ctx->keystream[ctx->keystreamOff + i];

	*outLen		  = ctx->inputBufLen;
	ctx->inputBufLen = 0;
}
