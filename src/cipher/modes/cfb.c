#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/cipher/modes.h"

void cfbGenUpdate(t_cfbGenCtx	*ctx,
				  const uint8_t	*in,
				  size_t		inLen,
				  uint8_t		*out,
				  size_t		*outLen)
{
	size_t	blockSize = ctx->blockSize;
	size_t	unitSize  = ctx->unitSize;
	*outLen = 0;

	/* Flush buffered partial unit */
	if (ctx->inputBufLen > 0) {
		size_t need = unitSize - ctx->inputBufLen;
		size_t take = (need < inLen) ? need : inLen;

		ft_memcpy(ctx->inputBuf + ctx->inputBufLen, in, take);
		ctx->inputBufLen += take;
		in	+= take;
		inLen -= take;

		if (ctx->inputBufLen == unitSize) {
			uint8_t ks[64];
			ft_memcpy(ks, ctx->shiftRegister, blockSize);
			ctx->processBlock(ks, ks, ctx->cipherCtx);

			for (size_t i = 0; i < unitSize; i++)
				out[i] = ctx->inputBuf[i] ^ ks[i];

			const uint8_t *feedback = (ctx->dir == CIPHER_ENCRYPT)
									  ? out : ctx->inputBuf;
			ft_memcpy(ctx->shiftRegister,
					  ctx->shiftRegister + unitSize,
					  blockSize - unitSize);
			ft_memcpy(ctx->shiftRegister + blockSize - unitSize,
					  feedback, unitSize);

			out			  += unitSize;
			*outLen		  += unitSize;
			ctx->inputBufLen  = 0;
		}
	}

	/* Process full units */
	while (inLen >= unitSize) {
		uint8_t ks[64];
		ft_memcpy(ks, ctx->shiftRegister, blockSize);
		ctx->processBlock(ks, ks, ctx->cipherCtx);

		for (size_t i = 0; i < unitSize; i++)
			out[i] = in[i] ^ ks[i];

		const uint8_t *feedback = (ctx->dir == CIPHER_ENCRYPT) ? out : in;
		ft_memcpy(ctx->shiftRegister,
				  ctx->shiftRegister + unitSize,
				  blockSize - unitSize);
		ft_memcpy(ctx->shiftRegister + blockSize - unitSize,
				  feedback, unitSize);

		out	 += unitSize;
		in	  += unitSize;
		inLen   -= unitSize;
		*outLen += unitSize;
	}

	/* Buffer remaining bytes */
	if (inLen > 0) {
		ft_memcpy(ctx->inputBuf + ctx->inputBufLen, in, inLen);
		ctx->inputBufLen += inLen;
	}
}

void cfbGenFinal(t_cfbGenCtx *ctx, uint8_t *out, size_t *outLen)
{
	*outLen = 0;
	if (ctx->inputBufLen == 0)
		return;

	uint8_t ks[64];
	ft_memcpy(ks, ctx->shiftRegister, ctx->blockSize);
	ctx->processBlock(ks, ks, ctx->cipherCtx);

	for (size_t i = 0; i < ctx->inputBufLen; i++)
		out[i] = ctx->inputBuf[i] ^ ks[i];

	*outLen		  = ctx->inputBufLen;
	ctx->inputBufLen = 0;
}

void cfb1Update(t_cfbGenCtx		*ctx,
				const uint8_t	*in,
				size_t			inBits,
				uint8_t			*out,
				size_t			*outBits)
{
	size_t	blockSize = ctx->blockSize;
	*outBits = 0;

	for (size_t b = 0; b < inBits; b++) {
		uint8_t ks[64];
		ft_memcpy(ks, ctx->shiftRegister, blockSize);
		ctx->processBlock(ks, ks, ctx->cipherCtx);

		uint8_t	inBit			= (in[b / 8] >> (7 - (b % 8))) & 1;
		uint8_t	keystreamBit	= (ks[0] >> 7) & 1;
		uint8_t	outBit			= inBit ^ keystreamBit;

		/* Write output bit, clearing byte on first bit of each byte */
		if (*outBits % 8 == 0)
			out[*outBits / 8] = 0;
		out[*outBits / 8] |= (outBit << (7 - (*outBits % 8)));
		(*outBits)++;

		/* Feedback: ciphertext bit for encrypt, input (ciphertext) bit for decrypt */
		uint8_t feedbackBit = (ctx->dir == CIPHER_ENCRYPT) ? outBit : inBit;

		/* Left-shift SR by 1, insert feedbackBit at LSB of last byte */
		for (size_t i = 0; i < blockSize - 1; i++)
			ctx->shiftRegister[i] = (ctx->shiftRegister[i] << 1)
								  | (ctx->shiftRegister[i + 1] >> 7);
		ctx->shiftRegister[blockSize - 1] =
			(ctx->shiftRegister[blockSize - 1] << 1) | feedbackBit;
	}
}
