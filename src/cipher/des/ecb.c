#include <string.h>

#include "../../../includes/cipher/des.h"

void desEcbInit(void				*vctx,
				const uint8_t		*key,
				size_t				keyLen,
				const uint8_t		*iv,
				t_cipherDirection	dir)
{
	t_desEcbCtx	*ctx = vctx;
	uint64_t	k = 0;
	int			i;

	(void)iv;	/* ECB does not use an IV */

	/* Convert the key (max 8 bytes) */
	for (i = 0; i < 8 && i < (int)keyLen; i++)
		k = (k << 8) | key[i];

	desGenerateSubkeys(k, ctx->subkeys);
	ctx->bufferLen = 0;
	ctx->dir = dir;
}

void desEcbUpdate(void			*vctx,
				  const uint8_t	*in,
				  size_t		inLen,
				  uint8_t		*out,
				  size_t		*outLen)
{
	t_desEcbCtx	*ctx = vctx;
	size_t		processed = 0;
	*outLen = 0;

	while (processed < inLen) {
		size_t to_copy = 8 - ctx->bufferLen;
		if (to_copy > inLen - processed)
			to_copy = inLen - processed;

		memcpy(ctx->buffer + ctx->bufferLen, in + processed, to_copy);
		ctx->bufferLen += to_copy;
		processed += to_copy;

		if (ctx->bufferLen == 8) {
			uint64_t block = 0;
			for (int i = 0; i < 8; i++)
				block = (block << 8) | ctx->buffer[i];

			if (ctx->dir == CIPHER_ENCRYPT)
				block = desEncryptBlock(block, ctx->subkeys);
			else
				block = desDecryptBlock(block, ctx->subkeys);

			for (int i = 0; i < 8; i++)
				out[(*outLen)++] = (block >> (56 - i * 8)) & 0xFF;

			ctx->bufferLen = 0;
		}
	}
}

void desEcbFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	t_desEcbCtx	*ctx = vctx;
	*outLen = 0;

	if (ctx->dir == CIPHER_ENCRYPT && ctx->bufferLen > 0) {
		uint8_t block[8];
		memcpy(block, ctx->buffer, ctx->bufferLen);
		desPad(block, ctx->bufferLen, 8);

		uint64_t blockVal = 0;
		for (int i = 0; i < 8; i++)
			blockVal = (blockVal << 8) | block[i];

		blockVal = desEncryptBlock(blockVal, ctx->subkeys);

		for (int i = 0; i < 8; i++)
			out[(*outLen)++] = (blockVal >> (56 - i * 8)) & 0xFF;
	}
	/* For decryption, we assume the input is always a multiple of 8 bytes and properly padded, so no action is needed here. */
}

void desEcbFree(void *vctx)
{
	(void)vctx;
}

const t_cipher g_desEcbCipher = {
	.name = "DES-ECB",
	.blockSize = 8,
	.keySize = 8,
	.ivSize = 0,
	.init = desEcbInit,
	.update = desEcbUpdate,
	.final = desEcbFinal,
	.free = desEcbFree
};
