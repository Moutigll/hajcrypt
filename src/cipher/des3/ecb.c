#include "../../../includes/cipher/des3.h"
#include "../../../includes/utils/utils.h"
#include "../../../hajlib/include/hmemory.h"

static void des3EcbProcessBlock(const uint8_t *in, uint8_t *out, const void *key, int encrypt)
{
	const t_des3EcbCtx	*ctx = key;
	uint64_t			block = 0;

	for (int i = 0; i < 8; i++)
		block = (block << 8) | in[i];

	if (encrypt)
		block = des3EncryptBlock(block, ctx->subkeys1, ctx->subkeys2, ctx->subkeys3);
	else
		block = des3DecryptBlock(block, ctx->subkeys1, ctx->subkeys2, ctx->subkeys3);

	for (int i = 0; i < 8; i++)
		out[i] = (block >> (56 - i * 8)) & 0xFF;
}

int des3EcbInit(void				*vctx,
				const uint8_t		*key,
				size_t				keyLen,
				const uint8_t		*iv,
				t_cipherDirection	dir)
{
	t_des3EcbCtx *ctx = vctx;

	if (keyLen != 24)
		return (-1);

	des3GenerateSubkeys(key, ctx->subkeys1, ctx->subkeys2, ctx->subkeys3);

	ctx->bufferLen = 0;
	ctx->dir = dir;
	(void)iv;   /* ECB ignores IV */
	return (0);
}

void des3EcbUpdate(void				*vctx,
				   const uint8_t	*in,
				   size_t			inLen,
				   uint8_t			*out,
				   size_t			*outLen)
{
	t_des3EcbCtx	*ctx = vctx;
	size_t			to_copy;
	size_t			block_count;
	size_t			i;

	*outLen = 0;

	/* If we have a partially filled buffer from previous call, fill it first */
	if (ctx->bufferLen > 0) {
		/* Calculate how many bytes we need to complete a block */
		to_copy = 8 - ctx->bufferLen;
		if (to_copy > inLen)
			to_copy = inLen;

		/* Copy data to complete the buffer */
		ft_memcpy(ctx->buffer + ctx->bufferLen, in, to_copy);
		ctx->bufferLen += to_copy;
		in += to_copy;
		inLen -= to_copy;

		/* If we have a full block now, process it */
		if (ctx->bufferLen == 8) {
			des3EcbProcessBlock(ctx->buffer, out, ctx,
					    ctx->dir == CIPHER_ENCRYPT);
			out += 8;
			*outLen += 8;
			ctx->bufferLen = 0;
		}
	}

	/* Process full blocks from input */
	block_count = inLen / 8;
	for (i = 0; i < block_count; i++) {
		des3EcbProcessBlock(in + i * 8, out + i * 8, ctx,
				    ctx->dir == CIPHER_ENCRYPT);
	}
	*outLen += block_count * 8;
	in += block_count * 8;
	inLen -= block_count * 8;

	/* Buffer remaining bytes for next call */
	if (inLen > 0) {
		ft_memcpy(ctx->buffer, in, inLen);
		ctx->bufferLen = inLen;
	}
}

void des3EcbFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	t_des3EcbCtx *ctx = vctx;
	*outLen = 0;

	if (ctx->dir == CIPHER_ENCRYPT) {
		/* PKCS#7 padding */
		uint8_t pad = 8 - ctx->bufferLen;
		for (size_t i = ctx->bufferLen; i < 8; i++)
			ctx->buffer[i] = pad;
		des3EcbProcessBlock(ctx->buffer, out, ctx, 1);
		*outLen = 8;
	} else {
		/* Decryption – last block may have padding; caller handles unpad */
		if (ctx->bufferLen != 0) {
			/* Should not happen for correctly padded data */
			return;
		}
	}
	ctx->bufferLen = 0;
}

void des3EcbFree(void *vctx)
{
	t_des3EcbCtx *ctx = vctx;
	secureZeroMemory(ctx->subkeys1, sizeof(ctx->subkeys1));
	secureZeroMemory(ctx->subkeys2, sizeof(ctx->subkeys2));
	secureZeroMemory(ctx->subkeys3, sizeof(ctx->subkeys3));
	secureZeroMemory(ctx->buffer, sizeof(ctx->buffer));
}

const t_cipher g_des3EcbCipher = {
	.name			= "des3-ecb",
	.mode			= CIPHER_MODE_ECB,
	.isEncoder		= 1,
	.blockSize		= 8,
	.keySize		= 24,
	.ivSize			= 0,
	.ctxSize		= sizeof(t_des3EcbCtx),
	.init			= des3EcbInit,
	.update			= des3EcbUpdate,
	.final			= des3EcbFinal,
	.free			= des3EcbFree,
	.pad			= pkcs7Pad,
	.unpad			= pkcs7Unpad,
	.supportsWrap	= 0
};
