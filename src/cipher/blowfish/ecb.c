#include "../../../includes/cipher/blowfish.h"
#include "../../../includes/utils/utils.h"
#include "../../../hajlib/include/hmemory.h"

int	blowfishEcbInit(void				*vctx,
					 const uint8_t		*key,
					 size_t				keyLen,
					 const uint8_t		*iv,
					 t_cipherDirection	dir)
{
	t_blowfishEcbCtx	*ctx = vctx;

	if (!key || keyLen < BLOWFISH_MIN_KEY_SIZE || keyLen > BLOWFISH_MAX_KEY_SIZE)
		return (-1);

	(void)iv;	/* ECB does not use an IV */

	blowfishInitKey(ctx, key, keyLen);
	ctx->bufferLen = 0;
	ctx->dir = dir;
	return (0);
}

void	blowfishEcbUpdate(void			*vctx,
						  const uint8_t	*in,
						  size_t		inLen,
						  uint8_t		*out,
						  size_t		*outLen)
{
	t_blowfishEcbCtx	*ctx = vctx;
	uint64_t			block;
	size_t				i, j;

	*outLen = 0;

	for (i = 0; i + 8 <= inLen; i += 8)
	{
		block = 0;
		for (j = 0; j < 8; j++)
			block = (block << 8) | in[i + j];

		if (ctx->dir == CIPHER_ENCRYPT)
			block = blowfishEncryptBlock(ctx, block);
		else
			block = blowfishDecryptBlock(ctx, block);

		for (j = 0; j < 8; j++)
			out[(*outLen)++] = (block >> (56 - j * 8)) & 0xFF;
	}

	/* Save remaining bytes for final */
	if (i < inLen)
	{
		ft_memcpy(ctx->buffer, in + i, inLen - i);
		ctx->bufferLen = inLen - i;
	}
}

void blowfishEcbFinal(void *vctx, uint8_t *out, size_t *outLen)
{
    (void)vctx;
    (void)out;
    *outLen = 0;   /* Rien à faire, le padding est géré par le dispatcher */
}
void	blowfishEcbFree(void *vctx)
{
	t_blowfishEcbCtx	*ctx = vctx;

	secureZeroMemory(ctx->P, sizeof(ctx->P));
	secureZeroMemory(ctx->S, sizeof(ctx->S));
	secureZeroMemory(ctx->buffer, sizeof(ctx->buffer));
	ctx->bufferLen = 0;
}

const t_cipher	g_blowfishEcbCipher = {
	.name			= "blowfish-ecb",
	.mode			= CIPHER_MODE_ECB,
	.isEncoder		= 1,
	.blockSize		= BLOWFISH_BLOCK_SIZE,
	.keySize		= BLOWFISH_DEFAULT_KEY_SIZE,
	.ivSize			= 0,
	.ctxSize		= sizeof(t_blowfishEcbCtx),
	.init			= blowfishEcbInit,
	.update			= blowfishEcbUpdate,
	.final			= blowfishEcbFinal,
	.free			= blowfishEcbFree,
	.pad			= pkcs7Pad,
	.unpad			= pkcs7Unpad,
	.supportsWrap	= 0
};
