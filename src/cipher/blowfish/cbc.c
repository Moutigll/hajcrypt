#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/utils/utils.h"
#include "../../../includes/cipher/modes.h"
#include "../../../includes/cipher/blowfish.h"

static void	blowfishProcessBlock(const uint8_t *in, uint8_t *out, const void *key, int encrypt)
{
	const t_blowfishCbcCtx	*ctx = key;
	uint64_t				block = 0;

	for (int i = 0; i < 8; i++)
		block = (block << 8) | in[i];

	if (encrypt)
	{
		/* For CBC encryption we need the context's P and S */
		t_blowfishEcbCtx	tmp;
		ft_memcpy(tmp.P, ctx->P, sizeof(tmp.P));
		ft_memcpy(tmp.S, ctx->S, sizeof(tmp.S));
		block = blowfishEncryptBlock(&tmp, block);
	}
	else
	{
		t_blowfishEcbCtx	tmp;
		ft_memcpy(tmp.P, ctx->P, sizeof(tmp.P));
		ft_memcpy(tmp.S, ctx->S, sizeof(tmp.S));
		block = blowfishDecryptBlock(&tmp, block);
	}

	for (int i = 0; i < 8; i++)
		out[i] = (block >> (56 - i * 8)) & 0xFF;
}

int	blowfishCbcInit(void				*vctx,
					 const uint8_t		*key,
					 size_t				keyLen,
					 const uint8_t		*iv,
					 t_cipherDirection	dir)
{
	t_blowfishCbcCtx	*ctx = vctx;

	if (!key || keyLen < BLOWFISH_MIN_KEY_SIZE || keyLen > BLOWFISH_MAX_KEY_SIZE)
		return (-1);

	/* Initialize key schedule into P and S of the context */
	{
		t_blowfishEcbCtx	tmp;
		blowfishInitKey(&tmp, key, keyLen);
		ft_memcpy(ctx->P, tmp.P, sizeof(ctx->P));
		ft_memcpy(ctx->S, tmp.S, sizeof(ctx->S));
	}

	ft_memcpy(ctx->cbcCtx.iv, iv ? iv : (uint8_t[8]){0}, 8);
	ctx->cbcCtx.bufferLen = 0;
	ctx->cbcCtx.dir = dir;
	ctx->cbcCtx.blockSize = BLOWFISH_BLOCK_SIZE;
	ctx->cbcCtx.cipherCtx = ctx;
	ctx->cbcCtx.processBlock = blowfishProcessBlock;

	return (0);
}

void	blowfishCbcUpdate(void			*vctx,
						  const uint8_t	*in,
						  size_t		inLen,
						  uint8_t		*out,
						  size_t		*outLen)
{
	t_blowfishCbcCtx	*ctx = vctx;
	cbcGenUpdate(&ctx->cbcCtx, in, inLen, out, outLen);
}

void	blowfishCbcFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	t_blowfishCbcCtx	*ctx = vctx;
	cbcGenFinal(&ctx->cbcCtx, out, outLen);
}

void	blowfishCbcFree(void *vctx)
{
	t_blowfishCbcCtx	*ctx = vctx;

	secureZeroMemory(ctx->P, sizeof(ctx->P));
	secureZeroMemory(ctx->S, sizeof(ctx->S));
	secureZeroMemory(ctx->cbcCtx.iv, sizeof(ctx->cbcCtx.iv));
	secureZeroMemory(ctx->cbcCtx.buffer, sizeof(ctx->cbcCtx.buffer));
}

const t_cipher	g_blowfishCbcCipher = {
	.name			= "blowfish-cbc",
	.mode			= CIPHER_MODE_CBC,
	.isEncoder		= 1,
	.blockSize		= BLOWFISH_BLOCK_SIZE,
	.keySize		= BLOWFISH_DEFAULT_KEY_SIZE,
	.ivSize			= BLOWFISH_IV_SIZE,
	.ctxSize		= sizeof(t_blowfishCbcCtx),
	.init			= blowfishCbcInit,
	.update			= blowfishCbcUpdate,
	.final			= blowfishCbcFinal,
	.free			= blowfishCbcFree,
	.pad			= pkcs7Pad,
	.unpad			= pkcs7Unpad,
	.supportsWrap	= 0
};

const t_cipher	g_blowfishCipher = {
	.name			= "blowfish",
	.mode			= CIPHER_MODE_CBC,
	.isEncoder		= 1,
	.blockSize		= BLOWFISH_BLOCK_SIZE,
	.keySize		= BLOWFISH_DEFAULT_KEY_SIZE,
	.ivSize			= BLOWFISH_IV_SIZE,
	.ctxSize		= sizeof(t_blowfishCbcCtx),
	.init			= blowfishCbcInit,
	.update			= blowfishCbcUpdate,
	.final			= blowfishCbcFinal,
	.free			= blowfishCbcFree,
	.pad			= pkcs7Pad,
	.unpad			= pkcs7Unpad,
	.supportsWrap	= 0
};
