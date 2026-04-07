#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/utils/utils.h"
#include "../../../includes/cipher/modes.h"
#include "../../../includes/cipher/blowfish.h"

static void	blowfishProcessBlock(const uint8_t *in, uint8_t *out, const void *key, int encrypt)
{
	const uint64_t	*subkeys = key;
	const t_blowfishPcbcCtx *ctx = (const t_blowfishPcbcCtx *)key;
	uint64_t block = 0;

	(void)subkeys;

	for (int i = 0; i < 8; i++)
		block = (block << 8) | in[i];

	t_blowfishEcbCtx	tmp;
	ft_memcpy(tmp.P, ctx->P, sizeof(tmp.P));
	ft_memcpy(tmp.S, ctx->S, sizeof(tmp.S));

	if (encrypt)
		block = blowfishEncryptBlock(&tmp, block);
	else
		block = blowfishDecryptBlock(&tmp, block);

	for (int i = 0; i < 8; i++)
		out[i] = (block >> (56 - i * 8)) & 0xFF;
}

int	blowfishPcbcInit(void				*vctx,
					  const uint8_t		*key,
					  size_t			keyLen,
					  const uint8_t		*iv,
					  t_cipherDirection	dir)
{
	t_blowfishPcbcCtx	*ctx = vctx;

	if (!key || keyLen < BLOWFISH_MIN_KEY_SIZE || keyLen > BLOWFISH_MAX_KEY_SIZE)
		return (-1);

	/* Initialize key schedule */
	{
		t_blowfishEcbCtx	tmp;
		blowfishInitKey(&tmp, key, keyLen);
		ft_memcpy(ctx->P, tmp.P, sizeof(ctx->P));
		ft_memcpy(ctx->S, tmp.S, sizeof(ctx->S));
	}

	ft_memcpy(ctx->pcbcCtx.iv, iv ? iv : (uint8_t[8]){0}, 8);
	ft_memcpy(ctx->pcbcCtx.prevPlain, ctx->pcbcCtx.iv, 8);
	ctx->pcbcCtx.bufferLen = 0;
	ctx->pcbcCtx.dir = dir;
	ctx->pcbcCtx.blockSize = BLOWFISH_BLOCK_SIZE;
	ctx->pcbcCtx.cipherCtx = ctx;	/* Pass the whole context to processBlock */
	ctx->pcbcCtx.processBlock = blowfishProcessBlock;

	return (0);
}

void	blowfishPcbcUpdate(void *vctx, const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen)
{
	t_blowfishPcbcCtx *ctx = vctx;
	pcbcGenUpdate(&ctx->pcbcCtx, in, inLen, out, outLen);
}

void	blowfishPcbcFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	t_blowfishPcbcCtx *ctx = vctx;
	pcbcGenFinal(&ctx->pcbcCtx, out, outLen);
}

void	blowfishPcbcFree(void *vctx)
{
	t_blowfishPcbcCtx *ctx = vctx;

	secureZeroMemory(ctx->P, sizeof(ctx->P));
	secureZeroMemory(ctx->S, sizeof(ctx->S));
	secureZeroMemory(ctx->pcbcCtx.iv, sizeof(ctx->pcbcCtx.iv));
	secureZeroMemory(ctx->pcbcCtx.prevPlain, sizeof(ctx->pcbcCtx.prevPlain));
	secureZeroMemory(ctx->pcbcCtx.buffer, sizeof(ctx->pcbcCtx.buffer));
}

const t_cipher	g_blowfishPcbcCipher = {
	.name			= "blowfish-pcbc",
	.mode			= CIPHER_MODE_PCBC,
	.isEncoder		= 1,
	.blockSize		= BLOWFISH_BLOCK_SIZE,
	.keySize		= BLOWFISH_DEFAULT_KEY_SIZE,
	.ivSize			= BLOWFISH_IV_SIZE,
	.ctxSize		= sizeof(t_blowfishPcbcCtx),
	.init			= blowfishPcbcInit,
	.update			= blowfishPcbcUpdate,
	.final			= blowfishPcbcFinal,
	.free			= blowfishPcbcFree,
	.pad			= pkcs7Pad,
	.unpad			= pkcs7Unpad,
	.supportsWrap	= 0
};
