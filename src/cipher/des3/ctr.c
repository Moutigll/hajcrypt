#include "../../../includes/cipher/des3.h"
#include "../../../includes/cipher/modes.h"
#include "../../../includes/utils/utils.h"
#include "../../../hajlib/include/hmemory.h"

static void des3CtrProcessBlock(const uint8_t *in, uint8_t *out, const void *key)
{
	const t_des3CtrCtx	*ctx = key;
	uint64_t			block = 0;

	for (int i = 0; i < 8; i++)
		block = (block << 8) | in[i];

	block = des3EncryptBlock(block, ctx->subkeys1, ctx->subkeys2, ctx->subkeys3);

	for (int i = 0; i < 8; i++)
		out[i] = (block >> (56 - i * 8)) & 0xFF;
}

int des3CtrInit(void				*vctx,
				const uint8_t		*key,
				size_t				keyLen,
				const uint8_t		*iv,
				t_cipherDirection	dir)
{
	t_des3CtrCtx	*ctx = vctx;

	if (keyLen != 24)
		return (-1);

	des3GenerateSubkeys(key, ctx->subkeys1, ctx->subkeys2, ctx->subkeys3);

	ft_memcpy(ctx->ctrCtx.iv, iv ? iv : (uint8_t[8]){0}, 8);
	ft_memcpy(ctx->ctrCtx.counter, ctx->ctrCtx.iv, 8);
	ctx->ctrCtx.keystreamOff = 8;   /* force generation on first use */
	ctx->ctrCtx.blockSize = 8;
	ctx->ctrCtx.cipherCtx = ctx;
	ctx->ctrCtx.processBlock = des3CtrProcessBlock;

	(void)dir;   /* CTR encrypt == decrypt */
	return (0);
}

void des3CtrUpdate(void				*vctx,
				   const uint8_t	*in,
				   size_t			inLen,
				   uint8_t			*out,
				   size_t			*outLen)
{
	t_des3CtrCtx	*ctx = vctx;
	ctrGenUpdate(&ctx->ctrCtx, in, inLen, out, outLen);
}

void des3CtrFinal(void				*vctx,
				   uint8_t			*out,
				   size_t			*outLen)
{
	(void)vctx;
	(void)out;
	*outLen = 0;   /* CTR has no finalisation */
}

void des3CtrFree(void *vctx)
{
	t_des3CtrCtx	*ctx = vctx;
	secureZeroMemory(ctx->subkeys1, sizeof(ctx->subkeys1));
	secureZeroMemory(ctx->subkeys2, sizeof(ctx->subkeys2));
	secureZeroMemory(ctx->subkeys3, sizeof(ctx->subkeys3));
	secureZeroMemory(ctx->ctrCtx.iv, sizeof(ctx->ctrCtx.iv));
	secureZeroMemory(ctx->ctrCtx.counter, sizeof(ctx->ctrCtx.counter));
	secureZeroMemory(ctx->ctrCtx.keystream, sizeof(ctx->ctrCtx.keystream));
}

const t_cipher g_des3CtrCipher = {
	.name			= "des3-ctr",
	.mode			= CIPHER_MODE_CTR,
	.isEncoder		= 1,
	.blockSize		= 8,
	.keySize		= 24,
	.ivSize			= 8,
	.ctxSize		= sizeof(t_des3CtrCtx),
	.init			= des3CtrInit,
	.update			= des3CtrUpdate,
	.final			= des3CtrFinal,
	.free			= des3CtrFree,
	.pad			= NULL,
	.unpad			= NULL,
	.supportsWrap   = 0
};
