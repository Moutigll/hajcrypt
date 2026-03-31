#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/utils/utils.h"
#include "../../../includes/cipher/cipher.h"
#include "../../../includes/cipher/modes.h"
#include "../../../includes/cipher/des.h"

static void	desProcessBlock(const uint8_t *in, uint8_t *out, const void *key)
{
	const t_desCtrCtx	*ctx = key;
	uint64_t			block = 0;

	for (int i = 0; i < 8; i++)
		block = (block << 8) | in[i];
	block = desEncryptBlock(block, (uint64_t *)ctx->subkeys);
	for (int i = 0; i < 8; i++)
		out[i] = (block >> (56 - i * 8)) & 0xFF;
}

int	desCtrInit(void				*vctx,
			   const uint8_t	*key,
			   size_t			keyLen,
			   const uint8_t	*iv,
			   t_cipherDirection dir)
{
	t_desCtrCtx	*ctx = vctx;
	uint64_t	k = 0;

	(void)dir; /* CTR encrypt == decrypt */
	if (keyLen == 0)
		return (-1);
	for (int i = 0; i < 8 && i < (int)keyLen; i++)
		k = (k << 8) | key[i];
	desGenerateSubkeys(k, (uint64_t *)ctx->subkeys);

	ft_memcpy(ctx->ctrCtx.iv,      iv ? iv : (uint8_t[8]){0}, 8);
	ft_memcpy(ctx->ctrCtx.counter, ctx->ctrCtx.iv, 8);
	ctx->ctrCtx.keystreamOff = 8; /* force generation on first use */
	ctx->ctrCtx.blockSize    = 8;
	ctx->ctrCtx.cipherCtx    = ctx;
	ctx->ctrCtx.processBlock = desProcessBlock;
	return (0);
}

void	desCtrFree(void *vctx)
{
	t_desCtrCtx	*ctx = vctx;

	secureZeroMemory(ctx->subkeys, sizeof(ctx->subkeys));
	secureZeroMemory(ctx->ctrCtx.iv,        sizeof(ctx->ctrCtx.iv));
	secureZeroMemory(ctx->ctrCtx.counter,   sizeof(ctx->ctrCtx.counter));
	secureZeroMemory(ctx->ctrCtx.keystream, sizeof(ctx->ctrCtx.keystream));
}

void	desCtrUpdate(void			*vctx,
					 const uint8_t	*in,
					 size_t			inLen,
					 uint8_t		*out,
					 size_t			*outLen)
{
	t_desCtrCtx	*ctx = vctx;

	ctrGenUpdate(&ctx->ctrCtx, in, inLen, out, outLen);
}

void	desCtrFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	t_desCtrCtx	*ctx = vctx;

	(void)out; /* no padding in CTR mode */
	(void)outLen;
	(void)ctx; /* nothing to finalize */
}

const t_cipher g_desCtrCipher = {
	.name			= "des-ctr",
	.mode			= CIPHER_MODE_CTR,
	.isEncoder		= 1,
	.blockSize		= 8,
	.keySize		= 8,
	.ivSize			= 8,
	.ctxSize		= sizeof(t_desCtrCtx),
	.init			= desCtrInit,
	.update			= desCtrUpdate,
	.final			= desCtrFinal,
	.free			= desCtrFree,
	.pad			= NULL,
	.unpad			= NULL,
	.supportsWrap	= 0
};
