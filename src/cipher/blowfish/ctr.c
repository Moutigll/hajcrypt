#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/utils/utils.h"
#include "../../../includes/cipher/modes.h"
#include "../../../includes/cipher/blowfish.h"

static void	blowfishProcessBlock(const uint8_t *in, uint8_t *out, const void *key)
{
	const t_blowfishCtrCtx	*ctx = key;

	blowfishEncryptBlock(ctx->P, ctx->S, in, out);
}

int	blowfishCtrInit(void				*vctx,
					 const uint8_t		*key,
					 size_t				keyLen,
					 const uint8_t		*iv,
					 t_cipherDirection	dir)
{
	t_blowfishCtrCtx	*ctx = vctx;

	(void)dir; /* CTR encrypt == decrypt */

	if (!key || keyLen < BLOWFISH_MIN_KEY_SIZE || keyLen > BLOWFISH_MAX_KEY_SIZE)
		return (-1);

	/* Initialize key schedule */
	blowfishInitKey(ctx->P, ctx->S, key, keyLen);

	ft_memcpy(ctx->ctrCtx.iv, iv ? iv : (uint8_t[8]){0}, 8);
	ft_memcpy(ctx->ctrCtx.counter, ctx->ctrCtx.iv, 8);
	ctx->ctrCtx.keystreamOff = 8; /* force generation on first use */
	ctx->ctrCtx.blockSize = BLOWFISH_BLOCK_SIZE;
	ctx->ctrCtx.cipherCtx = ctx;
	ctx->ctrCtx.processBlock = blowfishProcessBlock;

	return (0);
}

void	blowfishCtrUpdate(void *vctx, const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen)
{
	t_blowfishCtrCtx *ctx = vctx;
	ctrGenUpdate(&ctx->ctrCtx, in, inLen, out, outLen);
}

void	blowfishCtrFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	(void)vctx;
	(void)out;
	*outLen = 0;	/* No padding, nothing to do */
}

void	blowfishCtrFree(void *vctx)
{
	t_blowfishCtrCtx *ctx = vctx;

	secureZeroMemory(ctx->P, sizeof(ctx->P));
	secureZeroMemory(ctx->S, sizeof(ctx->S));
	secureZeroMemory(ctx->ctrCtx.iv, sizeof(ctx->ctrCtx.iv));
	secureZeroMemory(ctx->ctrCtx.counter, sizeof(ctx->ctrCtx.counter));
	secureZeroMemory(ctx->ctrCtx.keystream, sizeof(ctx->ctrCtx.keystream));
}

const t_cipher	g_blowfishCtrCipher = {
	.name			= "blowfish-ctr",
	.mode			= CIPHER_MODE_CTR,
	.oid			= OID_DEF("BLOWFISH-CTR", BLOWFISH_CTR_OID),
	.oiwOid			= OID_NONE,
	.isEncoder		= 1,
	.blockSize		= BLOWFISH_BLOCK_SIZE,
	.keySize		= BLOWFISH_DEFAULT_KEY_SIZE,
	.ivSize			= BLOWFISH_IV_SIZE,
	.ctxSize		= sizeof(t_blowfishCtrCtx),
	.init			= blowfishCtrInit,
	.update			= blowfishCtrUpdate,
	.final			= blowfishCtrFinal,
	.free			= blowfishCtrFree,
	.pad			= NULL,
	.unpad			= NULL,
	.supportsWrap	= 0
};
