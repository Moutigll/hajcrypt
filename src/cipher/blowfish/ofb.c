#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/utils/utils.h"
#include "../../../includes/cipher/modes.h"
#include "../../../includes/cipher/blowfish.h"

static void	blowfishProcessBlock(const uint8_t *in, uint8_t *out, const void *key)
{
	const t_blowfishOfbCtx	*ctx = key;

	blowfishEncryptBlock(ctx->P, ctx->S, in, out);
}

int	blowfishOfbInit(void				*vctx,
					 const uint8_t		*key,
					 size_t				keyLen,
					 const uint8_t		*iv,
					 t_cipherDirection	dir)
{
	t_blowfishOfbCtx	*ctx = vctx;

	(void)dir; /* OFB encrypt == decrypt */

	if (!key || keyLen < BLOWFISH_MIN_KEY_SIZE || keyLen > BLOWFISH_MAX_KEY_SIZE)
		return (-1);

	/* Initialize key schedule */
	blowfishInitKey(ctx->P, ctx->S, key, keyLen);

	ft_memcpy(ctx->ofbCtx.iv, iv ? iv : (uint8_t[8]){0}, 8);
	ft_memcpy(ctx->ofbCtx.keystream, ctx->ofbCtx.iv, 8);
	ctx->ofbCtx.keystreamOff = 8; /* force generation on first use */
	ctx->ofbCtx.inputBufLen = 0;
	ctx->ofbCtx.blockSize = BLOWFISH_BLOCK_SIZE;
	ctx->ofbCtx.cipherCtx = ctx;
	ctx->ofbCtx.processBlock = blowfishProcessBlock;

	return (0);
}

void	blowfishOfbUpdate(void *vctx, const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen)
{
	t_blowfishOfbCtx *ctx = vctx;
	ofbGenUpdate(&ctx->ofbCtx, in, inLen, out, outLen);
}

void	blowfishOfbFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	t_blowfishOfbCtx *ctx = vctx;
	ofbGenFinal(&ctx->ofbCtx, out, outLen);
}

void	blowfishOfbFree(void *vctx)
{
	t_blowfishOfbCtx *ctx = vctx;

	secureZeroMemory(ctx->P, sizeof(ctx->P));
	secureZeroMemory(ctx->S, sizeof(ctx->S));
	secureZeroMemory(ctx->ofbCtx.iv, sizeof(ctx->ofbCtx.iv));
	secureZeroMemory(ctx->ofbCtx.keystream, sizeof(ctx->ofbCtx.keystream));
}

const t_cipher	g_blowfishOfbCipher = {
	.name			= "blowfish-ofb",
	.mode			= CIPHER_MODE_OFB,
	.oid			= OID_DEF("BLOWFISH-OFB", BLOWFISH_OFB_OID),
	.oiwOid			= OID_NONE,
	.isEncoder		= 1,
	.blockSize		= BLOWFISH_BLOCK_SIZE,
	.keySize		= BLOWFISH_DEFAULT_KEY_SIZE,
	.ivSize			= BLOWFISH_IV_SIZE,
	.ctxSize		= sizeof(t_blowfishOfbCtx),
	.init			= blowfishOfbInit,
	.update			= blowfishOfbUpdate,
	.final			= blowfishOfbFinal,
	.free			= blowfishOfbFree,
	.pad			= NULL,
	.unpad			= NULL,
	.supportsWrap	= 0
};
