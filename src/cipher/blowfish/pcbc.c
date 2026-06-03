#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/utils/utils.h"
#include "../../../includes/cipher/modes.h"
#include "../../../includes/cipher/blowfish.h"

static void	blowfishProcessBlock(const uint8_t *in, uint8_t *out, const void *key, int encrypt)
{
	const t_blowfishPcbcCtx	*ctx = key;

	if (encrypt)
		blowfishEncryptBlock(ctx->P, ctx->S, in, out);
	else
		blowfishDecryptBlock(ctx->P, ctx->S, in, out);
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
	blowfishInitKey(ctx->P, ctx->S, key, keyLen);

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
	.deprecated		= 1,
	.mode			= CIPHER_MODE_PCBC,
	.oid			= OID_DEF("BLOWFISH-PCBC", BLOWFISH_PCBC_OID),
	.oiwOid			= OID_NONE,
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
