#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/utils/utils.h"
#include "../../../includes/cipher/modes.h"
#include "../../../includes/cipher/blowfish.h"

/* Process block always uses encryption (CFB mode encrypts the IV/shift register) */
static void	blowfishProcessBlock(const uint8_t *in, uint8_t *out, const void *key)
{
	const t_blowfishCfbCtx	*ctx = key;

	blowfishEncryptBlock(ctx->P, ctx->S, in, out);
}

/* Generic initialization for CFB, CFB8, CFB1 */
static int	blowfishCfbGenInit(void					*vctx,
							   const uint8_t		*key,
							   size_t				keyLen,
							   const uint8_t		*iv,
							   t_cipherDirection	dir,
							   int					unitSize)
{
	t_blowfishCfbCtx	*ctx = vctx;

	if (!key || keyLen < BLOWFISH_MIN_KEY_SIZE || keyLen > BLOWFISH_MAX_KEY_SIZE)
		return (-1);

	/* Initialize key schedule directly into P and S of the context */
	blowfishInitKey(ctx->P, ctx->S, key, keyLen);

	ft_memcpy(ctx->cfbCtx.iv, iv ? iv : (uint8_t[8]){0}, 8);
	ft_memcpy(ctx->cfbCtx.shiftRegister, ctx->cfbCtx.iv, 8);
	ctx->cfbCtx.inputBufLen = 0;
	ctx->cfbCtx.dir = dir;
	ctx->cfbCtx.blockSize = BLOWFISH_BLOCK_SIZE;
	ctx->cfbCtx.unitSize = unitSize;
	ctx->cfbCtx.cipherCtx = ctx;
	ctx->cfbCtx.processBlock = blowfishProcessBlock;

	return (0);
}

int	blowfishCfbInit(void *vctx, const uint8_t *key, size_t keyLen, const uint8_t *iv, t_cipherDirection dir)
{
	return blowfishCfbGenInit(vctx, key, keyLen, iv, dir, 8);
}

int	blowfishCfb8Init(void *vctx, const uint8_t *key, size_t keyLen, const uint8_t *iv, t_cipherDirection dir)
{
	return blowfishCfbGenInit(vctx, key, keyLen, iv, dir, 1);
}

int	blowfishCfb1Init(void *vctx, const uint8_t *key, size_t keyLen, const uint8_t *iv, t_cipherDirection dir)
{
	return blowfishCfbGenInit(vctx, key, keyLen, iv, dir, 1);
}

void	blowfishCfbUpdate(void *vctx, const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen)
{
	t_blowfishCfbCtx *ctx = vctx;
	cfbGenUpdate(&ctx->cfbCtx, in, inLen, out, outLen);
}

void	blowfishCfb1Update(void *vctx, const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen)
{
	t_blowfishCfbCtx *ctx = vctx;
	size_t outBits = 0;
	cfb1Update(&ctx->cfbCtx, in, inLen * 8, out, &outBits);
	*outLen = (outBits + 7) / 8;
}

void	blowfishCfbFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	t_blowfishCfbCtx *ctx = vctx;
	cfbGenFinal(&ctx->cfbCtx, out, outLen);
}

void	blowfishCfb1Final(void *vctx, uint8_t *out, size_t *outBits)
{
	(void)vctx;
	(void)out;
	*outBits = 0;
}

void	blowfishCfbFree(void *vctx)
{
	t_blowfishCfbCtx *ctx = vctx;

	secureZeroMemory(ctx->P, sizeof(ctx->P));
	secureZeroMemory(ctx->S, sizeof(ctx->S));
	secureZeroMemory(ctx->cfbCtx.iv, sizeof(ctx->cfbCtx.iv));
	secureZeroMemory(ctx->cfbCtx.shiftRegister, sizeof(ctx->cfbCtx.shiftRegister));
}

const t_cipher	g_blowfishCfbCipher = {
	.name			= "blowfish-cfb",
	.mode			= CIPHER_MODE_CFB,
	.oid			= OID_DEF("BLOWFISH-CFB", BLOWFISH_CFB_OID),
	.oiwOid			= OID_NONE,
	.isEncoder		= 1,
	.blockSize		= BLOWFISH_BLOCK_SIZE,
	.keySize		= BLOWFISH_DEFAULT_KEY_SIZE,
	.ivSize			= BLOWFISH_IV_SIZE,
	.ctxSize		= sizeof(t_blowfishCfbCtx),
	.init			= blowfishCfbInit,
	.update			= blowfishCfbUpdate,
	.final			= blowfishCfbFinal,
	.free			= blowfishCfbFree,
	.pad			= NULL,
	.unpad			= NULL,
	.supportsWrap	= 0
};

const t_cipher	g_blowfishCfb8Cipher = {
	.name			= "blowfish-cfb8",
	.mode			= CIPHER_MODE_CFB8,
	.oid			= OID_NONE,
	.oiwOid			= OID_NONE,
	.isEncoder		= 1,
	.blockSize		= BLOWFISH_BLOCK_SIZE,
	.keySize		= BLOWFISH_DEFAULT_KEY_SIZE,
	.ivSize			= BLOWFISH_IV_SIZE,
	.ctxSize		= sizeof(t_blowfishCfbCtx),
	.init			= blowfishCfb8Init,
	.update			= blowfishCfbUpdate,
	.final			= blowfishCfbFinal,
	.free			= blowfishCfbFree,
	.pad			= NULL,
	.unpad			= NULL,
	.supportsWrap	= 0
};

const t_cipher	g_blowfishCfb1Cipher = {
	.name			= "blowfish-cfb1",
	.mode			= CIPHER_MODE_CFB1,
	.oid			= OID_NONE,
	.oiwOid			= OID_NONE,
	.isEncoder		= 1,
	.blockSize		= BLOWFISH_BLOCK_SIZE,
	.keySize		= BLOWFISH_DEFAULT_KEY_SIZE,
	.ivSize			= BLOWFISH_IV_SIZE,
	.ctxSize		= sizeof(t_blowfishCfbCtx),
	.init			= blowfishCfb1Init,
	.update			= blowfishCfb1Update,
	.final			= blowfishCfb1Final,
	.free			= blowfishCfbFree,
	.pad			= NULL,
	.unpad			= NULL,
	.supportsWrap	= 0
};
