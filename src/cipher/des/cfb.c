#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/utils/utils.h"
#include "../../../includes/cipher/cipher.h"
#include "../../../includes/cipher/modes.h"
#include "../../../includes/cipher/des.h"

/* Process block for DES (always uses encryption in CFB mode) */
static void desProcessBlock(const uint8_t *in, uint8_t *out, const void *key)
{
	const t_desCfbCtx	*ctx = key;
	uint64_t			block = 0;

	for (int i = 0; i < 8; i++)
		block = (block << 8) | in[i];

	block = desEncryptBlock(block, (uint64_t*)ctx->subkeys);

	for (int i = 0; i < 8; i++)
		out[i] = (block >> (56 - i * 8)) & 0xFF;
}

/* Generic initialization for all CFB variants */
static int desCfbGenInit(void				*vctx,
						 const uint8_t		*key,
						 size_t				keyLen,
                         const uint8_t		*iv,
						 t_cipherDirection	dir,
						 int				unitSize)
{
	t_desCfbCtx	*ctx = vctx;
	uint64_t	k = 0;
	int			i;

	if (keyLen == 0)
		return -1;

	for (i = 0; i < 8 && i < (int)keyLen; i++)
		k = (k << 8) | key[i];

	desGenerateSubkeys(k, (uint64_t*)ctx->subkeys);

	ft_memcpy(ctx->cfbCtx.iv, iv ? iv : (uint8_t[8]){0}, 8);
	ft_memcpy(ctx->cfbCtx.shiftRegister, ctx->cfbCtx.iv, 8);
	ctx->cfbCtx.inputBufLen = 0;
	ctx->cfbCtx.dir = dir;
	ctx->cfbCtx.blockSize = 8;
	ctx->cfbCtx.unitSize = unitSize;
	ctx->cfbCtx.cipherCtx = ctx;
	ctx->cfbCtx.processBlock = desProcessBlock;

	return (0);
}

int desCfbInit(void *vctx, const uint8_t *key, size_t keyLen, const uint8_t *iv, t_cipherDirection dir)
{
	return desCfbGenInit(vctx, key, keyLen, iv, dir, 8);
}

int desCfb8Init(void *vctx, const uint8_t *key, size_t keyLen, const uint8_t *iv, t_cipherDirection dir)
{
	return desCfbGenInit(vctx, key, keyLen, iv, dir, 1);
}

int desCfb1Init(void *vctx, const uint8_t *key, size_t keyLen, const uint8_t *iv, t_cipherDirection dir)
{
	return desCfbGenInit(vctx, key, keyLen, iv, dir, 1);
}

void desCfbFree(void *vctx)
{
	t_desCfbCtx *ctx = vctx;
	secureZeroMemory(ctx->subkeys, sizeof(ctx->subkeys));
	secureZeroMemory(ctx->cfbCtx.iv, sizeof(ctx->cfbCtx.iv));
	secureZeroMemory(ctx->cfbCtx.shiftRegister, sizeof(ctx->cfbCtx.shiftRegister));
}

void desCfbUpdate(void *vctx, const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen)
{
	t_desCfbCtx *ctx = vctx;
	cfbGenUpdate(&ctx->cfbCtx, in, inLen, out, outLen);
}

void desCfb1Update(void *vctx, const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen)
{
    t_desCfbCtx *ctx = vctx;
    size_t outBits = 0;
    cfb1Update(&ctx->cfbCtx, in, inLen * 8, out, &outBits);
    *outLen = (outBits + 7) / 8;
}

void desCfbFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	t_desCfbCtx *ctx = vctx;
	cfbGenFinal(&ctx->cfbCtx, out, outLen);
}

void desCfb1Final(void *vctx, uint8_t *out, size_t *outBits)
{
	(void)vctx;
	(void)out;
	*outBits = 0;
	/* CFB1 doesn't need special finalization */
}

const t_cipher g_desCfbCipher = {
	.name		= "des-cfb",
	.mode		= CIPHER_MODE_CFB,
	.isEncoder	= 1,

	.blockSize	= 8,
	.keySize	= 8,
	.ivSize		= 8,
	.ctxSize	= sizeof(t_desCfbCtx),

	.init	= desCfbInit,
	.update	= desCfbUpdate,
	.final	= desCfbFinal,
	.free	= desCfbFree,

	.pad	= NULL,
	.unpad	= NULL,

	.supportsWrap	= 0
};

const t_cipher g_desCfb8Cipher = {
	.name		= "des-cfb8",
	.mode		= CIPHER_MODE_CFB8,
	.isEncoder	= 1,

	.blockSize	= 8,
	.keySize	= 8,
	.ivSize		= 8,
	.ctxSize	= sizeof(t_desCfbCtx),

	.init	= desCfb8Init,
	.update	= desCfbUpdate,
	.final	= desCfbFinal,
	.free	= desCfbFree,

	.pad	= NULL,
	.unpad	= NULL,

	.supportsWrap	= 0
};

const t_cipher g_desCfb1Cipher = {
	.name		= "des-cfb1",
	.mode		= CIPHER_MODE_CFB1,
	.isEncoder	= 1,

	.blockSize	= 8,
	.keySize	= 8,
	.ivSize		= 8,
	.ctxSize	= sizeof(t_desCfbCtx),

	.init	= desCfb1Init,
	.update	= desCfb1Update,
	.final	= desCfb1Final,
	.free	= desCfbFree,

	.pad	= NULL,
	.unpad	= NULL,

	.supportsWrap	= 0
};
