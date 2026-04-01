#include "../../../includes/cipher/des3.h"
#include "../../../includes/cipher/modes.h"
#include "../../../includes/utils/utils.h"
#include "../../../hajlib/include/hmemory.h"

static void des3CfbProcessBlock(const uint8_t *in, uint8_t *out, const void *key)
{
	const t_des3CfbCtx	*ctx = key;
	uint64_t			block = 0;

	for (int i = 0; i < 8; i++)
		block = (block << 8) | in[i];

	block = des3EncryptBlock(block, ctx->subkeys1, ctx->subkeys2, ctx->subkeys3);

	for (int i = 0; i < 8; i++)
		out[i] = (block >> (56 - i * 8)) & 0xFF;
}

static int des3CfbGenInit(void				*vctx,
						  const uint8_t		*key,
						  size_t			keyLen,
						  const uint8_t		*iv,
						  t_cipherDirection	dir,
						  int				unitSize)
{
	t_des3CfbCtx	*ctx = vctx;

	if (keyLen != 24)
		return (-1);

	des3GenerateSubkeys(key, ctx->subkeys1, ctx->subkeys2, ctx->subkeys3);

	ft_memcpy(ctx->cfbCtx.iv, iv ? iv : (uint8_t[8]){0}, 8);
	ft_memcpy(ctx->cfbCtx.shiftRegister, ctx->cfbCtx.iv, 8);
	ctx->cfbCtx.inputBufLen = 0;
	ctx->cfbCtx.dir = dir;
	ctx->cfbCtx.blockSize = 8;
	ctx->cfbCtx.unitSize = unitSize;
	ctx->cfbCtx.cipherCtx = ctx;
	ctx->cfbCtx.processBlock = des3CfbProcessBlock;

	return (0);
}

int des3CfbInit(void				*vctx,
				const uint8_t		*key,
				size_t				keyLen,
				const uint8_t		*iv,
				t_cipherDirection	dir)
{
	return (des3CfbGenInit(vctx, key, keyLen, iv, dir, 8));
}

int des3Cfb8Init(void				*vctx,
				  const uint8_t		*key,
				  size_t			keyLen,
				  const uint8_t		*iv,
				  t_cipherDirection	dir)
{
	return (des3CfbGenInit(vctx, key, keyLen, iv, dir, 1));
}

int des3Cfb1Init(void				*vctx,
				  const uint8_t		*key,
				  size_t			keyLen,
				  const uint8_t		*iv,
				  t_cipherDirection	dir)
{
	return (des3CfbGenInit(vctx, key, keyLen, iv, dir, 1));
}

void des3CfbFree(void *vctx)
{
	t_des3CfbCtx	*ctx = vctx;
	secureZeroMemory(ctx->subkeys1, sizeof(ctx->subkeys1));
	secureZeroMemory(ctx->subkeys2, sizeof(ctx->subkeys2));
	secureZeroMemory(ctx->subkeys3, sizeof(ctx->subkeys3));
	secureZeroMemory(ctx->cfbCtx.iv, sizeof(ctx->cfbCtx.iv));
	secureZeroMemory(ctx->cfbCtx.shiftRegister, sizeof(ctx->cfbCtx.shiftRegister));
}

void des3CfbUpdate(void				*vctx,
				   const uint8_t	*in,
				   size_t			inLen,
				   uint8_t			*out,
				   size_t			*outLen)
{
	t_des3CfbCtx	*ctx = vctx;
	cfbGenUpdate(&ctx->cfbCtx, in, inLen, out, outLen);
}

void des3Cfb1Update(void			*vctx,
					const uint8_t	*in,
					size_t			inLen,
					uint8_t			*out,
					size_t			*outLen)
{
	t_des3CfbCtx	*ctx = vctx;
	size_t outBits = 0;
	cfb1Update(&ctx->cfbCtx, in, inLen * 8, out, &outBits);
	*outLen = (outBits + 7) / 8;
}

void des3CfbFinal(void				*vctx,
				   uint8_t			*out,
				   size_t			*outLen)
{
	t_des3CfbCtx	*ctx = vctx;
	cfbGenFinal(&ctx->cfbCtx, out, outLen);
}

void des3Cfb1Final(void *vctx, uint8_t *out, size_t *outBits)
{
	(void)vctx;
	(void)out;
	*outBits = 0;
}

/* ---------- Global cipher structures ---------- */

const t_cipher g_des3CfbCipher = {
	.name			= "des3-cfb",
	.mode			= CIPHER_MODE_CFB,
	.isEncoder		= 1,
	.blockSize		= 8,
	.keySize		= 24,
	.ivSize			= 8,
	.ctxSize		= sizeof(t_des3CfbCtx),
	.init			= des3CfbInit,
	.update			= des3CfbUpdate,
	.final			= des3CfbFinal,
	.free			= des3CfbFree,
	.pad			= NULL,
	.unpad			= NULL,
	.supportsWrap	= 0
};

const t_cipher g_des3Cfb8Cipher = {
	.name			= "des3-cfb8",
	.mode			= CIPHER_MODE_CFB8,
	.isEncoder		= 1,
	.blockSize		= 8,
	.keySize		= 24,
	.ivSize			= 8,
	.ctxSize		= sizeof(t_des3CfbCtx),
	.init			= des3Cfb8Init,
	.update			= des3CfbUpdate,
	.final			= des3CfbFinal,
	.free		   	= des3CfbFree,
	.pad			= NULL,
	.unpad			= NULL,
	.supportsWrap	= 0
};

const t_cipher g_des3Cfb1Cipher = {
	.name			= "des3-cfb1",
	.mode			= CIPHER_MODE_CFB1,
	.isEncoder		= 1,
	.blockSize		= 8,
	.keySize		= 24,
	.ivSize			= 8,
	.ctxSize		= sizeof(t_des3CfbCtx),
	.init			= des3Cfb1Init,
	.update			= des3Cfb1Update,
	.final			= des3Cfb1Final,
	.free			= des3CfbFree,
	.pad			= NULL,
	.unpad			= NULL,
	.supportsWrap	= 0
};
