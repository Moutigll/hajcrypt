#include "../../../includes/cipher/des3.h"
#include "../../../includes/cipher/modes.h"
#include "../../../includes/utils/utils.h"
#include "../../../hajlib/include/hmemory.h"

static void des3CbcProcessBlock(const uint8_t	*in,
								uint8_t			*out,
								const void		*key,
								int				encrypt)
{
	const t_des3CbcCtx	*ctx = key;
	uint64_t			block = 0;

	for (int i = 0; i < 8; i++)
		block = (block << 8) | in[i];

	if (encrypt)
		block = des3EncryptBlock(block, ctx->subkeys1, ctx->subkeys2, ctx->subkeys3);
	else
		block = des3DecryptBlock(block, ctx->subkeys1, ctx->subkeys2, ctx->subkeys3);

	for (int i = 0; i < 8; i++)
		out[i] = (block >> (56 - i * 8)) & 0xFF;
}

int des3CbcInit(void				*vctx,
				const uint8_t		*key,
				size_t				keyLen,
				const uint8_t		*iv,
				t_cipherDirection	dir)
{
	t_des3CbcCtx	*ctx = vctx;

	if (keyLen != 24)
		return (-1);

	des3GenerateSubkeys(key, ctx->subkeys1, ctx->subkeys2, ctx->subkeys3);

	ft_memcpy(ctx->cbcCtx.iv, iv ? iv : (uint8_t[8]){0}, 8);
	ctx->cbcCtx.bufferLen = 0;
	ctx->cbcCtx.dir = dir;
	ctx->cbcCtx.blockSize = 8;
	ctx->cbcCtx.cipherCtx = ctx;
	ctx->cbcCtx.processBlock = des3CbcProcessBlock;

	return (0);
}

void des3CbcUpdate(void				*vctx,
				   const uint8_t	*in,
				   size_t			inLen,
				   uint8_t			*out,
				   size_t			*outLen)
{
	t_des3CbcCtx	*ctx = vctx;
	cbcGenUpdate(&ctx->cbcCtx, in, inLen, out, outLen);
}

void des3CbcFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	t_des3CbcCtx	*ctx = vctx;
	cbcGenFinal(&ctx->cbcCtx, out, outLen);
}

void des3CbcFree(void *vctx)
{
	t_des3CbcCtx	*ctx = vctx;
	secureZeroMemory(ctx->subkeys1, sizeof(ctx->subkeys1));
	secureZeroMemory(ctx->subkeys2, sizeof(ctx->subkeys2));
	secureZeroMemory(ctx->subkeys3, sizeof(ctx->subkeys3));
	secureZeroMemory(ctx->cbcCtx.iv, sizeof(ctx->cbcCtx.iv));
	secureZeroMemory(ctx->cbcCtx.buffer, sizeof(ctx->cbcCtx.buffer));
}

const t_cipher g_des3CbcCipher = {
	.name			= "des3-cbc",
	.deprecated		= 1,
	.mode			= CIPHER_MODE_CBC,
	.oid			= OID_DEF("DES3-CBC", DES_EDE3_CBC_NIST_OID),
	.oiwOid			= OIW_DEF("DES3-CBC", DES_EDE3_CBC_OIW_OID),
	.isEncoder		= 1,
	.blockSize		= 8,
	.keySize		= 24,
	.ivSize			= 8,
	.ctxSize		= sizeof(t_des3CbcCtx),
	.init			= des3CbcInit,
	.update			= des3CbcUpdate,
	.final			= des3CbcFinal,
	.free			= des3CbcFree,
	.pad			= pkcs7Pad,
	.unpad			= pkcs7Unpad,
	.supportsWrap	= 0
};

const t_cipher g_des3Cipher = {
	.name			= "des3",
	.deprecated		= 1,
	.mode			= CIPHER_MODE_CBC,
	.oid			= OID_DEF("DES3-CBC", DES_EDE3_CBC_NIST_OID),
	.oiwOid			= OIW_DEF("DES3-CBC", DES_EDE3_CBC_OIW_OID),
	.isEncoder		= 1,
	.blockSize		= 8,
	.keySize		= 24,
	.ivSize			= 8,
	.ctxSize		= sizeof(t_des3CbcCtx),
	.init			= des3CbcInit,
	.update			= des3CbcUpdate,
	.final			= des3CbcFinal,
	.free			= des3CbcFree,
	.pad			= pkcs7Pad,
	.unpad			= pkcs7Unpad,
	.supportsWrap	= 0
};
