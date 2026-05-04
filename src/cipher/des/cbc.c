#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/utils/utils.h"

#include "../../../includes/cipher/modes.h"

#include "../../../includes/cipher/des.h"

static void desProcessBlock(const uint8_t *in, uint8_t *out, const void *key, int encrypt)
{
	const t_desCbcCtx	*ctx = key;
	uint64_t			block = 0;
	
	for (int i = 0; i < 8; i++)
		block = (block << 8) | in[i];
	
	if (encrypt)
		block = desEncryptBlock(block, (uint64_t*)ctx->subkeys);
	else
		block = desDecryptBlock(block, (uint64_t*)ctx->subkeys);
	
	for (int i = 0; i < 8; i++)
		out[i] = (block >> (56 - i * 8)) & 0xFF;
}

int desCbcInit(void					*vctx,
			   const uint8_t		*key,
			   size_t				keyLen,
			   const uint8_t		*iv,
			   t_cipherDirection	dir)
{
	t_desCbcCtx *ctx = vctx;
	uint64_t k = 0;
	int i;

	if (keyLen == 0 || keyLen > 8)
		return -1;

	/* Convert the key (max 8 bytes) */
	for (i = 0; i < 8 && i < (int)keyLen; i++)
		k = (k << 8) | key[i];

	desGenerateSubkeys(k, ctx->subkeys);

	/* Initialize IV: use provided IV or default to zeros */
	ft_memcpy(ctx->cbcCtx.iv, iv ? iv : (uint8_t[8]){0}, 8);

	ctx->cbcCtx.bufferLen = 0;
	ctx->cbcCtx.dir = dir;
	ctx->cbcCtx.blockSize = 8;
	ctx->cbcCtx.cipherCtx = ctx;
	ctx->cbcCtx.processBlock = desProcessBlock;

	return 0;
}


void desCbcFree(void *vctx)
{
	t_desCbcCtx *ctx = vctx;
	secureZeroMemory(ctx->subkeys, sizeof(ctx->subkeys));
	secureZeroMemory(ctx->cbcCtx.iv, sizeof(ctx->cbcCtx.iv));
	secureZeroMemory(ctx->cbcCtx.buffer, sizeof(ctx->cbcCtx.buffer));
}

void desCbcUpdate(void *vctx, const uint8_t *in, size_t inLen,
				  uint8_t *out, size_t *outLen)
{
	t_desCbcCtx *ctx = vctx;
	cbcGenUpdate(&ctx->cbcCtx, in, inLen, out, outLen);
}

void desCbcFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	t_desCbcCtx *ctx = vctx;
	cbcGenFinal(&ctx->cbcCtx, out, outLen);
}

/* ---------- Global cipher structures ---------- */

const t_cipher g_desCbcCipher = {
	.name		= "des-cbc",
	.mode		= CIPHER_MODE_CBC,
	.oid		= OID_DEF("DES-CBC", DES_CBC_NIST_OID),
	.oiwOid		= OIW_DEF("DES-CBC", DES_CBC_OIW_OID),
	.isEncoder	= 1,

	.blockSize	= 8,
	.keySize	= 8,
	.ivSize		= 8,
	.ctxSize	= sizeof(t_desCbcCtx),

	.init	= desCbcInit,
	.update	= desCbcUpdate,
	.final	= desCbcFinal,
	.free	= desCbcFree,

	.pad	= pkcs7Pad,
	.unpad	= pkcs7Unpad,

	.supportsWrap	= 0
};

const t_cipher g_desCipher = {
	.name			= "des",
	.mode			= CIPHER_MODE_CBC,
	.isEncoder		= 1,
	.oid			= OID_DEF("DES-CBC", DES_CBC_NIST_OID),
	.oiwOid			= OIW_DEF("DES-CBC", DES_CBC_OIW_OID),
	.blockSize		= 8,
	.keySize		= 8,
	.ivSize			= 8,
	.ctxSize		= sizeof(t_desCbcCtx),
	.init			= desCbcInit,
	.update			= desCbcUpdate,
	.final			= desCbcFinal,
	.free			= desCbcFree,
	.pad			= pkcs7Pad,
	.unpad			= pkcs7Unpad,
	.supportsWrap	= 0
};
