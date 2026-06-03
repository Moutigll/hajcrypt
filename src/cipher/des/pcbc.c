#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/utils/utils.h"

#include "../../../includes/cipher/modes.h"

#include "../../../includes/cipher/des.h"

static void desProcessBlock(const uint8_t *in, uint8_t *out, const void *key, int encrypt)
{
	const uint64_t	*subkeys = key;
	uint64_t		block = 0;
	
	for (int i = 0; i < 8; i++)
		block = (block << 8) | in[i];
	
	if (encrypt)
		block = desEncryptBlock(block, (uint64_t*)subkeys);
	else
		block = desDecryptBlock(block, (uint64_t*)subkeys);
	
	for (int i = 0; i < 8; i++)
		out[i] = (block >> (56 - i * 8)) & 0xFF;
}

int desPcbcInit(void				*vctx,
				const uint8_t		*key,
				size_t				keyLen,
				const uint8_t		*iv,
				t_cipherDirection	dir)
{
	t_desPcbcCtx	*ctx = vctx;
	uint64_t		k = 0;
	int i;

	if (keyLen == 0 || keyLen > 8)
		return -1;

	/* Convert the key (max 8 bytes) */
	for (i = 0; i < 8 && i < (int)keyLen; i++)
		k = (k << 8) | key[i];

	desGenerateSubkeys(k, ctx->subkeys);

	/* Initialize IV: use provided IV or default to zeros */
	ft_memcpy(ctx->pcbcCtx.iv, iv ? iv : (uint8_t[8]){0}, 8);
	/* PCBC initial previous plaintext is the IV */
	ft_bzero(ctx->pcbcCtx.prevPlain, 8);

	ctx->pcbcCtx.bufferLen = 0;
	ctx->pcbcCtx.dir = dir;
	ctx->pcbcCtx.blockSize = 8;
	ctx->pcbcCtx.cipherCtx = ctx->subkeys;
	ctx->pcbcCtx.processBlock = desProcessBlock;

	return (0);
}

void desPcbcFree(void *vctx)
{
	t_desPcbcCtx *ctx = vctx;
	secureZeroMemory(ctx->subkeys, sizeof(ctx->subkeys));
	secureZeroMemory(ctx->pcbcCtx.iv, sizeof(ctx->pcbcCtx.iv));
	secureZeroMemory(ctx->pcbcCtx.prevPlain, sizeof(ctx->pcbcCtx.prevPlain));
	secureZeroMemory(ctx->pcbcCtx.buffer, sizeof(ctx->pcbcCtx.buffer));
}

void desPcbcUpdate(void *vctx, const uint8_t *in, size_t inLen,
				   uint8_t *out, size_t *outLen)
{
	t_desPcbcCtx *ctx = vctx;
	pcbcGenUpdate(&ctx->pcbcCtx, in, inLen, out, outLen);
}

void desPcbcFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	t_desPcbcCtx *ctx = vctx;
	pcbcGenFinal(&ctx->pcbcCtx, out, outLen);
}

/* ---------- Global cipher structures ---------- */

const t_cipher g_desPcbcCipher = {
	.name		= "des-pcbc",
	.deprecated	= 1,
	.mode		= CIPHER_MODE_PCBC,
	.oid		= OID_DEF("DES-PCBC", DES_PCBC_NIST_OID),
	.oiwOid		= OIW_DEF("DES-PCBC", DES_PCBC_OIW_OID),
	.isEncoder	= 1,
	.blockSize	= 8,
	.keySize	= 8,
	.ivSize		= 8,
	.ctxSize	= sizeof(t_desPcbcCtx),
	.init		= desPcbcInit,
	.update 	= desPcbcUpdate,
	.final  	= desPcbcFinal,
	.free   	= desPcbcFree,
	.pad		= pkcs7Pad,
	.unpad  	= pkcs7Unpad,
	.supportsWrap = 0
};
