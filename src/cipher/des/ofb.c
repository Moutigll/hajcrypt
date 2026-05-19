#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/utils/utils.h"
#include "../../../includes/cipher/cipher.h"
#include "../../../includes/cipher/modes.h"
#include "../../../includes/cipher/des.h"

static void	desProcessBlock(const uint8_t *in, uint8_t *out, const void *key)
{
	const t_desOfbCtx	*ctx = key;
	uint64_t			block = 0;

	for (int i = 0; i < 8; i++)
		block = (block << 8) | in[i];
	block = desEncryptBlock(block, (uint64_t *)ctx->subkeys);
	for (int i = 0; i < 8; i++)
		out[i] = (block >> (56 - i * 8)) & 0xFF;
}

int	desOfbInit(void					*vctx,
			   const uint8_t		*key,
			   size_t				keyLen,
			   const uint8_t		*iv,
			   t_cipherDirection	dir)
{
	t_desOfbCtx	*ctx = vctx;
	uint64_t	k = 0;

	(void)dir; /* OFB encrypt == decrypt */
	if (keyLen == 0)
		return (-1);
	for (int i = 0; i < 8 && i < (int)keyLen; i++)
		k = (k << 8) | key[i];
	desGenerateSubkeys(k, (uint64_t *)ctx->subkeys);

	ft_memcpy(ctx->ofbCtx.iv, iv ? iv : (uint8_t[8]){0}, 8);
	ft_memcpy(ctx->ofbCtx.keystream, ctx->ofbCtx.iv, 8);
	ctx->ofbCtx.keystreamOff = 8; /* force generation on first use */
	ctx->ofbCtx.inputBufLen  = 0;
	ctx->ofbCtx.blockSize    = 8;
	ctx->ofbCtx.cipherCtx    = ctx;
	ctx->ofbCtx.processBlock = desProcessBlock;
	return (0);
}

void	desOfbFree(void *vctx)
{
	t_desOfbCtx	*ctx = vctx;

	secureZeroMemory(ctx->subkeys, sizeof(ctx->subkeys));
	secureZeroMemory(ctx->ofbCtx.iv, sizeof(ctx->ofbCtx.iv));
	secureZeroMemory(ctx->ofbCtx.keystream, sizeof(ctx->ofbCtx.keystream));
}

void	desOfbUpdate(void *vctx, const uint8_t *in, size_t inLen,
					 uint8_t *out, size_t *outLen)
{
	t_desOfbCtx	*ctx = vctx;

	ofbGenUpdate(&ctx->ofbCtx, in, inLen, out, outLen);
}

void	desOfbFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	t_desOfbCtx	*ctx = vctx;

	ofbGenFinal(&ctx->ofbCtx, out, outLen);
}

const t_cipher g_desOfbCipher = {
	.name			= "des-ofb",
	.mode			= CIPHER_MODE_OFB,
	.oid			= OID_DEF("DES-OFB", DES_OFB_NIST_OID),
	.oiwOid			= OIW_DEF("DES-OFB", DES_OFB_OIW_OID),
	.isEncoder		= 1,
	.blockSize		= 8,
	.keySize		= 8,
	.ivSize			= 8,
	.ctxSize		= sizeof(t_desOfbCtx),
	.init			= desOfbInit,
	.update			= desOfbUpdate,
	.final			= desOfbFinal,
	.free			= desOfbFree,
	.pad			= NULL,
	.unpad			= NULL,
	.supportsWrap	= 0
};
