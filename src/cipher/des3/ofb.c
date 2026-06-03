#include "../../../includes/cipher/des3.h"
#include "../../../includes/cipher/modes.h"
#include "../../../includes/utils/utils.h"
#include "../../../hajlib/include/hmemory.h"

static void des3OfbProcessBlock(const uint8_t *in, uint8_t *out, const void *key)
{
	const t_des3OfbCtx	*ctx = key;
	uint64_t			block = 0;

	for (int i = 0; i < 8; i++)
		block = (block << 8) | in[i];

	block = des3EncryptBlock(block, ctx->subkeys1, ctx->subkeys2, ctx->subkeys3);

	for (int i = 0; i < 8; i++)
		out[i] = (block >> (56 - i * 8)) & 0xFF;
}

int des3OfbInit(void				*vctx,
				const uint8_t		*key,
				size_t				keyLen,
				const uint8_t		*iv,
				t_cipherDirection	dir)
{
	t_des3OfbCtx *ctx = vctx;

	if (keyLen != 24)
		return (-1);

	des3GenerateSubkeys(key, ctx->subkeys1, ctx->subkeys2, ctx->subkeys3);

	ft_memcpy(ctx->ofbCtx.iv, iv ? iv : (uint8_t[8]){0}, 8);
	ft_memcpy(ctx->ofbCtx.keystream, ctx->ofbCtx.iv, 8);
	ctx->ofbCtx.keystreamOff = 8;   /* force first generation */
	ctx->ofbCtx.inputBufLen = 0;
	ctx->ofbCtx.blockSize = 8;
	ctx->ofbCtx.cipherCtx = ctx;
	ctx->ofbCtx.processBlock = des3OfbProcessBlock;

	(void)dir;   /* OFB uses same process for encrypt/decrypt */
	return (0);
}

void des3OfbUpdate(void				*vctx,
				   const uint8_t	*in,
				   size_t			inLen,
				   uint8_t			*out,
				   size_t			*outLen)
{
	t_des3OfbCtx	*ctx = vctx;
	ofbGenUpdate(&ctx->ofbCtx, in, inLen, out, outLen);
}

void des3OfbFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	t_des3OfbCtx	*ctx = vctx;
	ofbGenFinal(&ctx->ofbCtx, out, outLen);
}

void des3OfbFree(void *vctx)
{
	t_des3OfbCtx	*ctx = vctx;
	secureZeroMemory(ctx->subkeys1, sizeof(ctx->subkeys1));
	secureZeroMemory(ctx->subkeys2, sizeof(ctx->subkeys2));
	secureZeroMemory(ctx->subkeys3, sizeof(ctx->subkeys3));
	secureZeroMemory(ctx->ofbCtx.iv, sizeof(ctx->ofbCtx.iv));
	secureZeroMemory(ctx->ofbCtx.keystream, sizeof(ctx->ofbCtx.keystream));
}

const t_cipher g_des3OfbCipher = {
	.name			= "des3-ofb",
	.deprecated		= 1,
	.mode			= CIPHER_MODE_OFB,
	.oid			= OID_DEF("DES3-OFB", DES_EDE3_OFB_NIST_OID),
	.oiwOid			= OIW_DEF("DES3-OFB", DES_EDE3_OFB_OIW_OID),
	.isEncoder		= 1,
	.blockSize		= 8,
	.keySize		= 24,
	.ivSize			= 8,
	.ctxSize		= sizeof(t_des3OfbCtx),
	.init			= des3OfbInit,
	.update			= des3OfbUpdate,
	.final			= des3OfbFinal,
	.free			= des3OfbFree,
	.pad			= NULL,
	.unpad			= NULL,
	.supportsWrap	= 0
};
