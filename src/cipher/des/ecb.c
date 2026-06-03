#include "../../../includes/utils/utils.h"

#include "../../../includes/cipher/des.h"

int desEcbInit(void					*vctx,
				const uint8_t		*key,
				size_t				keyLen,
				const uint8_t		*iv,
				t_cipherDirection	dir)
{
	t_desEcbCtx	*ctx = vctx;
	uint64_t	k = 0;
	int			i;

	if (!key || keyLen != 8)
		return (-1);

	(void)iv;	/* ECB does not use an IV */

	/* Convert the key (max 8 bytes) */
	for (i = 0; i < 8 && i < (int)keyLen; i++)
		k = (k << 8) | key[i];

	desGenerateSubkeys(k, ctx->subkeys);
	ctx->bufferLen = 0;
	ctx->dir = dir;
	return (0);
}

void desEcbUpdate(void			*vctx,
				  const uint8_t	*in,
				  size_t		inLen,
				  uint8_t		*out,
				  size_t		*outLen)
{
	t_desEcbCtx	*ctx = vctx;
	*outLen = 0;

	for (size_t i = 0; i < inLen; i += 8) {
		uint64_t block = 0;
		for (int j = 0; j < 8; j++)
			block = (block << 8) | in[i + j];
		
		if (ctx->dir == CIPHER_ENCRYPT)
			block = desEncryptBlock(block, ctx->subkeys);
		else
			block = desDecryptBlock(block, ctx->subkeys);
		
		for (int j = 0; j < 8; j++)
			out[(*outLen)++] = (block >> (56 - j * 8)) & 0xFF;
	}
}

void desEcbFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	(void)vctx;
	(void)out;
	*outLen = 0;
}

void desEcbFree(void *vctx)
{
	t_desEcbCtx *ctx = vctx;
	secureZeroMemory(ctx->subkeys, sizeof(ctx->subkeys));
	secureZeroMemory(ctx->buffer, sizeof(ctx->buffer));
}

const t_cipher g_desEcbCipher = {
	.name			= "des-ecb",
	.deprecated		= 1,
	.mode			= CIPHER_MODE_ECB,
	.oid			= OID_DEF("DES-ECB", DES_ECB_NIST_OID),
	.oiwOid			= OIW_DEF("DES-ECB", DES_ECB_OIW_OID),
	.isEncoder		= 1,
	.blockSize		= 8,
	.keySize		= 8,
	.ivSize			= 0,
	.ctxSize		= sizeof(t_desEcbCtx),
	.init			= desEcbInit,
	.update			= desEcbUpdate,
	.final			= desEcbFinal,
	.free			= desEcbFree,
	.pad			= pkcs7Pad,
	.unpad  		= pkcs7Unpad,
	.supportsWrap	= 0
};
