#include "../../../includes/cipher/des3.h"
#include "../../../includes/cipher/modes.h"
#include "../../../includes/utils/utils.h"
#include "../../../hajlib/include/hmemory.h"

static void des3PcbcProcessBlock(const uint8_t	*in,
								 uint8_t		*out,
								 const void		*key,
								 int			encrypt)
{
	const t_des3PcbcCtx	*ctx = key;
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

int des3PcbcInit(void				*vctx,
				 const uint8_t		*key,
				 size_t				keyLen,
				 const uint8_t		*iv,
				 t_cipherDirection	dir)
{
	t_des3PcbcCtx	*ctx = vctx;

	if (keyLen != 24)
		return -1;

	des3GenerateSubkeys(key, ctx->subkeys1, ctx->subkeys2, ctx->subkeys3);

	ft_memcpy(ctx->pcbcCtx.iv, iv ? iv : (uint8_t[8]){0}, 8);
	ft_bzero(ctx->pcbcCtx.prevPlain, 8);
	ctx->pcbcCtx.bufferLen = 0;
	ctx->pcbcCtx.dir = dir;
	ctx->pcbcCtx.blockSize = 8;
	ctx->pcbcCtx.cipherCtx = ctx;
	ctx->pcbcCtx.processBlock = des3PcbcProcessBlock;

	return (0);
}

void des3PcbcUpdate(void			*vctx,
					const uint8_t	*in,
					size_t			inLen,
					uint8_t			*out,
					size_t			*outLen)
{
	t_des3PcbcCtx	*ctx = vctx;
	pcbcGenUpdate(&ctx->pcbcCtx, in, inLen, out, outLen);
}

void des3PcbcFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	t_des3PcbcCtx	*ctx = vctx;
	pcbcGenFinal(&ctx->pcbcCtx, out, outLen);
}

void des3PcbcFree(void *vctx)
{
	t_des3PcbcCtx	*ctx = vctx;
	secureZeroMemory(ctx->subkeys1, sizeof(ctx->subkeys1));
	secureZeroMemory(ctx->subkeys2, sizeof(ctx->subkeys2));
	secureZeroMemory(ctx->subkeys3, sizeof(ctx->subkeys3));
	secureZeroMemory(ctx->pcbcCtx.iv, sizeof(ctx->pcbcCtx.iv));
	secureZeroMemory(ctx->pcbcCtx.prevPlain, sizeof(ctx->pcbcCtx.prevPlain));
	secureZeroMemory(ctx->pcbcCtx.buffer, sizeof(ctx->pcbcCtx.buffer));
}

const t_cipher g_des3PcbcCipher = {
	.name			= "des3-pcbc",
	.deprecated		= 1,
	.mode			= CIPHER_MODE_PCBC,
	.oid			= OID_NONE,
	.oiwOid			= OID_NONE,
	.isEncoder		= 1,
	.blockSize		= 8,
	.keySize		= 24,
	.ivSize			= 8,
	.ctxSize		= sizeof(t_des3PcbcCtx),
	.init			= des3PcbcInit,
	.update			= des3PcbcUpdate,
	.final			= des3PcbcFinal,
	.free			= des3PcbcFree,
	.pad			= pkcs7Pad,
	.unpad			= pkcs7Unpad,
	.supportsWrap	= 0
};
