#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/utils/utils.h"
#include "../../../includes/cipher/cipher.h"
#include "../../../includes/cipher/modes.h"
#include "../../../includes/cipher/aes.h"

static void	aesProcessBlock(const uint8_t *in, uint8_t *out, const void *key)
{
	const t_aesOfbCtx	*ctx = key;

#if defined(AES_USE_NEON)
	aesProcessBlocksNeon(in, out, ctx->roundKeys, 1, ctx->nbRounds, 1);
#elif defined(AES_USE_AESNI)
	aesProcessBlocksX86(in, out, ctx->roundKeys, 1, ctx->nbRounds, 1);
#else
	aesEncryptBlock(in, out, ctx->roundKeys, ctx->nbRounds);
#endif
}

int	aesOfbInit(void					*vctx,
			   const uint8_t		*key,
			   size_t				keyLen,
			   const uint8_t		*iv,
			   t_cipherDirection	dir)
{
	t_aesOfbCtx	*ctx = vctx;

	(void)dir; /* OFB encrypt == decrypt */
	ctx->nbRounds = aesExpandKey(key, keyLen, ctx->roundKeys);
	if (ctx->nbRounds == 0)
		return (-1);

	ft_memcpy(ctx->ofbCtx.iv, iv ? iv : (uint8_t[AES_BLOCK_SIZE]){0}, AES_BLOCK_SIZE);
	ft_memcpy(ctx->ofbCtx.keystream, ctx->ofbCtx.iv, AES_BLOCK_SIZE);
	ctx->ofbCtx.keystreamOff = AES_BLOCK_SIZE; /* force generation on first use */
	ctx->ofbCtx.inputBufLen  = 0;
	ctx->ofbCtx.blockSize    = AES_BLOCK_SIZE;
	ctx->ofbCtx.cipherCtx    = ctx;
	ctx->ofbCtx.processBlock = aesProcessBlock;

	return (0);
}

void	aesOfbFree(void *vctx)
{
	t_aesOfbCtx	*ctx = vctx;

	secureZeroMemory(ctx->roundKeys, sizeof(ctx->roundKeys));
	secureZeroMemory(ctx->ofbCtx.iv, sizeof(ctx->ofbCtx.iv));
	secureZeroMemory(ctx->ofbCtx.keystream, sizeof(ctx->ofbCtx.keystream));
}

void	aesOfbUpdate(void			*vctx,
					 const uint8_t	*in,
					 size_t			inLen,
					 uint8_t		*out,
					 size_t			*outLen)
{
	t_aesOfbCtx	*ctx = vctx;

	ofbGenUpdate(&ctx->ofbCtx, in, inLen, out, outLen);
}

void	aesOfbFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	t_aesOfbCtx	*ctx = vctx;

	ofbGenFinal(&ctx->ofbCtx, out, outLen);
}

#define AES_OFB_CIPHER(nameStr, size) {		\
	.name			= nameStr,				\
	.mode			= CIPHER_MODE_OFB,		\
	.isEncoder		= 1,					\
	.blockSize		= AES_BLOCK_SIZE,		\
	.keySize		= size,					\
	.ivSize			= AES_BLOCK_SIZE,		\
	.ctxSize		= sizeof(t_aesOfbCtx),	\
	.init			= aesOfbInit,			\
	.update			= aesOfbUpdate,			\
	.final			= aesOfbFinal,			\
	.free			= aesOfbFree,			\
	.pad			= NULL,					\
	.unpad			= NULL,					\
	.supportsWrap	= 0						\
}

const t_cipher g_aes128OfbCipher	= AES_OFB_CIPHER("aes-128-ofb", AES_KEY_SIZE_128);
const t_cipher g_aes192OfbCipher	= AES_OFB_CIPHER("aes-192-ofb", AES_KEY_SIZE_192);
const t_cipher g_aes256OfbCipher	= AES_OFB_CIPHER("aes-256-ofb", AES_KEY_SIZE_256);
