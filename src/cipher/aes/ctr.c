#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/utils/utils.h"
#include "../../../includes/cipher/cipher.h"
#include "../../../includes/cipher/modes.h"
#include "../../../includes/cipher/aes.h"

static void	aesProcessBlock(const uint8_t *in, uint8_t *out, const void *key)
{
	const t_aesCtrCtx	*ctx = key;

#if defined(AES_USE_NEON)
	aesProcessBlocksNeon(in, out, ctx->roundKeys, 1, ctx->nbRounds, 1);
#elif defined(AES_USE_AESNI)
	aesProcessBlocksX86(in, out, ctx->roundKeys, 1, ctx->nbRounds, 1);
#else
	aesEncryptBlock(in, out, ctx->roundKeys, ctx->nbRounds);
#endif
}

int	aesCtrInit(void				*vctx,
			   const uint8_t	*key,
			   size_t			keyLen,
			   const uint8_t	*iv,
			   t_cipherDirection dir)
{
	t_aesCtrCtx	*ctx = vctx;

	(void)dir; /* CTR encrypt == decrypt */
	ctx->nbRounds = aesExpandKey(key, keyLen, ctx->roundKeys);
	if (ctx->nbRounds == 0)
		return (-1);

	ft_memcpy(ctx->ctrCtx.iv,      iv ? iv : (uint8_t[AES_BLOCK_SIZE]){0}, AES_BLOCK_SIZE);
	ft_memcpy(ctx->ctrCtx.counter, ctx->ctrCtx.iv, AES_BLOCK_SIZE);
	ctx->ctrCtx.keystreamOff = AES_BLOCK_SIZE; /* force generation on first use */
	ctx->ctrCtx.blockSize    = AES_BLOCK_SIZE;
	ctx->ctrCtx.cipherCtx    = ctx;
	ctx->ctrCtx.processBlock = aesProcessBlock;

	return (0);
}

void	aesCtrFree(void *vctx)
{
	t_aesCtrCtx	*ctx = vctx;

	secureZeroMemory(ctx->roundKeys, sizeof(ctx->roundKeys));
	secureZeroMemory(ctx->ctrCtx.iv,       sizeof(ctx->ctrCtx.iv));
	secureZeroMemory(ctx->ctrCtx.counter,  sizeof(ctx->ctrCtx.counter));
	secureZeroMemory(ctx->ctrCtx.keystream, sizeof(ctx->ctrCtx.keystream));
}

void	aesCtrUpdate(void			*vctx,
					 const uint8_t	*in,
					 size_t			inLen,
					 uint8_t		*out,
					 size_t			*outLen)
{
	t_aesCtrCtx	*ctx = vctx;

	ctrGenUpdate(&ctx->ctrCtx, in, inLen, out, outLen);
}

void	aesCtrFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	t_aesCtrCtx	*ctx = vctx;

	(void)ctx;
	(void)out;
	/* CTR is a stream cipher — all data is processed in update, nothing to flush */
	*outLen = 0;
}

#define AES_CTR_CIPHER(nameStr, size) {		\
	.name			= nameStr,				\
	.mode			= CIPHER_MODE_CTR,		\
	.isEncoder		= 1,					\
	.blockSize		= AES_BLOCK_SIZE,		\
	.keySize		= size,					\
	.ivSize			= AES_BLOCK_SIZE,		\
	.ctxSize		= sizeof(t_aesCtrCtx),	\
	.init			= aesCtrInit,			\
	.update			= aesCtrUpdate,			\
	.final			= aesCtrFinal,			\
	.free			= aesCtrFree,			\
	.pad			= NULL,					\
	.unpad			= NULL,					\
	.supportsWrap	= 0						\
}

const t_cipher g_aes128CtrCipher	= AES_CTR_CIPHER("aes-128-ctr", AES_KEY_SIZE_128);
const t_cipher g_aes192CtrCipher	= AES_CTR_CIPHER("aes-192-ctr", AES_KEY_SIZE_192);
const t_cipher g_aes256CtrCipher	= AES_CTR_CIPHER("aes-256-ctr", AES_KEY_SIZE_256);
