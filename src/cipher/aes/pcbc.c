#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/cipher/modes.h"
#include "../../../includes/utils/utils.h"

#include "../../../includes/cipher/aes.h"

static void aesProcessBlock(const uint8_t *in, uint8_t *out, const void *key, int encrypt)
{
	const t_aesPcbcCtx	*ctx = key;

#if defined(AES_USE_NEON)
	if (encrypt)
		aesProcessBlocksNeon(in, out, ctx->roundKeys, 1, ctx->nbRounds, 1);
	else
		aesProcessBlocksNeon(in, out, ctx->roundKeys, 1, ctx->nbRounds, 0);
#elif defined(AES_USE_AESNI)
	if (encrypt)
		aesProcessBlocksX86(in, out, ctx->roundKeys, 1, ctx->nbRounds, 1);
	else
		aesProcessBlocksX86(in, out, ctx->roundKeys, 1, ctx->nbRounds, 0);
#else
	if (encrypt)
		aesEncryptBlock(in, out, ctx->roundKeys, ctx->nbRounds);
	else
		aesDecryptBlock(in, out, ctx->roundKeys, ctx->nbRounds);
#endif
}


int aesPcbcInit(void *vctx, const uint8_t *key, size_t keyLen, const uint8_t *iv, t_cipherDirection dir)
{
	t_aesPcbcCtx *ctx = vctx;

	ctx->nbRounds = aesExpandKey(key, keyLen, ctx->roundKeys);
	if (ctx->nbRounds == 0)
		return -1;

	ft_memcpy(ctx->pcbcCtx.iv, iv ? iv : (uint8_t[AES_BLOCK_SIZE]){0}, AES_BLOCK_SIZE);
	ft_bzero(ctx->pcbcCtx.prevPlain, AES_BLOCK_SIZE);
	ctx->pcbcCtx.bufferLen = 0;
	ctx->pcbcCtx.dir = dir;
	ctx->pcbcCtx.blockSize = AES_BLOCK_SIZE;
	ctx->pcbcCtx.cipherCtx = ctx;
	ctx->pcbcCtx.processBlock = aesProcessBlock;

#if !defined(AES_USE_NEON) && !defined(AES_USE_AESNI) && !defined(AES_USE_REFERENCE)
	if (dir == CIPHER_DECRYPT)
		aesExpandDecryptKeys(ctx->roundKeys, ctx->nbRounds, ctx->roundKeys);
#endif

	return 0;
}

void aesPcbcUpdate(void *vctx, const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen)
{
	t_aesPcbcCtx *ctx = vctx;
	pcbcGenUpdate(&ctx->pcbcCtx, in, inLen, out, outLen);
}

void aesPcbcFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	t_aesPcbcCtx *ctx = vctx;
	pcbcGenFinal(&ctx->pcbcCtx, out, outLen);
}

void aesPcbcFree(void *vctx)
{
	t_aesPcbcCtx *ctx = vctx;
	secureZeroMemory(ctx->roundKeys, sizeof(ctx->roundKeys));
	secureZeroMemory(ctx->pcbcCtx.iv, sizeof(ctx->pcbcCtx.iv));
	secureZeroMemory(ctx->pcbcCtx.prevPlain, sizeof(ctx->pcbcCtx.prevPlain));
	secureZeroMemory(ctx->pcbcCtx.buffer, sizeof(ctx->pcbcCtx.buffer));
}

#define AES_PCBC_CIPHER(nameStr, size) {	\
	.name			= nameStr,				\
	.mode			= CIPHER_MODE_PCBC,		\
	.isEncoder		= 1,					\
	.blockSize		= AES_BLOCK_SIZE,		\
	.keySize		= size,					\
	.ivSize			= AES_BLOCK_SIZE,		\
	.ctxSize		= sizeof(t_aesPcbcCtx),	\
	.init			= aesPcbcInit,			\
	.update			= aesPcbcUpdate,			\
	.final			= aesPcbcFinal,			\
	.free			= aesPcbcFree,			\
	.pad			= pkcs7Pad,				\
	.unpad			= pkcs7Unpad,			\
	.supportsWrap	= 0						\
}

const t_cipher g_aes128PcbcCipher = AES_PCBC_CIPHER("aes-128-pcbc", AES_KEY_SIZE_128);
const t_cipher g_aes192PcbcCipher = AES_PCBC_CIPHER("aes-192-pcbc", AES_KEY_SIZE_192);
const t_cipher g_aes256PcbcCipher = AES_PCBC_CIPHER("aes-256-pcbc", AES_KEY_SIZE_256);
