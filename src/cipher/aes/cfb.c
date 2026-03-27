#include "../../../hajlib/include/hmemory.h"
#include "../../../includes/utils/utils.h"
#include "../../../includes/cipher/cipher.h"
#include "../../../includes/cipher/modes.h"
#include "../../../includes/cipher/aes.h"

static void aesProcessBlock(const uint8_t *in, uint8_t *out, const void *key)
{
	const t_aesCfbCtx *ctx = key;

#if defined(__aarch64__)
	aesProcessBlocksNeon(in, out, ctx->roundKeys, 1, ctx->nbRounds, 1);
#else
	aesEncryptBlock((uint8_t*)in, ctx->roundKeys, ctx->nbRounds);

	(void)out;
#endif
}

static int aesCfbGenInit(void *vctx, const uint8_t *key, size_t keyLen, const uint8_t *iv, t_cipherDirection dir, int unitSize)
{
	t_aesCfbCtx	*ctx = vctx;

	ctx->nbRounds = aesExpandKey(key, keyLen, ctx->roundKeys);
	if (ctx->nbRounds == 0)
		return -1;

	ft_memcpy(ctx->cfbCtx.iv, iv ? iv : (uint8_t[AES_BLOCK_SIZE]){0}, AES_BLOCK_SIZE);
	ft_memcpy(ctx->cfbCtx.shiftRegister, ctx->cfbCtx.iv, AES_BLOCK_SIZE);
	ctx->cfbCtx.inputBufLen = 0;
	ctx->cfbCtx.dir = dir;
	ctx->cfbCtx.blockSize = AES_BLOCK_SIZE;
	ctx->cfbCtx.unitSize = unitSize;
	ctx->cfbCtx.cipherCtx = ctx;
	ctx->cfbCtx.processBlock = aesProcessBlock;

	return (0);
}

int aesCfbInit(void *vctx, const uint8_t *key, size_t keyLen, const uint8_t *iv, t_cipherDirection dir)
{
	return aesCfbGenInit(vctx, key, keyLen, iv, dir, AES_BLOCK_SIZE);
}

int aesCfb8Init(void *vctx, const uint8_t *key, size_t keyLen, const uint8_t *iv, t_cipherDirection dir)
{
	return aesCfbGenInit(vctx, key, keyLen, iv, dir, 1); /* CFB8 processes 1 byte at a time */
}

int aesCfb1Init(void *vctx, const uint8_t *key, size_t keyLen, const uint8_t *iv, t_cipherDirection dir)
{
	return aesCfbGenInit(vctx, key, keyLen, iv, dir, 1);
}

void aesCfbFree(void *vctx)
{
	t_aesCfbCtx *ctx = vctx;
	secureZeroMemory(ctx->roundKeys, sizeof(ctx->roundKeys));
	secureZeroMemory(ctx->cfbCtx.iv, sizeof(ctx->cfbCtx.iv));
	secureZeroMemory(ctx->cfbCtx.shiftRegister, sizeof(ctx->cfbCtx.shiftRegister));
}

void aesCfbUpdate(void *vctx, const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen)
{
	t_aesCfbCtx *ctx = vctx;
	cfbGenUpdate(&ctx->cfbCtx, in, inLen, out, outLen);
}

void aesCfb1Update(void *vctx, const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen)
{
	t_aesCfbCtx *ctx = vctx;
	size_t outBits = 0;
	cfb1Update(&ctx->cfbCtx, in, inLen * 8, out, &outBits);
	*outLen = (outBits + 7) / 8;
}

void aesCfbFinal(void *vctx, uint8_t *out, size_t *outLen)
{
	t_aesCfbCtx *ctx = vctx;
	cfbGenFinal(&ctx->cfbCtx, out, outLen);
}

void aesCfb1Final(void *vctx, uint8_t *out, size_t *outBits)
{
	(void)vctx;
	(void)out;
	*outBits = 0;
	/* CFB1 doesn't require any special finalization since it processes bit by bit */
}

#define AES_CFB_CIPHER(nameStr, size) { \
	.name			= nameStr,			\
	.mode			= CIPHER_MODE_CFB,	\
	.isEncoder		= 1,				\
	.blockSize		= AES_BLOCK_SIZE,	\
	.keySize		= size,				\
	.ivSize			= AES_BLOCK_SIZE,	\
	.ctxSize		= sizeof(t_aesCfbCtx),\
	.init			= aesCfbInit,		\
	.update			= aesCfbUpdate,		\
	.final			= aesCfbFinal,		\
	.free			= aesCfbFree,		\
	.pad			= NULL,				\
	.unpad			= NULL,				\
	.supportsWrap	= 0					\
}

#define AES_CFB8_CIPHER(nameStr, size) { \
	.name			= nameStr,			\
	.mode			= CIPHER_MODE_CFB8,	\
	.isEncoder		= 1,				\
	.blockSize		= AES_BLOCK_SIZE,	\
	.keySize		= size,				\
	.ivSize			= AES_BLOCK_SIZE,	\
	.ctxSize		= sizeof(t_aesCfbCtx),\
	.init			= aesCfb8Init,		\
	.update			= aesCfbUpdate,		\
	.final			= aesCfbFinal,		\
	.free			= aesCfbFree,		\
	.pad			= NULL,				\
	.unpad			= NULL,				\
	.supportsWrap	= 0					\
}

#define AES_CFB1_CIPHER(nameStr, size) { \
	.name			= nameStr,			\
	.mode			= CIPHER_MODE_CFB1,	\
	.isEncoder		= 1,				\
	.blockSize		= AES_BLOCK_SIZE,	\
	.keySize		= size,				\
	.ivSize			= AES_BLOCK_SIZE,	\
	.ctxSize		= sizeof(t_aesCfbCtx),\
	.init			= aesCfb1Init,		\
	.update			= aesCfb1Update,	\
	.final			= aesCfb1Final,		\
	.free			= aesCfbFree,		\
	.pad			= NULL,				\
	.unpad			= NULL,				\
	.supportsWrap	= 0					\
}

const t_cipher g_aes128CfbCipher	= AES_CFB_CIPHER("aes-128-cfb", AES_KEY_SIZE_128);
const t_cipher g_aes192CfbCipher	= AES_CFB_CIPHER("aes-192-cfb", AES_KEY_SIZE_192);
const t_cipher g_aes256CfbCipher	= AES_CFB_CIPHER("aes-256-cfb", AES_KEY_SIZE_256);

const t_cipher g_aes128Cfb8Cipher	= AES_CFB8_CIPHER("aes-128-cfb8", AES_KEY_SIZE_128);
const t_cipher g_aes192Cfb8Cipher	= AES_CFB8_CIPHER("aes-192-cfb8", AES_KEY_SIZE_192);
const t_cipher g_aes256Cfb8Cipher	= AES_CFB8_CIPHER("aes-256-cfb8", AES_KEY_SIZE_256);

const t_cipher g_aes128Cfb1Cipher	= AES_CFB1_CIPHER("aes-128-cfb1", AES_KEY_SIZE_128);
const t_cipher g_aes192Cfb1Cipher	= AES_CFB1_CIPHER("aes-192-cfb1", AES_KEY_SIZE_192);
const t_cipher g_aes256Cfb1Cipher	= AES_CFB1_CIPHER("aes-256-cfb1", AES_KEY_SIZE_256);
